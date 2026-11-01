/*
 * tls_load_open.c - OPEN-loop TLS 1.3 load generator (Poisson arrivals), paper 2, WP6 (latency under load).
 *
 * tls_load.c is closed-loop: it measures capacity but its latency is the latency of a saturated server. A bank sizes for a budget at a
 * fraction of capacity, so this program starts connections at a fixed mean rate (exponential gaps), whatever the server does, and reports the
 * latency distribution of the transactions (connect() start -> last response byte, as in tls_load) in ONE CSV line:
 *   rate_target,time_s,started,ok,err,dropped,rate_ok,p50_ms,p90_ms,p99_ms,p999_ms,max_ms,first_error
 * `dropped` counts arrivals not started because --max-conc connections were already open (a sign of overload, reported separately).
 *
 *   tls_load_open --addr A --port P --ca root.pem --groups G [--cert full_chain.pem --key k.pem] [--resume [--pool]]
 *   (--pool: a stock of single-use tickets, one per resumed connection; the default shares ONE ticket between all connections, which fails in 4-14 % of them)
 *                 --req Q --resp R --rate X --time S [--warmup W] [--max-conc N] [--seed Z]
 * Build: gcc -O2 -Wall -pthread -o tls_load_open tls_load_open.c -I$P/include -L$P/lib -lssl -lcrypto -lm -Wl,-rpath,$P/lib
 */
#define _GNU_SOURCE
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <getopt.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NBIN 100000          /* 10-us bins up to 1 s; the last bin is the overflow */
#define BIN_US 10.0

typedef struct {
    const char *addr, *port, *cert, *key, *ca, *groups;
    int req, resp, resume, max_conc, pool;
    double rate, time_s, warmup_s;
    unsigned seed;
} Opt;

static Opt O;
static SSL_CTX *CTX;
static struct addrinfo *AI;
static SSL_SESSION *SESS;                       /* one ticket, shared by all resumed connections (default) */
#define POOLMAX 4096
static SSL_SESSION *POOL[POOLMAX];              /* --pool: single-use tickets, one per resumed connection (a client of its own each) */
static int NPOOL;
static pthread_mutex_t SESS_MU = PTHREAD_MUTEX_INITIALIZER;
static double T_MEASURE, T_END;
static unsigned long HIST[NBIN], STARTED, OK, ERR, DROPPED, ACTIVE;
static double MAXMS;
static char FIRST_ERR[48];

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static int new_session_cb(SSL *ssl, SSL_SESSION *sess) {
    (void)ssl;
    pthread_mutex_lock(&SESS_MU);
    if (O.pool) {
        if (NPOOL < POOLMAX) POOL[NPOOL++] = sess; else SSL_SESSION_free(sess);
    } else {
        if (SESS) SSL_SESSION_free(SESS);
        SESS = sess;
    }
    pthread_mutex_unlock(&SESS_MU);
    return 1;
}

static int read_exact(SSL *ssl, unsigned char *buf, int n) {
    int got = 0;
    while (got < n) {
        int r = SSL_read(ssl, buf + got, n - got);
        if (r <= 0) return -1;
        got += r;
    }
    return got;
}

static const char *transact(unsigned char *req, unsigned char *resp, SSL_SESSION *sess, int *reused) {
    const char *err = NULL;
    int one = 1;
    int fd = socket(AI->ai_family, AI->ai_socktype, AI->ai_protocol);
    if (fd < 0) return "socket";
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    struct timeval tv = {30, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, AI->ai_addr, AI->ai_addrlen) != 0) { close(fd); return "connect"; }
    SSL *ssl = SSL_new(CTX);
    SSL_set_fd(ssl, fd);
    if (sess) SSL_set_session(ssl, sess);
    if (SSL_connect(ssl) != 1) err = "handshake";
    else {
        *reused = SSL_session_reused(ssl) ? 1 : 0;
        int w = 0;
        while (w < O.req) { int r = SSL_write(ssl, req + w, O.req - w); if (r <= 0) { err = "write"; break; } w += r; }
        if (!err && read_exact(ssl, resp, O.resp) < 0) err = "read";
        if (!err) SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    close(fd);
    ERR_clear_error();
    return err;
}

static void *one_connection(void *arg) {
    (void)arg;
    unsigned char *req = calloc(O.req, 1), *resp = malloc(O.resp);
    int reused = 0;
    SSL_SESSION *use = NULL;
    if (O.resume) {
        pthread_mutex_lock(&SESS_MU);
        if (O.pool) { if (NPOOL > 0) use = POOL[--NPOOL]; }     /* ownership passes to this connection */
        else if (SESS) { use = SESS; SSL_SESSION_up_ref(use); }
        pthread_mutex_unlock(&SESS_MU);
    }
    double t0 = now_ms();
    const char *e = transact(req, resp, use, &reused);
    double t1 = now_ms();
    if (use) SSL_SESSION_free(use);
    if (t0 >= T_MEASURE) {
        if (!e && O.resume && !reused) e = "not_resumed";
        __atomic_fetch_add(&STARTED, 1, __ATOMIC_RELAXED);
        if (e) {
            __atomic_fetch_add(&ERR, 1, __ATOMIC_RELAXED);
            if (!FIRST_ERR[0]) snprintf(FIRST_ERR, sizeof FIRST_ERR, "%s", e);
        } else {
            double ms = t1 - t0;
            long b = (long)(ms * 1000.0 / BIN_US);
            __atomic_fetch_add(&HIST[b >= NBIN ? NBIN - 1 : b], 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&OK, 1, __ATOMIC_RELAXED);
            if (ms > MAXMS) MAXMS = ms;     /* benign race: only an upper bound is reported */
        }
    }
    free(req);
    free(resp);
    __atomic_fetch_sub(&ACTIVE, 1, __ATOMIC_RELAXED);
    return NULL;
}

static double pct(double p) {
    unsigned long acc = 0;
    for (int b = 0; b < NBIN && OK; b++) {
        acc += HIST[b];
        if (acc >= p * OK) return (b + 0.5) * BIN_US / 1000.0;
    }
    return -1;
}

int main(int argc, char **argv) {
    O.addr = "127.0.0.1"; O.port = "4433"; O.req = 302; O.resp = 222; O.rate = 500; O.time_s = 10; O.warmup_s = 2; O.max_conc = 2048; O.seed = 1;
    static struct option lo[] = {{"addr", 1, 0, 'a'}, {"port", 1, 0, 'p'}, {"cert", 1, 0, 'c'}, {"key", 1, 0, 'k'}, {"ca", 1, 0, 'A'}, {"groups", 1, 0, 'g'},
                                 {"req", 1, 0, 'q'}, {"resp", 1, 0, 'r'}, {"rate", 1, 0, 'x'}, {"time", 1, 0, 'T'}, {"warmup", 1, 0, 'w'}, {"resume", 0, 0, 'R'}, {"pool", 0, 0, 'L'},
                                 {"max-conc", 1, 0, 'm'}, {"seed", 1, 0, 'z'}, {0, 0, 0, 0}};
    int c;
    while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
        switch (c) {
        case 'a': O.addr = optarg; break;
        case 'p': O.port = optarg; break;
        case 'c': O.cert = optarg; break;
        case 'k': O.key = optarg; break;
        case 'A': O.ca = optarg; break;
        case 'g': O.groups = optarg; break;
        case 'q': O.req = atoi(optarg); break;
        case 'r': O.resp = atoi(optarg); break;
        case 'x': O.rate = atof(optarg); break;
        case 'T': O.time_s = atof(optarg); break;
        case 'w': O.warmup_s = atof(optarg); break;
        case 'R': O.resume = 1; break;
        case 'L': O.pool = 1; break;
        case 'm': O.max_conc = atoi(optarg); break;
        case 'z': O.seed = (unsigned)atoi(optarg); break;
        default: return 2;
        }
    }
    signal(SIGPIPE, SIG_IGN);
    CTX = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(CTX, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(CTX, TLS1_3_VERSION);
    SSL_CTX_set_mode(CTX, SSL_MODE_NO_AUTO_CHAIN);
    if (O.resume) {
        SSL_CTX_set_session_cache_mode(CTX, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        SSL_CTX_sess_set_new_cb(CTX, new_session_cb);
    } else {
        SSL_CTX_set_session_cache_mode(CTX, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_options(CTX, SSL_OP_NO_TICKET);
    }
    if (O.groups && SSL_CTX_set1_groups_list(CTX, O.groups) != 1) { ERR_print_errors_fp(stderr); return 1; }
    if (O.cert && O.key && (SSL_CTX_use_certificate_chain_file(CTX, O.cert) != 1 || SSL_CTX_use_PrivateKey_file(CTX, O.key, SSL_FILETYPE_PEM) != 1)) { ERR_print_errors_fp(stderr); return 1; }
    if (O.ca && SSL_CTX_load_verify_locations(CTX, O.ca, NULL) != 1) { ERR_print_errors_fp(stderr); return 1; }
    SSL_CTX_set_verify(CTX, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(CTX, 8);
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(O.addr, O.port, &hints, &AI) != 0) { fprintf(stderr, "tls_load_open: getaddrinfo\n"); return 1; }
    if (O.resume) {                                   /* the ticket: one full transaction first */
        unsigned char *rq = calloc(O.req, 1), *rs = malloc(O.resp);
        int dummy = 0;
        if (O.pool) { for (int k = 0; k < 64; k++) transact(rq, rs, NULL, &dummy); }     /* a stock of tickets */
        else for (int k = 0; k < 20 && !SESS; k++) transact(rq, rs, NULL, &dummy);
        free(rq); free(rs);
        if (!SESS && NPOOL == 0) { fprintf(stderr, "tls_load_open: no session ticket obtained\n"); return 1; }
    }
    srand48(O.seed);
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&at, 512 * 1024);
    double t_start = now_ms();
    T_MEASURE = t_start + O.warmup_s * 1e3;
    T_END = T_MEASURE + O.time_s * 1e3;
    double next = t_start;
    while (next < T_END) {
        next += -log(1.0 - drand48()) / O.rate * 1e3;
        double wait = next - now_ms();
        if (wait > 0) {
            struct timespec ts = {(time_t)(wait / 1e3), (long)(fmod(wait, 1e3) * 1e6)};
            nanosleep(&ts, NULL);
        }
        if ((int)__atomic_load_n(&ACTIVE, __ATOMIC_RELAXED) >= O.max_conc) {
            if (next >= T_MEASURE) __atomic_fetch_add(&DROPPED, 1, __ATOMIC_RELAXED);
            continue;
        }
        pthread_t th;
        __atomic_fetch_add(&ACTIVE, 1, __ATOMIC_RELAXED);
        if (pthread_create(&th, &at, one_connection, NULL) != 0) __atomic_fetch_sub(&ACTIVE, 1, __ATOMIC_RELAXED);
    }
    while (__atomic_load_n(&ACTIVE, __ATOMIC_RELAXED) > 0 && now_ms() < T_END + 35000) usleep(20000);
    printf("rate_target,time_s,started,ok,err,dropped,rate_ok,p50_ms,p90_ms,p99_ms,p999_ms,max_ms,first_error\n");
    printf("%.1f,%.2f,%lu,%lu,%lu,%lu,%.1f,%.3f,%.3f,%.3f,%.3f,%.3f,%s\n", O.rate, O.time_s, STARTED, OK, ERR, DROPPED, OK / O.time_s,
           pct(0.5), pct(0.9), pct(0.99), pct(0.999), MAXMS, FIRST_ERR);
    return 0;
}
