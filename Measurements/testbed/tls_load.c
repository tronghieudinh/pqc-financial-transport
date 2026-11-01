/*
 * tls_load.c - closed-loop TLS 1.3 load generator for server-capacity tests (OpenSSL >= 3.5), paper 2 (WP2).
 *
 * T threads, each looping: new TCP connection -> TLS 1.3 handshake (full, or resumed with --resume) -> one request of --req bytes
 * -> one response of --resp bytes -> close. It runs for --time seconds after --warmup seconds and prints ONE CSV line:
 *   threads,time_s,ok,err,reused,rate_per_s,p50_ms,p99_ms,max_ms,first_error
 * The latency of a transaction is connect() start -> last response byte. Pair it with `tls_probe server [--reuseport]` (one process
 * per server core): the harness capacity_test.py measures the CPU time of the server processes, which this program cannot see.
 *
 *   tls_load --addr A --port P --ca root.pem --groups G [--cert full_chain.pem --key k.pem] [--resume]
 *            --req Q --resp R --threads T --time S [--warmup W]
 * Build: gcc -O2 -Wall -pthread -o tls_load tls_load.c -I$P/include -L$P/lib -lssl -lcrypto -Wl,-rpath,$P/lib
 */
#define _GNU_SOURCE
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <getopt.h>
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

#define NBIN 20000            /* latency histogram: 10-us bins up to 200 ms, last bin = overflow */
#define BIN_US 10.0

typedef struct {
    const char *addr, *port, *cert, *key, *ca, *groups, *suites;
    int req, resp, threads, resume, hs_only;
    double time_s, warmup_s;
} Opt;

typedef struct {
    unsigned long ok, err, reused, hist[NBIN];
    double max_ms;
    char first_err[48];
} Stat;

static Opt O;
static SSL_CTX *CTX;
static struct addrinfo *AI;
static double T_START, T_MEASURE, T_END;
static __thread SSL_SESSION *tl_sess;

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static int new_session_cb(SSL *ssl, SSL_SESSION *sess) {
    (void)ssl;
    if (tl_sess) SSL_SESSION_free(tl_sess);
    tl_sess = sess;
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

/* one transaction; returns NULL on success or an error tag */
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
    if (SSL_connect(ssl) != 1) {
        err = "handshake";
    } else {
        *reused = SSL_session_reused(ssl) ? 1 : 0;
        if (O.hs_only) { SSL_free(ssl); close(fd); return NULL; }   /* handshake only, like openssl s_time -new */
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

static void *worker(void *arg) {
    Stat *st = arg;
    unsigned char *req = calloc(O.req, 1), *resp = malloc(O.resp);
    int reused;
    if (O.resume) {                      /* obtain the first ticket with a full transaction */
        for (int k = 0; k < 20 && !tl_sess; k++) { reused = 0; transact(req, resp, NULL, &reused); }
    }
    while (now_ms() < T_END) {
        double t0 = now_ms();
        SSL_SESSION *use = NULL;
        if (O.resume && tl_sess) { use = tl_sess; SSL_SESSION_up_ref(use); }
        reused = 0;
        const char *e = transact(req, resp, use, &reused);
        if (use) SSL_SESSION_free(use);
        double t1 = now_ms();
        if (t0 < T_MEASURE) continue;
        if (e) {
            st->err++;
            if (!st->first_err[0]) snprintf(st->first_err, sizeof st->first_err, "%s", e);
            continue;
        }
        if (O.resume && !reused) { st->err++; if (!st->first_err[0]) snprintf(st->first_err, sizeof st->first_err, "not_resumed"); continue; }
        st->ok++;
        st->reused += reused;
        double ms = t1 - t0;
        long b = (long)(ms * 1000.0 / BIN_US);
        st->hist[b >= NBIN ? NBIN - 1 : b]++;
        if (ms > st->max_ms) st->max_ms = ms;
    }
    free(req);
    free(resp);
    return NULL;
}

int main(int argc, char **argv) {
    O.addr = "127.0.0.1"; O.port = "4433"; O.req = 302; O.resp = 222; O.threads = 4; O.time_s = 10; O.warmup_s = 2;
    static struct option lo[] = {{"addr", 1, 0, 'a'}, {"port", 1, 0, 'p'}, {"cert", 1, 0, 'c'}, {"key", 1, 0, 'k'}, {"ca", 1, 0, 'A'},
                                 {"groups", 1, 0, 'g'}, {"req", 1, 0, 'q'}, {"resp", 1, 0, 'r'}, {"threads", 1, 0, 't'},
                                 {"time", 1, 0, 'T'}, {"warmup", 1, 0, 'w'}, {"resume", 0, 0, 'R'}, {"hs-only", 0, 0, 'H'}, {"ciphersuites", 1, 0, 'C'}, {0, 0, 0, 0}};
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
        case 't': O.threads = atoi(optarg); break;
        case 'T': O.time_s = atof(optarg); break;
        case 'w': O.warmup_s = atof(optarg); break;
        case 'R': O.resume = 1; break;
        case 'H': O.hs_only = 1; break;
        case 'C': O.suites = optarg; break;
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
    if (O.suites) SSL_CTX_set_ciphersuites(CTX, O.suites);
    if (O.groups && SSL_CTX_set1_groups_list(CTX, O.groups) != 1) { ERR_print_errors_fp(stderr); return 1; }
    if (O.cert && O.key) {
        if (SSL_CTX_use_certificate_chain_file(CTX, O.cert) != 1 || SSL_CTX_use_PrivateKey_file(CTX, O.key, SSL_FILETYPE_PEM) != 1) {
            ERR_print_errors_fp(stderr); return 1;
        }
    }
    if (O.ca && SSL_CTX_load_verify_locations(CTX, O.ca, NULL) != 1) { ERR_print_errors_fp(stderr); return 1; }
    SSL_CTX_set_verify(CTX, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(CTX, 8);
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(O.addr, O.port, &hints, &AI) != 0) { fprintf(stderr, "tls_load: getaddrinfo\n"); return 1; }
    T_START = now_ms();
    T_MEASURE = T_START + O.warmup_s * 1e3;
    T_END = T_MEASURE + O.time_s * 1e3;
    pthread_t *th = malloc(sizeof(pthread_t) * O.threads);
    Stat *st = calloc(O.threads, sizeof(Stat));
    for (int i = 0; i < O.threads; i++) pthread_create(&th[i], NULL, worker, &st[i]);
    for (int i = 0; i < O.threads; i++) pthread_join(th[i], NULL);
    unsigned long ok = 0, err = 0, reused = 0, *h = calloc(NBIN, sizeof(unsigned long));
    double mx = 0;
    const char *fe = "";
    for (int i = 0; i < O.threads; i++) {
        ok += st[i].ok; err += st[i].err; reused += st[i].reused;
        if (st[i].max_ms > mx) mx = st[i].max_ms;
        if (!*fe && st[i].first_err[0]) fe = st[i].first_err;
        for (int b = 0; b < NBIN; b++) h[b] += st[i].hist[b];
    }
    double p50 = -1, p99 = -1;
    unsigned long acc = 0;
    for (int b = 0; b < NBIN && ok; b++) {
        acc += h[b];
        if (p50 < 0 && acc >= 0.5 * ok) p50 = (b + 0.5) * BIN_US / 1000.0;
        if (p99 < 0 && acc >= 0.99 * ok) p99 = (b + 0.5) * BIN_US / 1000.0;
    }
    printf("threads,time_s,ok,err,reused,rate_per_s,p50_ms,p99_ms,max_ms,first_error\n");
    printf("%d,%.2f,%lu,%lu,%lu,%.1f,%.3f,%.3f,%.3f,%s\n", O.threads, O.time_s, ok, err, reused, ok / O.time_s, p50, p99, mx, fe);
    return 0;
}
