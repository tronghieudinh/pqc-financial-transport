/*
 * tls_probe.c - TLS 1.3 client/server probe for the PQC transport testbed (OpenSSL >= 3.5).
 *
 * One transaction = new TCP connection + full TLS 1.3 handshake (no tickets, no session cache)
 * + one request of --req bytes + one response of --resp bytes. The client prints one CSV row
 * per measured transaction:
 *   i,t_tcp_ms,t_hs_ms,t_total_ms,bytes_w,bytes_r,snd_mss,snd_cwnd0,retrans,rtt_us,data_segs_out,data_segs_in,err,reused,prime_ms
 *     reused      1 if the measured connection resumed a session (PSK), else 0
 *     prime_ms    with --resume: total time of the full transaction that obtained the ticket just before (same network
 *                 conditions, same connection pattern), -1 otherwise
 *     t_tcp_ms    connect() duration (SYN -> SYN/ACK)
 *     t_hs_ms     connect() start -> SSL_connect() returned (client Finished sent)
 *     t_total_ms  connect() start -> last byte of the response received
 *     bytes_w/r   TCP payload bytes written/read by the client (TLS records, all flights)
 *     snd_mss     TCP_INFO snd_mss right after connect (the payload per segment actually used)
 *     snd_cwnd0   TCP_INFO snd_cwnd right after connect (the initial window actually used)
 *     retrans     total TCP retransmissions of the connection (client side)
 *     data_segs_out / data_segs_in   data-carrying TCP segments sent / received by the client (TCP_INFO, Linux >= 4.15);
 *                 more than ceil(bytes / MSS) when the library writes a flight in several write() calls
 *
 * With --resume (on both sides) every measured transaction is a RESUMED one: the client first runs a full transaction on a
 * separate connection to obtain a TLS 1.3 session ticket (not counted as a measurement, but its time is reported in prime_ms), then
 * opens a new TCP connection that offers the ticket (PSK with (EC)DHE key exchange) and measures that one. The server issues one
 * stateless ticket per full handshake; under mutual TLS OpenSSL stores the client certificate in the ticket.
 *
 *   server: tls_probe server --addr A --port P --cert full_chain.pem --key k.pem
 *                            [--mtls --ca root.pem] [--resume] [--reuseport] --groups G --req Q --resp R
 *   client: tls_probe client --addr A --port P --ca root.pem --groups G
 *                            [--cert full_chain.pem --key k.pem] [--resume] --req Q --resp R
 *                            --n N --warmup W --gap-ms MS
 *
 * Build: gcc -O2 -Wall -o tls_probe tls_probe.c -I$P/include -L$P/lib -lssl -lcrypto -Wl,-rpath,$P/lib
 */
#define _GNU_SOURCE
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    const char *addr, *port, *cert, *key, *ca, *groups;
    int mtls, req, resp, n, warmup, resume, reuseport;
    double gap_ms;
} Opt;

static volatile sig_atomic_t g_stats_req;   /* SIGUSR1: the server prints STATS (capacity tests) */
static void on_usr1(int sig) { (void)sig; g_stats_req = 1; }

static SSL_SESSION *g_sess;    /* the newest ticket received by the client (--resume) */

static int new_session_cb(SSL *ssl, SSL_SESSION *sess) {
    (void)ssl;
    if (g_sess) SSL_SESSION_free(g_sess);
    g_sess = sess;              /* keep the reference handed to us */
    return 1;
}

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static void set_timeouts(int fd, int sec) {
    struct timeval tv = {sec, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
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

static int write_all(SSL *ssl, const unsigned char *buf, int n) {
    int done = 0;
    while (done < n) {
        int r = SSL_write(ssl, buf + done, n - done);
        if (r <= 0) return -1;
        done += r;
    }
    return done;
}

static int fail(const char *what) {
    fprintf(stderr, "tls_probe: %s\n", what);
    ERR_print_errors_fp(stderr);
    return 1;
}

static SSL_CTX *make_ctx(const Opt *o, int server) {
    SSL_CTX *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if (o->resume) {
        if (server) {
            SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);   /* stateless tickets only */
            SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"pqcprobe", 8);
            SSL_CTX_set_num_tickets(ctx, 1);
            {   /* fixed ticket keys (TEST ONLY): all server processes of a capacity test must accept each other's tickets */
                unsigned char keys[80];
                for (int i = 0; i < 80; i++) keys[i] = (unsigned char)(0x5a ^ (i * 37));
                SSL_CTX_set_tlsext_ticket_keys(ctx, keys, sizeof keys);
            }
        } else {
            SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
            SSL_CTX_sess_set_new_cb(ctx, new_session_cb);
        }
    } else {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_NO_AUTO_CHAIN);   /* send exactly the chain in the file: no auto-built chain, no root */
    if (server && !o->resume) SSL_CTX_set_num_tickets(ctx, 0);
    if (o->groups && SSL_CTX_set1_groups_list(ctx, o->groups) != 1) { fail("groups"); SSL_CTX_free(ctx); return NULL; }
    if (o->cert && o->key) {
        if (SSL_CTX_use_certificate_chain_file(ctx, o->cert) != 1) { fail("certificate chain"); SSL_CTX_free(ctx); return NULL; }
        if (SSL_CTX_use_PrivateKey_file(ctx, o->key, SSL_FILETYPE_PEM) != 1) { fail("private key"); SSL_CTX_free(ctx); return NULL; }
    }
    if (o->ca) {
        if (SSL_CTX_load_verify_locations(ctx, o->ca, NULL) != 1) { fail("CA file"); SSL_CTX_free(ctx); return NULL; }
        SSL_CTX_set_verify_depth(ctx, 8);
    }
    if (server)
        SSL_CTX_set_verify(ctx, o->mtls ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : SSL_VERIFY_NONE, NULL);
    else
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

static int run_server(const Opt *o) {
    SSL_CTX *ctx = make_ctx(o, 1);
    if (!ctx) return 1;
    struct addrinfo hints = {0}, *ai;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(o->addr, o->port, &hints, &ai) != 0) return fail("getaddrinfo");
    int ls = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (o->reuseport) setsockopt(ls, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);   /* several server processes on one port (capacity tests) */
    if (bind(ls, ai->ai_addr, ai->ai_addrlen) != 0) return fail("bind");
    if (listen(ls, 4096) != 0) return fail("listen");
    freeaddrinfo(ai);
    unsigned char *req = malloc(o->req), *resp = calloc(o->resp, 1);
    int first = 1;
    unsigned long hs_ok = 0;
    printf("READY\n");
    fflush(stdout);
    for (;;) {
        if (g_stats_req) {          /* STATS,handshakes completed,user cpu s,system cpu s (this process) */
            struct rusage ru;
            getrusage(RUSAGE_SELF, &ru);
            printf("STATS,%lu,%.6f,%.6f\n", hs_ok, ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6, ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6);
            fflush(stdout);
            g_stats_req = 0;
        }
        int fd = accept(ls, NULL, NULL);
        if (fd < 0) continue;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        set_timeouts(fd, 30);
        if (first) {
            struct tcp_info ti;
            socklen_t len = sizeof ti;
            if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == 0) {
                printf("SRVINFO,%u,%u\n", ti.tcpi_snd_mss, ti.tcpi_snd_cwnd);
                fflush(stdout);
            }
            first = 0;
        }
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) == 1 && read_exact(ssl, req, o->req) == o->req && write_all(ssl, resp, o->resp) == o->resp) {
            hs_ok++;
            SSL_shutdown(ssl);
        } else
            ERR_clear_error();
        SSL_free(ssl);
        close(fd);
    }
}

typedef struct {
    double t0, t1, t2, t3;
    unsigned mss, cwnd0, retr, rtt, dso, dsi;
    unsigned long bw, br;
    int reused;
    const char *err;
} Result;

/* One transaction on a new TCP connection; sess != NULL offers that session (PSK resumption). */
static void transact(SSL_CTX *ctx, const struct addrinfo *ai, const Opt *o, unsigned char *req, unsigned char *resp,
                     SSL_SESSION *sess, Result *r) {
    int one = 1;
    memset(r, 0, sizeof *r);
    r->err = "";
    r->t0 = now_ms();
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    set_timeouts(fd, 30);
    SSL *ssl = NULL;
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
        r->err = "connect";
    } else {
        r->t1 = now_ms();
        struct tcp_info ti;
        socklen_t len = sizeof ti;
        if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == 0) { r->mss = ti.tcpi_snd_mss; r->cwnd0 = ti.tcpi_snd_cwnd; }
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        if (sess) SSL_set_session(ssl, sess);
        if (SSL_connect(ssl) != 1) {
            r->err = "handshake";
        } else {
            r->t2 = now_ms();
            r->reused = SSL_session_reused(ssl) ? 1 : 0;
            if (write_all(ssl, req, o->req) < 0) r->err = "write";
            else if (read_exact(ssl, resp, o->resp) < 0) r->err = "read";
            else r->t3 = now_ms();
            struct tcp_info te;
            len = sizeof te;
            if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &te, &len) == 0) { r->retr = te.tcpi_total_retrans; r->rtt = te.tcpi_rtt; }
            {   /* data_segs_in/out are at byte offsets 152/156 of the Linux uapi struct tcp_info (glibc's header lacks them) */
                unsigned char raw[256];
                socklen_t rl = sizeof raw;
                if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, raw, &rl) == 0 && rl >= 160) {
                    memcpy(&r->dsi, raw + 152, 4);
                    memcpy(&r->dso, raw + 156, 4);
                }
            }
            r->bw = BIO_number_written(SSL_get_wbio(ssl));
            r->br = BIO_number_read(SSL_get_rbio(ssl));
        }
    }
    if (*r->err) ERR_clear_error();
    if (ssl) { if (!*r->err) SSL_shutdown(ssl); SSL_free(ssl); }
    close(fd);
}

static int run_client(const Opt *o) {
    SSL_CTX *ctx = make_ctx(o, 0);
    if (!ctx) return 1;
    struct addrinfo hints = {0}, *ai;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(o->addr, o->port, &hints, &ai) != 0) return fail("getaddrinfo");
    unsigned char *req = calloc(o->req, 1), *resp = malloc(o->resp);
    printf("i,t_tcp_ms,t_hs_ms,t_total_ms,bytes_w,bytes_r,snd_mss,snd_cwnd0,retrans,rtt_us,data_segs_out,data_segs_in,err,reused,prime_ms\n");
    int consec_err = 0;
    for (int i = -o->warmup; i < o->n; i++) {
        Result r, prime;
        double prime_ms = -1.0;
        SSL_SESSION *use = NULL;
        if (o->resume) {
            /* full transaction on its own connection: yields the ticket (new_session_cb) and its time */
            transact(ctx, ai, o, req, resp, NULL, &prime);
            if (!*prime.err && g_sess && SSL_SESSION_is_resumable(g_sess)) {
                prime_ms = prime.t3 - prime.t0;
                use = g_sess;
                g_sess = NULL;
            }
            if (!use && !*prime.err) prime.err = "no_ticket";
            if (o->gap_ms > 0) {
                struct timespec ts = {(time_t)(o->gap_ms / 1000), (long)((o->gap_ms - 1000 * (time_t)(o->gap_ms / 1000)) * 1e6)};
                nanosleep(&ts, NULL);
            }
        }
        if (o->resume && !use) {
            memset(&r, 0, sizeof r);
            r.err = prime.err;          /* the priming transaction failed: report it as the error of this row */
        } else {
            transact(ctx, ai, o, req, resp, use, &r);
            if (o->resume && !*r.err && !r.reused) r.err = "not_resumed";
        }
        if (use) SSL_SESSION_free(use);
        if (i >= 0)
            printf("%d,%.3f,%.3f,%.3f,%lu,%lu,%u,%u,%u,%u,%u,%u,%s,%d,%.3f\n", i, r.t1 ? r.t1 - r.t0 : -1.0, r.t2 ? r.t2 - r.t0 : -1.0,
                   r.t3 ? r.t3 - r.t0 : -1.0, r.bw, r.br, r.mss, r.cwnd0, r.retr, r.rtt, r.dso, r.dsi, r.err, r.reused, prime_ms);
        fflush(stdout);
        consec_err = *r.err ? consec_err + 1 : 0;
        if (consec_err >= 3) { fprintf(stderr, "tls_probe: 3 consecutive errors (%s): stopping\n", r.err); break; }
        if (o->gap_ms > 0) {
            struct timespec ts = {(time_t)(o->gap_ms / 1000), (long)((o->gap_ms - 1000 * (time_t)(o->gap_ms / 1000)) * 1e6)};
            nanosleep(&ts, NULL);
        }
    }
    freeaddrinfo(ai);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
        fprintf(stderr, "usage: %s server|client [options]\n", argv[0]);
        return 2;
    }
    Opt o = {.addr = "::1", .port = "4433", .req = 302, .resp = 222, .n = 30, .warmup = 3, .gap_ms = 0};
    static struct option lo[] = {
        {"addr", 1, 0, 'a'}, {"port", 1, 0, 'p'}, {"cert", 1, 0, 'c'}, {"key", 1, 0, 'k'}, {"ca", 1, 0, 'A'},
        {"groups", 1, 0, 'g'}, {"mtls", 0, 0, 'm'}, {"req", 1, 0, 'q'}, {"resp", 1, 0, 'r'}, {"n", 1, 0, 'n'},
        {"warmup", 1, 0, 'w'}, {"gap-ms", 1, 0, 'G'}, {"resume", 0, 0, 'R'}, {"reuseport", 0, 0, 'P'}, {0, 0, 0, 0}};
    int c;
    optind = 2;
    while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
        switch (c) {
        case 'a': o.addr = optarg; break;
        case 'p': o.port = optarg; break;
        case 'c': o.cert = optarg; break;
        case 'k': o.key = optarg; break;
        case 'A': o.ca = optarg; break;
        case 'g': o.groups = optarg; break;
        case 'm': o.mtls = 1; break;
        case 'q': o.req = atoi(optarg); break;
        case 'r': o.resp = atoi(optarg); break;
        case 'n': o.n = atoi(optarg); break;
        case 'w': o.warmup = atoi(optarg); break;
        case 'G': o.gap_ms = atof(optarg); break;
        case 'R': o.resume = 1; break;
        case 'P': o.reuseport = 1; break;
        default: return 2;
        }
    }
    signal(SIGPIPE, SIG_IGN);
    {   struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_usr1;          /* no SA_RESTART: accept() returns EINTR and the loop prints the statistics */
        sigaction(SIGUSR1, &sa, NULL);
    }
    return strcmp(argv[1], "server") == 0 ? run_server(&o) : run_client(&o);
}
