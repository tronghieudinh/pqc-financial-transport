/*
 * tls_probe.c - TLS 1.3 client/server probe for the PQC transport testbed (OpenSSL >= 3.5).
 *
 * One transaction = new TCP connection + full TLS 1.3 handshake (no tickets, no session cache)
 * + one request of --req bytes + one response of --resp bytes. The client prints one CSV row
 * per measured transaction:
 *   i,t_tcp_ms,t_hs_ms,t_total_ms,bytes_w,bytes_r,snd_mss,snd_cwnd0,retrans,rtt_us,data_segs_out,data_segs_in,err
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
 *   server: tls_probe server --addr A --port P --cert full_chain.pem --key k.pem
 *                            [--mtls --ca root.pem] --groups G --req Q --resp R
 *   client: tls_probe client --addr A --port P --ca root.pem --groups G
 *                            [--cert full_chain.pem --key k.pem] --req Q --resp R
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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    const char *addr, *port, *cert, *key, *ca, *groups;
    int mtls, req, resp, n, warmup;
    double gap_ms;
} Opt;

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
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_mode(ctx, SSL_MODE_NO_AUTO_CHAIN);   /* send exactly the chain in the file: no auto-built chain, no root */
    if (server) SSL_CTX_set_num_tickets(ctx, 0);
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
    if (bind(ls, ai->ai_addr, ai->ai_addrlen) != 0) return fail("bind");
    if (listen(ls, 16) != 0) return fail("listen");
    freeaddrinfo(ai);
    unsigned char *req = malloc(o->req), *resp = calloc(o->resp, 1);
    int first = 1;
    printf("READY\n");
    fflush(stdout);
    for (;;) {
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
        if (SSL_accept(ssl) == 1 && read_exact(ssl, req, o->req) == o->req && write_all(ssl, resp, o->resp) == o->resp)
            SSL_shutdown(ssl);
        else
            ERR_clear_error();
        SSL_free(ssl);
        close(fd);
    }
}

static int run_client(const Opt *o) {
    SSL_CTX *ctx = make_ctx(o, 0);
    if (!ctx) return 1;
    struct addrinfo hints = {0}, *ai;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(o->addr, o->port, &hints, &ai) != 0) return fail("getaddrinfo");
    unsigned char *req = calloc(o->req, 1), *resp = malloc(o->resp);
    printf("i,t_tcp_ms,t_hs_ms,t_total_ms,bytes_w,bytes_r,snd_mss,snd_cwnd0,retrans,rtt_us,data_segs_out,data_segs_in,err\n");
    int one = 1, consec_err = 0;
    for (int i = -o->warmup; i < o->n; i++) {
        const char *err = "";
        double t0 = now_ms(), t1 = 0, t2 = 0, t3 = 0;
        unsigned mss = 0, cwnd0 = 0, retr = 0, rtt = 0, dso = 0, dsi = 0;
        unsigned long bw = 0, br = 0;
        int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        set_timeouts(fd, 30);
        SSL *ssl = NULL;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
            err = "connect";
        } else {
            t1 = now_ms();
            struct tcp_info ti;
            socklen_t len = sizeof ti;
            if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == 0) { mss = ti.tcpi_snd_mss; cwnd0 = ti.tcpi_snd_cwnd; }
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
            if (SSL_connect(ssl) != 1) {
                err = "handshake";
            } else {
                t2 = now_ms();
                if (write_all(ssl, req, o->req) < 0) err = "write";
                else if (read_exact(ssl, resp, o->resp) < 0) err = "read";
                else t3 = now_ms();
                struct tcp_info te;
                len = sizeof te;
                if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &te, &len) == 0) { retr = te.tcpi_total_retrans; rtt = te.tcpi_rtt; }
                {   /* data_segs_in/out are at byte offsets 152/156 of the Linux uapi struct tcp_info (glibc's header lacks them) */
                    unsigned char raw[256];
                    socklen_t rl = sizeof raw;
                    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, raw, &rl) == 0 && rl >= 160) {
                        memcpy(&dsi, raw + 152, 4);
                        memcpy(&dso, raw + 156, 4);
                    }
                }
                bw = BIO_number_written(SSL_get_wbio(ssl));
                br = BIO_number_read(SSL_get_rbio(ssl));
            }
        }
        if (*err) { ERR_clear_error(); }
        if (ssl) { if (!*err) SSL_shutdown(ssl); SSL_free(ssl); }
        close(fd);
        if (i >= 0)
            printf("%d,%.3f,%.3f,%.3f,%lu,%lu,%u,%u,%u,%u,%u,%u,%s\n", i, t1 ? t1 - t0 : -1.0, t2 ? t2 - t0 : -1.0,
                   t3 ? t3 - t0 : -1.0, bw, br, mss, cwnd0, retr, rtt, dso, dsi, err);
        fflush(stdout);
        consec_err = *err ? consec_err + 1 : 0;
        if (consec_err >= 3) { fprintf(stderr, "tls_probe: 3 consecutive errors (%s): stopping\n", err); break; }
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
        {"warmup", 1, 0, 'w'}, {"gap-ms", 1, 0, 'G'}, {0, 0, 0, 0}};
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
        default: return 2;
        }
    }
    signal(SIGPIPE, SIG_IGN);
    return strcmp(argv[1], "server") == 0 ? run_server(&o) : run_client(&o);
}
