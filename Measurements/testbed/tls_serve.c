/*
 * tls_serve.c - event-driven (epoll, non-blocking) TLS 1.3 server for capacity tests, paper 2 (WP2).
 *
 * One thread per process, as many connections in flight as the clients open: unlike the blocking tls_probe server, a core is kept busy
 * by interleaving handshakes, which is how production servers (nginx, HAProxy, Envoy) work. Per connection: TLS 1.3 handshake, read
 * --req bytes, write --resp bytes, close_notify, close. Run one process per core (--reuseport, taskset) and read the counters with
 * SIGUSR1:  STATS,<transactions completed>,<user cpu s>,<system cpu s>  on stdout (this process).
 *
 *   tls_serve --addr A --port P --cert full_chain.pem --key k.pem [--mtls --ca root.pem] [--resume] [--reuseport]
 *             --groups G --req Q --resp R
 * Build: gcc -O2 -Wall -o tls_serve tls_serve.c -I$P/include -L$P/lib -lssl -lcrypto -Wl,-rpath,$P/lib
 * Ticket keys are fixed with --resume (TEST ONLY) so that the processes accept each other's tickets.
 */
#define _GNU_SOURCE
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

enum { ST_HS, ST_READ, ST_WRITE, ST_SHUT };

typedef struct Conn {
    int fd, state, got, put;
    SSL *ssl;
} Conn;

static int REQ = 302, RESP = 222;
static unsigned char *RBUF, *WBUF;
static volatile sig_atomic_t g_stats;
static unsigned long g_hs_done;     /* handshakes that completed on the server (SSL_accept returned 1) */
static void on_usr1(int s) { (void)s; g_stats = 1; }

static void conn_free(int ep, Conn *c) {
    epoll_ctl(ep, EPOLL_CTL_DEL, c->fd, NULL);
    SSL_free(c->ssl);
    close(c->fd);
    free(c);
}

static void rearm(int ep, Conn *c, unsigned events) {
    struct epoll_event ev = {.events = events, .data.ptr = c};
    epoll_ctl(ep, EPOLL_CTL_MOD, c->fd, &ev);
}

/* advance one connection as far as it goes; returns 1 when it completed a transaction */
static int drive(int ep, Conn *c, unsigned long *done) {
    for (;;) {
        int r, e;
        switch (c->state) {
        case ST_HS:
            r = SSL_accept(c->ssl);
            if (r == 1) {
                static int shown;
                g_hs_done++;
                if (getenv("TLS_SERVE_DEBUG") && shown < 2) { shown++; fprintf(stderr, "DEBUG %s %s group=%s\n", SSL_get_version(c->ssl), SSL_get_cipher_name(c->ssl), SSL_group_to_name(c->ssl, SSL_get_negotiated_group(c->ssl))); }
                c->state = ST_READ; continue;
            }
            e = SSL_get_error(c->ssl, r);
            if (e == SSL_ERROR_WANT_READ) { rearm(ep, c, EPOLLIN); return 0; }
            if (e == SSL_ERROR_WANT_WRITE) { rearm(ep, c, EPOLLOUT); return 0; }
            ERR_clear_error();
            conn_free(ep, c);
            return 0;
        case ST_READ:
            while (c->got < REQ) {
                r = SSL_read(c->ssl, RBUF, REQ - c->got);
                if (r <= 0) {
                    e = SSL_get_error(c->ssl, r);
                    if (e == SSL_ERROR_WANT_READ) { rearm(ep, c, EPOLLIN); return 0; }
                    if (e == SSL_ERROR_WANT_WRITE) { rearm(ep, c, EPOLLOUT); return 0; }
                    ERR_clear_error();
                    conn_free(ep, c);
                    return 0;
                }
                c->got += r;
            }
            c->state = ST_WRITE;
            continue;
        case ST_WRITE:
            while (c->put < RESP) {
                r = SSL_write(c->ssl, WBUF + c->put, RESP - c->put);
                if (r <= 0) {
                    e = SSL_get_error(c->ssl, r);
                    if (e == SSL_ERROR_WANT_WRITE) { rearm(ep, c, EPOLLOUT); return 0; }
                    if (e == SSL_ERROR_WANT_READ) { rearm(ep, c, EPOLLIN); return 0; }
                    ERR_clear_error();
                    conn_free(ep, c);
                    return 0;
                }
                c->put += r;
            }
            (*done)++;
            c->state = ST_SHUT;
            continue;
        default:
            SSL_shutdown(c->ssl);      /* close_notify; we do not wait for the peer's */
            ERR_clear_error();
            conn_free(ep, c);
            return 1;
        }
    }
}

int main(int argc, char **argv) {
    const char *addr = "127.0.0.1", *port = "4433", *cert = NULL, *key = NULL, *ca = NULL, *groups = NULL;
    int mtls = 0, resume = 0, reuseport = 0, c;
    static struct option lo[] = {{"addr", 1, 0, 'a'}, {"port", 1, 0, 'p'}, {"cert", 1, 0, 'c'}, {"key", 1, 0, 'k'}, {"ca", 1, 0, 'A'},
                                 {"groups", 1, 0, 'g'}, {"mtls", 0, 0, 'm'}, {"req", 1, 0, 'q'}, {"resp", 1, 0, 'r'},
                                 {"resume", 0, 0, 'R'}, {"reuseport", 0, 0, 'P'}, {0, 0, 0, 0}};
    while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
        switch (c) {
        case 'a': addr = optarg; break;
        case 'p': port = optarg; break;
        case 'c': cert = optarg; break;
        case 'k': key = optarg; break;
        case 'A': ca = optarg; break;
        case 'g': groups = optarg; break;
        case 'm': mtls = 1; break;
        case 'q': REQ = atoi(optarg); break;
        case 'r': RESP = atoi(optarg); break;
        case 'R': resume = 1; break;
        case 'P': reuseport = 1; break;
        default: return 2;
        }
    }
    RBUF = malloc(REQ + 1);
    WBUF = calloc(RESP + 1, 1);
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_mode(ctx, SSL_MODE_NO_AUTO_CHAIN | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (resume) {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"pqcprobe", 8);
        SSL_CTX_set_num_tickets(ctx, 1);
        unsigned char keys[80];
        for (int i = 0; i < 80; i++) keys[i] = (unsigned char)(0x5a ^ (i * 37));
        SSL_CTX_set_tlsext_ticket_keys(ctx, keys, sizeof keys);
    } else {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
        SSL_CTX_set_num_tickets(ctx, 0);
    }
    if ((groups && SSL_CTX_set1_groups_list(ctx, groups) != 1) || !cert || !key || SSL_CTX_use_certificate_chain_file(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (ca) { SSL_CTX_load_verify_locations(ctx, ca, NULL); SSL_CTX_set_verify_depth(ctx, 8); }
    SSL_CTX_set_verify(ctx, mtls ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : SSL_VERIFY_NONE, NULL);

    struct addrinfo hints = {0}, *ai;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(addr, port, &hints, &ai) != 0) { fprintf(stderr, "tls_serve: getaddrinfo\n"); return 1; }
    int ls = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK, ai->ai_protocol), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (reuseport) setsockopt(ls, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    if (bind(ls, ai->ai_addr, ai->ai_addrlen) != 0 || listen(ls, 4096) != 0) { perror("tls_serve: bind/listen"); return 1; }
    freeaddrinfo(ai);
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);

    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.ptr = NULL}, evs[256];
    epoll_ctl(ep, EPOLL_CTL_ADD, ls, &ev);
    unsigned long done = 0;
    printf("READY\n");
    fflush(stdout);
    for (;;) {
        int n = epoll_wait(ep, evs, 256, -1);
        if (g_stats) {
            struct rusage ru;
            getrusage(RUSAGE_SELF, &ru);
            printf("STATS,%lu,%.6f,%.6f,%lu\n", done, ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6, ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6, g_hs_done);
            fflush(stdout);
            g_stats = 0;
        }
        for (int i = 0; i < n; i++) {
            Conn *cn = evs[i].data.ptr;
            if (!cn) {                               /* listening socket: accept everything pending */
                for (;;) {
                    int fd = accept4(ls, NULL, NULL, SOCK_NONBLOCK);
                    if (fd < 0) break;
                    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
                    Conn *k = calloc(1, sizeof *k);
                    k->fd = fd;
                    k->ssl = SSL_new(ctx);
                    SSL_set_fd(k->ssl, fd);
                    struct epoll_event e2 = {.events = EPOLLIN, .data.ptr = k};
                    epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e2);
                    drive(ep, k, &done);             /* the ClientHello may already be there */
                }
            } else {
                drive(ep, cn, &done);
            }
        }
    }
}
