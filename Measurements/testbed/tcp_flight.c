/*
 * tcp_flight.c - measures how Linux grows the congestion window of a fresh connection after a flight of n1 segments,
 * and what a second flight of n2 segments then costs, with no TLS in the way. Paper 2, WP5: tests the "slack" hypothesis
 * (the model's rule cwnd < 2 x segments-in-flight, loosened by `slack` segments; Simulation/pqc_sim.py, Net.cwnd_slack).
 *
 *   tcp_flight server --bind ADDR [--port 4500]
 *   tcp_flight client --connect ADDR [--port 4500] --n1 1,2,3 --n2 1,12 --reps 20 [--split] [--mss 1448] [--delay-ms 20] [--nodelay 0|1]
 *
 * One connection per (n1, n2, rep). The client writes burst 1 (n1 full segments, the first 12 bytes carry the sizes), waits for a
 * 100-byte reply (which acknowledges all of burst 1: nothing is in flight), reads TCP_INFO (snd_cwnd = the window the kernel actually
 * grew), writes burst 2 (n2 segments; with --split an 80-byte write first, like the TLS Finished before the request) and waits for a
 * 1-byte reply. This is the shape of a resumed TLS 1.3 client: ClientHello (burst 1), server flight, Finished + request (burst 2).
 *
 * CSV on stdout: n1,n2,rep,split,snd_mss,cwnd0,cwnd_pre2,ssthresh,unacked_pre2,t_b1_ms,t_b2_ms,cwnd_end,retrans,rtt_us,err
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define HDR 12
#define REPLY1 100

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static int rd_all(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int wr_all(int fd, const void *buf, size_t n) {
    size_t put = 0;
    while (put < n) {
        ssize_t r = write(fd, (const char *)buf + put, n - put);
        if (r <= 0) return -1;
        put += (size_t)r;
    }
    return 0;
}

static int listen_sock(const char *addr, const char *port) {
    const int server = 1;
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = server ? AI_PASSIVE : 0;
    if (getaddrinfo(addr, port, &hints, &res)) return -1;
    int fd = -1;
    for (p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (server) {
            int one = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
            if (bind(fd, p->ai_addr, p->ai_addrlen) == 0 && listen(fd, 16) == 0) break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

static int run_server(const char *bind_addr, const char *port, int nodelay) {
    int lfd = listen_sock(bind_addr, port);
    if (lfd < 0) { perror("tcp_flight: bind"); return 1; }
    printf("READY\n");
    fflush(stdout);
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) continue;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof nodelay);
        uint32_t h[3];
        if (rd_all(fd, h, HDR) == 0) {
            uint32_t b1 = ntohl(h[0]), b2 = ntohl(h[1]);
            char *buf = malloc(b1 > b2 ? b1 : b2);
            if (buf && b1 >= HDR && rd_all(fd, buf, b1 - HDR) == 0) {
                char reply[REPLY1] = {0};
                if (wr_all(fd, reply, sizeof reply) == 0 && rd_all(fd, buf, b2) == 0) wr_all(fd, "x", 1);
            }
            free(buf);
        }
        close(fd);
    }
}

static int list(const char *s, int *out, int max) {
    int n = 0;
    char *c = strdup(s), *tok = strtok(c, ",");
    while (tok && n < max) { out[n++] = atoi(tok); tok = strtok(NULL, ","); }
    free(c);
    return n;
}

static int run_client(const char *addr, const char *port, const char *n1s, const char *n2s, int reps, int split, int mss_req,
                      int delay_ms, int nodelay) {
    int n1[128], n2[128];
    int c1 = list(n1s, n1, 128), c2 = list(n2s, n2, 128);
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(addr, port, &hints, &res)) { fprintf(stderr, "tcp_flight: resolve %s\n", addr); return 1; }
    printf("n1,n2,rep,split,snd_mss,cwnd0,cwnd_pre2,ssthresh,unacked_pre2,t_b1_ms,t_b2_ms,cwnd_end,retrans,rtt_us,err\n");
    for (int rep = 0; rep < reps; rep++)
        for (int i = 0; i < c1; i++)
            for (int j = 0; j < c2; j++) {
                const char *err = "";
                int fd = socket(res->ai_family, SOCK_STREAM, 0);
                if (nodelay >= 0) setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof nodelay);
                if (mss_req > 0) setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss_req, sizeof mss_req);
                struct tcp_info ti;
                socklen_t tl = sizeof ti;
                unsigned mss = 0, cwnd0 = 0, cw2 = 0, ssth = 0, unack = 0, cwe = 0, retr = 0, rtt = 0;
                double t1 = -1, t2 = -1;
                if (connect(fd, res->ai_addr, res->ai_addrlen)) { err = "connect"; goto out; }
                if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tl) == 0) { mss = ti.tcpi_snd_mss; cwnd0 = ti.tcpi_snd_cwnd; }
                if (!mss) { err = "mss"; goto out; }
                {
                    size_t b1 = (size_t)n1[i] * mss, b2 = (size_t)n2[j] * mss;
                    if (split && n2[j] > 1) b2 = 80 + (size_t)(n2[j] - 1) * mss;      /* the header tells the server how many bytes burst 2 has */
                    if (b1 < HDR) b1 = HDR;
                    char *buf = calloc(1, (b1 > b2 ? b1 : b2) + 8);
                    uint32_t h[3] = {htonl((uint32_t)b1), htonl((uint32_t)b2), htonl(REPLY1)};
                    memcpy(buf, h, HDR);
                    double t0 = now_ms();
                    char rep1[REPLY1];
                    if (wr_all(fd, buf, b1) || rd_all(fd, rep1, REPLY1)) { err = "burst1"; free(buf); goto out; }
                    t1 = now_ms() - t0;
                    tl = sizeof ti;
                    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tl) == 0) { cw2 = ti.tcpi_snd_cwnd; ssth = ti.tcpi_snd_ssthresh; unack = ti.tcpi_unacked; }
                    double ta = now_ms();
                    char one;
                    if (split && n2[j] > 1) {
                        if (wr_all(fd, buf, 80) || wr_all(fd, buf, b2 - 80)) { err = "burst2"; free(buf); goto out; }
                    } else if (wr_all(fd, buf, b2)) { err = "burst2"; free(buf); goto out; }
                    if (rd_all(fd, &one, 1)) { err = "reply2"; free(buf); goto out; }
                    t2 = now_ms() - ta;
                    free(buf);
                    tl = sizeof ti;
                    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tl) == 0) { cwe = ti.tcpi_snd_cwnd; retr = ti.tcpi_total_retrans; rtt = ti.tcpi_rtt; }
                }
            out:
                printf("%d,%d,%d,%d,%u,%u,%u,%u,%u,%.3f,%.3f,%u,%u,%u,%s\n", n1[i], n2[j], rep, split, mss, cwnd0, cw2, ssth, unack, t1, t2, cwe, retr, rtt, err);
                fflush(stdout);
                close(fd);
                if (delay_ms > 0) usleep((useconds_t)delay_ms * 1000);
            }
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
        fprintf(stderr, "usage: %s server|client [options] (see the header of tcp_flight.c)\n", argv[0]);
        return 2;
    }
    const char *addr = "127.0.0.1", *port = "4500", *n1s = "1", *n2s = "1";
    int reps = 10, split = 0, mss = 0, delay = 20, nodelay = 1;
    static struct option lo[] = {{"bind", 1, 0, 'b'}, {"connect", 1, 0, 'c'}, {"port", 1, 0, 'p'}, {"n1", 1, 0, '1'}, {"n2", 1, 0, '2'},
                                 {"reps", 1, 0, 'r'}, {"split", 0, 0, 's'}, {"mss", 1, 0, 'm'}, {"delay-ms", 1, 0, 'd'}, {"nodelay", 1, 0, 'n'}, {0, 0, 0, 0}};
    int c;
    optind = 2;
    while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
        switch (c) {
        case 'b': case 'c': addr = optarg; break;
        case 'p': port = optarg; break;
        case '1': n1s = optarg; break;
        case '2': n2s = optarg; break;
        case 'r': reps = atoi(optarg); break;
        case 's': split = 1; break;
        case 'm': mss = atoi(optarg); break;
        case 'd': delay = atoi(optarg); break;
        case 'n': nodelay = atoi(optarg); break;
        default: return 2;
        }
    }
    return strcmp(argv[1], "server") == 0 ? run_server(addr, port, nodelay) : run_client(addr, port, n1s, n2s, reps, split, mss, delay, nodelay);
}
