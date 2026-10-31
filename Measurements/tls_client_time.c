/*
 * tls_client_time.c - one TLS 1.3 handshake to a public server with a forced key-exchange group.
 * Prints: group,tcp_ms,handshake_ms,bytes_out,bytes_in,negotiated_group
 *
 *   gcc -O2 -o tls_client_time tls_client_time.c -I$HOME/opt/openssl-3.5/include \
 *       -L$HOME/opt/openssl-3.5/lib -lssl -lcrypto
 *   ./tls_client_time host port group
 *
 * Certificate verification is disabled: only the key-establishment cost is compared.
 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s host port group\n", argv[0]); return 2; }
    struct addrinfo hints = {0}, *ai;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(argv[1], argv[2], &hints, &ai) != 0) { fprintf(stderr, "dns\n"); return 1; }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (SSL_CTX_set1_groups_list(ctx, argv[3]) != 1) { fprintf(stderr, "group\n"); return 1; }

    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    double t0 = now_ms();
    if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) { fprintf(stderr, "connect\n"); return 1; }
    double t1 = now_ms();

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, argv[1]);
    if (SSL_connect(ssl) != 1) { ERR_print_errors_fp(stderr); return 1; }
    double t2 = now_ms();

    int nid = SSL_get_negotiated_group(ssl);
    const char *gname = SSL_group_to_name(ssl, nid);
    printf("%s,%.3f,%.3f,%lu,%lu,%s\n", argv[3], t1 - t0, t2 - t1,
           BIO_number_written(SSL_get_wbio(ssl)), BIO_number_read(SSL_get_rbio(ssl)), gname ? gname : "?");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    freeaddrinfo(ai);
    return 0;
}
