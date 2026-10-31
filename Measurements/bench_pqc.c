/*
 * bench_pqc.c - per-operation CPU cost of the primitives used by the TLS 1.3 handshake,
 * measured with the same OpenSSL 3.5 EVP implementation that s_server/s_client use.
 *
 *   gcc -O2 -o bench_pqc bench_pqc.c -I$HOME/opt/openssl-3.5/include -L$HOME/opt/openssl-3.5/lib -lcrypto
 *   taskset -c 19 ./bench_pqc [seconds_per_op] [repeats]
 *
 * Output CSV: alg,op,median_us,min_us,max_us,iters
 * Signatures sign a 512-byte message (one-shot; SHA-256 for RSA-PSS/ECDSA, pure mode for ML-DSA/SLH-DSA).
 */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static void die(const char *what) {
    fprintf(stderr, "error: %s\n", what);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static EVP_PKEY *keygen(const char *alg) {
    EVP_PKEY *k = NULL;
    if (!strcmp(alg, "RSA-2048") || !strcmp(alg, "RSA-3072"))
        k = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)(alg[4] == '2' ? 2048 : 3072));
    else if (!strcmp(alg, "ECDSA-P256") || !strcmp(alg, "P-256"))
        k = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    else
        k = EVP_PKEY_Q_keygen(NULL, NULL, alg);
    if (!k) die(alg);
    return k;
}

typedef int (*op_fn)(void *);
typedef struct { double secs; int reps; } cfg_t;

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Run fn repeatedly for cfg.secs, `reps` times; report median/min/max of the per-op mean (us). */
static void bench(const char *alg, const char *op, op_fn fn, void *arg, cfg_t c) {
    double v[64];
    long iters = 0;
    for (int r = 0; r < c.reps; r++) {
        long n = 0;
        double t0 = now_us(), t;
        do {
            if (!fn(arg)) die(op);
            n++;
            t = now_us();
        } while (t - t0 < c.secs * 1e6 || n < 3);
        v[r] = (t - t0) / n;
        iters += n;
    }
    qsort(v, c.reps, sizeof(double), cmp);
    printf("%s,%s,%.3f,%.3f,%.3f,%ld\n", alg, op, v[c.reps / 2], v[0], v[c.reps - 1], iters);
    fflush(stdout);
}

/* ---------------- signatures ---------------- */
typedef struct { EVP_PKEY *k; const char *md; int pss; unsigned char msg[512]; unsigned char sig[60000]; size_t siglen; } sig_t;

static int do_sign(void *p) {
    sig_t *s = p;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int ok = EVP_DigestSignInit_ex(c, &pc, s->md, NULL, NULL, s->k, NULL) == 1;
    if (ok && s->pss) ok = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1;
    s->siglen = sizeof(s->sig);
    ok = ok && EVP_DigestSign(c, s->sig, &s->siglen, s->msg, sizeof(s->msg)) == 1;
    EVP_MD_CTX_free(c);
    return ok;
}

static int do_verify(void *p) {
    sig_t *s = p;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int ok = EVP_DigestVerifyInit_ex(c, &pc, s->md, NULL, NULL, s->k, NULL) == 1;
    if (ok && s->pss) ok = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1;
    ok = ok && EVP_DigestVerify(c, s->sig, s->siglen, s->msg, sizeof(s->msg)) == 1;
    EVP_MD_CTX_free(c);
    return ok;
}

static void bench_sig(const char *alg, cfg_t c) {
    sig_t *s = calloc(1, sizeof(sig_t));
    s->k = keygen(alg);
    int classical = !strncmp(alg, "RSA", 3) || !strncmp(alg, "ECDSA", 5);
    s->md = classical ? "SHA256" : NULL;
    s->pss = !strncmp(alg, "RSA", 3);
    memset(s->msg, 0x5a, sizeof(s->msg));
    if (!do_sign(s)) die("first sign");
    bench(alg, "sign", do_sign, s, c);
    bench(alg, "verify", do_verify, s, c);
    printf("%s,sigbytes,%zu,%zu,%zu,0\n", alg, s->siglen, s->siglen, s->siglen);
    EVP_PKEY_free(s->k);
    free(s);
}

/* ---------------- key establishment ---------------- */
typedef struct { const char *alg; EVP_PKEY *k, *peer; unsigned char ct[4096], ss[128]; size_t ctlen, sslen; } kex_t;

static int do_keygen(void *p) {
    kex_t *x = p;
    EVP_PKEY *k = keygen(x->alg);
    EVP_PKEY_free(k);
    return 1;
}

static int do_derive(void *p) {             /* ECDH / X25519 shared secret */
    kex_t *x = p;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, x->k, NULL);
    x->sslen = sizeof(x->ss);
    int ok = EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, x->peer) == 1 &&
             EVP_PKEY_derive(c, x->ss, &x->sslen) == 1;
    EVP_PKEY_CTX_free(c);
    return ok;
}

static int do_encap(void *p) {
    kex_t *x = p;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, x->k, NULL);
    x->ctlen = sizeof(x->ct);
    x->sslen = sizeof(x->ss);
    int ok = EVP_PKEY_encapsulate_init(c, NULL) == 1 && EVP_PKEY_encapsulate(c, x->ct, &x->ctlen, x->ss, &x->sslen) == 1;
    EVP_PKEY_CTX_free(c);
    return ok;
}

static int do_decap(void *p) {
    kex_t *x = p;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(NULL, x->k, NULL);
    unsigned char ss[128];
    size_t sl = sizeof(ss);
    int ok = EVP_PKEY_decapsulate_init(c, NULL) == 1 && EVP_PKEY_decapsulate(c, ss, &sl, x->ct, x->ctlen) == 1;
    EVP_PKEY_CTX_free(c);
    return ok;
}

static void bench_kex(const char *alg, int kem, cfg_t c) {
    kex_t *x = calloc(1, sizeof(kex_t));
    x->alg = alg;
    x->k = keygen(alg);
    bench(alg, "keygen", do_keygen, x, c);
    if (kem) {
        if (!do_encap(x)) die("encap");
        bench(alg, "encaps", do_encap, x, c);
        bench(alg, "decaps", do_decap, x, c);
    } else {
        x->peer = keygen(alg);
        bench(alg, "derive", do_derive, x, c);
        EVP_PKEY_free(x->peer);
    }
    EVP_PKEY_free(x->k);
    free(x);
}

int main(int argc, char **argv) {
    cfg_t c = { argc > 1 ? atof(argv[1]) : 0.5, argc > 2 ? atoi(argv[2]) : 7 };
    if (c.reps > 64) c.reps = 64;
    printf("alg,op,median_us,min_us,max_us,iters\n");
    const char *sigs[] = { "RSA-2048", "RSA-3072", "ECDSA-P256", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                           "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s" };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(*sigs); i++) bench_sig(sigs[i], c);
    bench_kex("X25519", 0, c);
    bench_kex("P-256", 0, c);
    const char *kems[] = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" };
    for (size_t i = 0; i < 3; i++) bench_kex(kems[i], 1, c);
    return 0;
}
