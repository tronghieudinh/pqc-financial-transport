#!/usr/bin/env python3
"""
pqc_sim.py - Post-quantum vs. classical cryptography in financial messaging.

Deterministic, per-segment simulation of a banking transaction (TCP + TLS 1.3 +
application-layer signatures) whose message sizes follow financial standards
(ISO 8583, ISO 20022, SWIFT MX, RFC 6749/6750, OIDC, FAPI 2.0, DER X.509 /
RFC 5280, RFC 8446 TLS 1.3, RFC 8879 certificate compression).

Pipeline
    1. build_flow(): suite x protocol x chain depth x connection mode -> an
       ordered list of CPU steps and byte transfers plus a byte breakdown.
       It depends on NO network parameter, so it is built once and reused.
    2. run_flow():   replays that flow over a link (bandwidth, RTT, MTU,
       transport penalty/threshold) with an ACK-clocked TCP slow-start model.
       Latency is split into cpu / ser / prop / ssw / pen and sums exactly.
    3. sweep:        full factorial over the requested parameter ranges.

Latency components (critical path, all serial)
    cpu   cryptographic execution (sign, verify, KEM)
    ser   serialization: wire bytes / bandwidth, summed over every segment
    prop  fixed propagation: TCP/TLS handshake RTTs + one-way delay per flight
    ssw   slow-start wait: idle time waiting for ACKs because flight > cwnd
    pen   transport penalty: `penalty_ms` per flight longer than `threshold`
          segments (middlebox reassembly / DPI / out-of-order handling).
          NOT defined by any standard -> swept (sensitivity analysis).

Usage
    python3 pqc_sim.py --out results            # full user grid
    python3 pqc_sim.py --out quick --quick      # tiny grid, seconds
    python3 pqc_sim.py --thresholds 2,4,8,16 --bandwidths 100 --rtts 30 \
                       --out thr                # threshold sensitivity
Only the Python standard library is required.
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import math
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, asdict
from functools import lru_cache

# =============================================================================
# 1. CRYPTOGRAPHIC PRIMITIVES
#    Sizes: FIPS 203/204/205, FN-DSA (Falcon) round-3 spec, RFC 5280/8017/8446.
#    CPU times are MEASURED medians on one Cortex-X925 core (NVIDIA GX10, aarch64):
#    OpenSSL 3.5.4 EVP for RSA-PSS, ECDSA, X25519, P-256, ML-KEM, ML-DSA, SLH-DSA-SHA2;
#    liboqs 0.14.0 for Falcon (padded). Source: ../Measurements (make_inputs.py writes these
#    values). Analysis rescales them (x2 = measured Cortex-A725 efficiency core, x4, x16).
# =============================================================================


@dataclass(frozen=True)
class Sig:
    name: str
    family: str       # classical | lattice | hash
    pk: int           # raw public key bytes
    spki_hdr: int     # DER SubjectPublicKeyInfo framing bytes added to pk
    sig: int          # signature bytes
    sign_ms: float
    verify_ms: float


@dataclass(frozen=True)
class Kex:
    name: str
    family: str       # classical | hybrid | pqc
    client_share: int  # ClientHello key_share bytes
    server_share: int  # ServerHello key_share bytes
    gen_ms: float      # client key generation (before ClientHello)
    derive_ms: float   # client decapsulation / shared-secret derivation
    server_ms: float   # server encapsulation / derivation


SIGS = {s.name: s for s in [
    Sig("RSA-2048",     "classical",  270, 24,  256,  0.491, 0.0147),
    Sig("RSA-3072",     "classical",  398, 24,  384,  1.451, 0.0293),
    Sig("ECDSA-P256",   "classical",   65, 26,   72,  0.01446, 0.04112),
    Sig("ML-DSA-44",    "lattice",   1312, 22, 2420,  0.3594, 0.06804),
    Sig("ML-DSA-65",    "lattice",   1952, 22, 3309,  0.586, 0.103),
    Sig("ML-DSA-87",    "lattice",   2592, 22, 4627,  0.6691, 0.1589),
    Sig("Falcon-512",   "lattice",    897, 22,  666,  0.1045, 0.01755),
    Sig("Falcon-1024",  "lattice",   1793, 22, 1280,  0.2114, 0.03098),
    Sig("SLH-DSA-128s", "hash",        32, 22, 7856, 170.8, 0.1614),
    Sig("SLH-DSA-128f", "hash",        32, 22, 17088, 8.2, 0.5058),
]}

def _composite(a: str, b: str) -> Sig:
    """Composite (hybrid) signature: concatenated keys and signatures, summed CPU (IETF LAMPS draft)."""
    x, y = SIGS[a], SIGS[b]
    return Sig(f"{a}+{b}", "composite", x.pk + y.pk, 22, x.sig + y.sig, x.sign_ms + y.sign_ms,
               x.verify_ms + y.verify_ms)


for _a in ("ML-DSA-44", "ML-DSA-65"):
    _c = _composite(_a, "ECDSA-P256")
    SIGS[_c.name] = _c

KEXS = {k.name: k for k in [
    Kex("ECDHE-P256",     "classical",   65,   65, 0.008448, 0.03406, 0.04251),
    Kex("X25519",         "classical",   32,   32, 0.01326, 0.0227, 0.03596),
    Kex("X25519MLKEM768", "hybrid",    1216, 1120, 0.0311, 0.03734, 0.04516),
    Kex("ML-KEM-768",     "pqc",       1184, 1088, 0.01784, 0.01464, 0.009197),
    Kex("ML-KEM-1024",    "pqc",       1568, 1568, 0.02664, 0.01898, 0.01183),
]}


@dataclass(frozen=True)
class Suite:
    name: str
    kex: str
    sig: str


# Chain, CertificateVerify and application signatures all use `sig`.
SUITES = {s.name: s for s in [
    Suite("RSA-2048|ECDHE-P256",        "ECDHE-P256",     "RSA-2048"),
    Suite("RSA-3072|ECDHE-P256",        "ECDHE-P256",     "RSA-3072"),
    Suite("ECDSA-P256|X25519",          "X25519",         "ECDSA-P256"),      # baseline
    Suite("ECDSA-P256|X25519MLKEM768",  "X25519MLKEM768", "ECDSA-P256"),      # KEM-only migration
    Suite("ML-DSA-44|ML-KEM-768",       "ML-KEM-768",     "ML-DSA-44"),
    Suite("ML-DSA-65|ML-KEM-768",       "ML-KEM-768",     "ML-DSA-65"),
    Suite("ML-DSA-87|ML-KEM-1024",      "ML-KEM-1024",    "ML-DSA-87"),
    Suite("Falcon-512|ML-KEM-768",      "ML-KEM-768",     "Falcon-512"),
    Suite("Falcon-1024|ML-KEM-1024",    "ML-KEM-1024",    "Falcon-1024"),
    Suite("SLH-DSA-128s|ML-KEM-768",    "ML-KEM-768",     "SLH-DSA-128s"),
    Suite("SLH-DSA-128f|ML-KEM-768",    "ML-KEM-768",     "SLH-DSA-128f"),
]}
# Composite certificates with hybrid key establishment ("full hybrid" migration); not part of the
# v1-v3 sweeps, used by the mitigation experiments.
COMPOSITE_SUITES = {s.name: s for s in [
    Suite("ML-DSA-44+ECDSA-P256|X25519MLKEM768", "X25519MLKEM768", "ML-DSA-44+ECDSA-P256"),
    Suite("ML-DSA-65+ECDSA-P256|X25519MLKEM768", "X25519MLKEM768", "ML-DSA-65+ECDSA-P256"),
]}
BASE_SUITES = list(SUITES)
SUITES.update(COMPOSITE_SUITES)
BASELINE = "ECDSA-P256|X25519"

# =============================================================================
# 2. FINANCIAL PROTOCOL PROFILES
#    Message sizes include HTTP/1.1 headers and bodies (ISO 8583: 2-byte length
#    prefix) and EXCLUDE every algorithm-dependent byte (signatures, keys,
#    certificates), which are added by the model. Sizes are typical values of
#    the cited message types, not measurements of any specific institution.
# =============================================================================


@dataclass(frozen=True)
class Obj:
    """A signed (or key-carrying) object inside an application message."""
    enc: str      # xmldsig | jws | dpop | jwk
    signer: str   # client | server | pre (signed earlier, verify only) | none
    fixed: int    # algorithm-independent bytes (header+claims / SignedInfo)
    label: str = ""


@dataclass(frozen=True)
class Exchange:
    name: str
    req: int
    resp: int
    req_objs: tuple = ()
    resp_objs: tuple = ()


@dataclass(frozen=True)
class Protocol:
    name: str
    standard: str
    mtls: bool           # mutual TLS (client chain also sent)
    default_depth: int   # chain depth of the reference deployment
    exchanges: tuple


PROTOCOLS = {p.name: p for p in [
    Protocol("ISO_8583", "ISO 8583-1 0200/0210 over TLS", True, 2, (
        # MTI + bitmap + PAN/amount/STAN/... ; MAC is symmetric (no PQ impact).
        Exchange("auth", 302, 222),)),
    Protocol("ISO_20022", "ISO 20022 pacs.008.001.08 / pacs.002 over HTTPS", True, 2, (
        Exchange("pacs008", 4200, 1900,
                 (Obj("xmldsig", "client", 750, "BAH signature"),),
                 (Obj("xmldsig", "server", 750, "pacs.002 signature"),)),)),
    Protocol("SWIFT_MX", "SWIFT MX cross-border pacs.008 + LAU/XMLDSig", True, 3, (
        Exchange("pacs008_xb", 9950, 3100,
                 (Obj("xmldsig", "client", 800, "SwAP signature"),),
                 (Obj("xmldsig", "server", 800, "ack signature"),)),)),
    Protocol("OAUTH2_RFC6749", "RFC 6749 client_credentials + RFC 6750 bearer", False, 2, (
        Exchange("token", 550, 370,
                 (Obj("jws", "client", 440, "client_assertion"),),
                 (Obj("jws", "server", 700, "access_token"),)),
        Exchange("resource", 650, 950,
                 (Obj("jws", "pre", 700, "bearer token"),)))),
    Protocol("OIDC", "OpenID Connect code flow back-channel", False, 2, (
        Exchange("token", 550, 370,
                 (Obj("jws", "client", 440, "client_assertion"),),
                 (Obj("jws", "server", 800, "id_token"),
                  Obj("jws", "server", 700, "access_token"))),
        Exchange("jwks", 300, 300, (), (Obj("jwk", "none", 120, "jwks_uri key"),)),
        Exchange("userinfo", 650, 550,
                 (Obj("jws", "pre", 700, "bearer token"),)))),
    Protocol("FAPI2", "FAPI 2.0 SP + Message Signing (PAR, JAR, DPoP, mTLS)", True, 2, (
        Exchange("par", 600, 350,
                 (Obj("jws", "client", 1000, "JAR request object"),)),
        Exchange("token", 700, 400,
                 (Obj("dpop", "client", 400, "DPoP proof"),),
                 (Obj("jws", "server", 700, "access_token"),
                  Obj("jws", "server", 800, "id_token"))),
        Exchange("resource", 700, 1000,
                 (Obj("jws", "pre", 700, "access_token"),
                  Obj("dpop", "client", 450, "DPoP proof")),
                 (Obj("jws", "server", 600, "signed response"),)))),
]}

# =============================================================================
# 3. MODEL PARAMETERS NOT FIXED BY A STANDARD (all overridable from the CLI)
# =============================================================================


@dataclass(frozen=True)
class Model:
    leaf_meta: int = 900       # DER bytes of a leaf excluding SPKI+signature
    ca_meta: int = 520         # same, CA certificate (names, AKI/SKI, policies)
    r_first: float = 0.68      # zlib ratio on DER structure of the 1st cert
    r_next: float = 0.52       # ... of later certs (issuer names repeat)
    comp_fixed: int = 12       # zlib header/adler/block framing
    compress_ms_per_kb: float = 0.0   # 0 = pre-compressed & cached (RFC 8879)
    server_decomp_ms_per_kb: float = 0.003
    ch_base: int = 250         # ClientHello bytes excluding key share
    # TLS framing calibrated on real OpenSSL 3.5.4 handshakes (../Measurements/tls_trace.py):
    sh_base: int = 91          # ServerHello bytes excluding key share
    enc_ext: int = 10          # EncryptedExtensions
    cert_req: int = 53         # CertificateRequest (mTLS, signature_algorithms incl. ML-DSA)
    finished: int = 48         # Finished verify_data (TLS_AES_256_GCM_SHA384, OpenSSL default)
    record_per_message: bool = True    # OpenSSL sends each handshake message in its own record
    app_records: bool = False  # application data leaves as one write() per TLS record of up to 16,384 bytes (OpenSSL SSL_write); off: one write per message (Paper 1, whose messages are below one record in the validated cases). Paper 2, WP6: explains MTU 9000
    # mitigations (all off by default, so v2/v3 results are unchanged)
    cached_info: bool = False  # RFC 7924: client already holds the server chain (hash only)
    cached_info_ext: int = 40  # cached_info extension in the ClientHello
    mtc: bool = False          # server presents a Merkle Tree Certificate (IETF draft)
    mtc_meta: int = 150        # MTC fields besides the public key and the inclusion proof
    mtc_proof: int = 640       # inclusion proof: 20 levels x 32-byte hashes
    # PSK resumption, calibrated on OpenSSL 3.5.4 (../Measurements/resumption.py)
    ticket_base: int = 208     # stateless ticket without client certificate
    psk_ext: int = 63          # pre_shared_key identity, binder and related ClientHello bytes
    sh_psk: int = 6            # pre_shared_key extension in the ServerHello
    nst_overhead: int = 71     # NewSessionTicket message and record around the ticket
    xmldsig_embed_cert: bool = True   # KeyInfo/X509Certificate carries the signer's leaf


# Client-side decompression speed profiles (ms per KB of uncompressed data).
DECOMP_PROFILES = {
    "server-class": 0.003,    # ~330 MB/s
    "phone/laptop": 0.03,     # ~33 MB/s
    "embedded":     0.3,      # ~3.3 MB/s
    "very-slow":    3.0,      # ~330 KB/s (smart-card / secure element class)
}

# Network defaults for parameters outside the user-specified sweeps.
IP_TCP_HDR = 60       # IPv6 (40) + TCP (20); 1280 B MTU is the IPv6 minimum
TLS_REC_MAX = 16384   # RFC 8446 plaintext limit per record
TLS_REC_OVH = 22      # 5 header + 1 content type + 16 AEAD tag


def b64(n: int) -> int:     # padded base64 (XML)
    return 4 * ((n + 2) // 3)


def b64u(n: int) -> int:    # unpadded base64url (JOSE)
    return -(-4 * n // 3)


def rec_ovh(n: int) -> int:
    return -(-n // TLS_REC_MAX) * TLS_REC_OVH if n > 0 else 0


def record_writes(payload: int) -> tuple:
    """write() sizes of an application message of `payload` bytes that OpenSSL sends as records of at most TLS_REC_MAX bytes, each with its framing."""
    full, rest = divmod(payload, TLS_REC_MAX)
    return tuple([TLS_REC_MAX + TLS_REC_OVH] * full + ([rest + TLS_REC_OVH] if rest else []))


OPENSSL_BIO_BUF = 4096    # OpenSSL writes handshake messages through a 4096-byte BIO_f_buffer


def bio_buffer(msgs, size: int = OPENSSL_BIO_BUF) -> list:
    """Sizes of the write() calls OpenSSL issues for consecutive handshake messages of `msgs` bytes.

    Messages are copied into a `size`-byte buffer that is written out whenever it is full; a remainder of at
    least `size` bytes is written directly. Verified against strace of OpenSSL 3.5 (Measurements/testbed):
    ML-DSA-65, depth 1, mutual TLS: server writes 4096 + 4096 + 2688, client writes 4096 + 4096 + 1402.
    """
    out, buf = [], 0
    for n in msgs:
        while n > 0:
            if n <= size - buf:
                buf += n
                n = 0
            else:
                n -= size - buf
                out.append(size)
                buf = 0
                if n >= size:
                    out.append(n)
                    n = 0
    if buf:
        out.append(buf)
    return out


def segment_sizes(writes, mss: int, avail: int) -> list:
    """Payload sizes of the TCP segments produced by back-to-back write() calls (TCP_NODELAY, `avail` segments of room).

    Full segments leave while the window allows; a partial tail is sent at once if the window has room, otherwise
    it is merged with the next write; what is still queued after the last write leaves as the window opens.
    Verified against the kernel counters (TCP_INFO data_segs_out/in) of the testbed: 11 of 12 counts exact.
    """
    q, out = 0, []
    for w in writes:
        q += w
        while q > 0 and len(out) < avail:
            seg = min(q, mss)
            out.append(seg)
            q -= seg
    while q > 0:
        seg = min(q, mss)
        out.append(seg)
        q -= seg
    return out


def segments_of_writes(writes, mss: int, avail: int) -> int:
    return len(segment_sizes(writes, mss, avail))


# =============================================================================
# 4. DER X.509 CHAIN MODEL
# =============================================================================


def cert_len(sig: Sig, is_leaf: bool, m: Model) -> int:
    """DER certificate = TBS metadata + SPKI + signature BIT STRING (+4)."""
    return (m.leaf_meta if is_leaf else m.ca_meta) + sig.pk + sig.spki_hdr + sig.sig + 4


def cert_chain(sig: Sig, depth: int, m: Model) -> list:
    """`depth` certificates sent: leaf + (depth-1) intermediates (root omitted)."""
    return [cert_len(sig, i == 0, m) for i in range(depth)]


def certificate_msg(chain: list, sig: Sig, cc: bool, m: Model):
    """Return (bytes_on_wire, uncompressed_body_bytes, compressed_used)."""
    # handshake header(4) + context(1) + list length(3) + per entry len(3)+ext len(2)
    plain = 4 + (1 + 3 + sum(5 + L for L in chain))
    if not cc:
        return plain, 0, False
    # High-entropy fields (public key point/modulus, signature) are incompressible.
    rnd = sig.pk + sig.sig
    comp = m.comp_fixed
    for i, L in enumerate(chain):
        meta = L + 5 - rnd
        comp += rnd + meta * (m.r_first if i == 0 else m.r_next)
    compressed = 4 + 2 + 3 + 3 + int(math.ceil(comp))   # RFC 8879 CompressedCertificate
    if compressed >= plain:
        return plain, 0, False
    return compressed, 1 + 3 + sum(5 + L for L in chain), True


# =============================================================================
# 5. FLOW CONSTRUCTION (network independent)
# =============================================================================


@dataclass(frozen=True)
class Flow:
    mode: str                   # cold | warm
    steps: tuple                # ('cpu', ms) | ('hs',) | ('x', side, bytes)
    sizes: dict                 # L7 byte breakdown
    decomp_kb_cli: float        # uncompressed KB the client must inflate
    decomp_kb_srv: float        # uncompressed KB the server must inflate
    comp_kb_cli: float
    comp_kb_srv: float
    writes: tuple = ()          # per 'x' step: sizes of the write() calls that make up the transfer (OpenSSL pattern)
    nst: int = 0                # bytes of the NewSessionTicket the server sends with the first response of a resumed flow (0 otherwise)


def _obj_bytes(o: Obj, sig: Sig, leaf: int, m: Model):
    if o.enc == "xmldsig":
        return o.fixed, b64(sig.sig) + (b64(leaf) if m.xmldsig_embed_cert else 0)
    if o.enc == "jws":
        return o.fixed, b64u(sig.sig)
    if o.enc == "dpop":
        return o.fixed, b64u(sig.sig) + b64u(b64u(sig.pk) + 90)
    if o.enc == "jwk":
        return o.fixed, b64u(sig.pk)
    raise ValueError(o.enc)


@lru_cache(maxsize=None)
def build_flow(suite_name: str, proto_name: str, depth: int, mode: str,
               cc: bool, m: Model = Model(), depth_client: int = 0) -> Flow:
    """`depth` = certificates in the SERVER chain; `depth_client` = certificates in the CLIENT chain under mutual TLS
    (0 = same as `depth`, the symmetric case of Paper 1: every published number uses it)."""
    suite, proto = SUITES[suite_name], PROTOCOLS[proto_name]
    dc = depth_client or depth
    sig, kex = SIGS[suite.sig], KEXS[suite.kex]
    cold = mode == "cold"
    resumed = mode == "resumed"
    chain = cert_chain(sig, depth, m)
    cert_wire, cert_body, cc_used = certificate_msg(chain, sig, cc, m)
    if dc != depth:                             # client chain of another depth (mutual TLS only)
        cert_wire_c, cert_body_c, cc_used_c = certificate_msg(cert_chain(sig, dc, m), sig, cc, m)
    else:
        cert_wire_c, cert_body_c, cc_used_c = cert_wire, cert_body, cc_used
    srv_cert_wire, srv_verifies = cert_wire, depth + 1
    if m.mtc:                                   # one certificate, no CA signatures, proof by hashing
        srv_cert_wire = 4 + (1 + 3 + 5 + m.mtc_meta + sig.pk + sig.spki_hdr + m.mtc_proof)
        srv_verifies = 1
    if m.cached_info:                           # chain replaced by a 32-byte hash
        srv_cert_wire = 4 + (1 + 3 + 5 + 32)
        srv_verifies = 1
    cv = 4 + 2 + 2 + sig.sig
    leaf = cert_len(sig, True, m)       # embedded in XMLDSig KeyInfo (also when warm)

    payload_fixed = obj_alg = app_rec = 0
    ex_bytes = []
    for ex in proto.exchanges:
        rq, rs = ex.req, ex.resp
        payload_fixed += ex.req + ex.resp
        for o in ex.req_objs:
            f, a = _obj_bytes(o, sig, leaf, m)
            rq += f + a; payload_fixed += f; obj_alg += a
        for o in ex.resp_objs:
            f, a = _obj_bytes(o, sig, leaf, m)
            rs += f + a; payload_fixed += f; obj_alg += a
        app_rec += rec_ovh(rq) + rec_ovh(rs)
        ex_bytes.append((rq + rec_ovh(rq), rs + rec_ovh(rs), rq, rs))

    steps = []
    xw = []                       # write() sizes of every 'x' step, in order
    tls_cert = tls_cv = tls_kex = tls_other = 0
    srv_decomp = cli_decomp = 0.0
    if cold:
        ch = m.ch_base + kex.client_share + (7 if cc else 0) + (m.cached_info_ext if m.cached_info else 0)
        sh = m.sh_base + kex.server_share
        fin = 4 + m.finished
        srv = [m.enc_ext] + ([m.cert_req] if proto.mtls else []) + [srv_cert_wire, cv, fin]
        cli = ([cert_wire_c, cv] if proto.mtls else []) + [fin]
        recs = (lambda ms: sum(rec_ovh(x) for x in ms)) if m.record_per_message else (lambda ms: rec_ovh(sum(ms)))
        s_flight = sh + 6 + sum(srv) + recs(srv)
        c_hs = 6 + sum(cli) + recs(cli)
        tls_cert = srv_cert_wire + (cert_wire_c if proto.mtls else 0)
        tls_cv = cv * (2 if proto.mtls else 1)
        tls_kex = kex.client_share + kex.server_share
        tls_other = (ch + s_flight + c_hs) - tls_cert - tls_cv - tls_kex
        cli_decomp = cert_body / 1024.0 if cc_used else 0.0       # server chain -> client
        srv_decomp = cert_body_c / 1024.0 if (cc_used_c and proto.mtls) else 0.0

        steps += [("cpu", kex.gen_ms), ("hs",), ("x", 0, ch),
                  ("cpu", kex.server_ms + sig.sign_ms), ("x", 1, s_flight)]
        o = (lambda x: x + rec_ovh(x)) if m.record_per_message else (lambda x: x)
        s_units = [sh + 6] + [o(x) for x in srv]
        s_units[-1] += 0 if m.record_per_message else rec_ovh(sum(srv))
        c_units = [6 + o(cli[0])] + [o(x) for x in cli[1:]]
        c_units[-1] += 0 if m.record_per_message else rec_ovh(sum(cli))
        xw += [(ch,), tuple(bio_buffer(s_units)), tuple(bio_buffer(c_units))]
        pend = kex.derive_ms + srv_verifies * sig.verify_ms + (sig.sign_ms if proto.mtls else 0.0)
        nst = 0
    elif resumed:                               # TLS 1.3 PSK (psk_dhe_ke): no certificates, no signatures
        recs = (lambda ms: sum(rec_ovh(x) for x in ms)) if m.record_per_message else (lambda ms: rec_ovh(sum(ms)))
        ticket = m.ticket_base + ((leaf + 3) if proto.mtls else 0)   # OpenSSL embeds the client leaf
        ch = m.ch_base + kex.client_share + ticket + m.psk_ext
        sh = m.sh_base + kex.server_share + m.sh_psk
        fin = 4 + m.finished
        s_flight = sh + 6 + m.enc_ext + fin + recs([m.enc_ext, fin])
        c_hs = 6 + fin + rec_ovh(fin)
        nst = ticket + m.nst_overhead           # fresh ticket sent before the first response
        tls_kex = kex.client_share + kex.server_share
        tls_other = ch + s_flight + c_hs + nst - tls_kex
        steps += [("cpu", kex.gen_ms), ("hs",), ("x", 0, ch), ("cpu", kex.server_ms), ("x", 1, s_flight)]
        xw += [(ch,), (s_flight,), (c_hs,)]
        pend = kex.derive_ms
    else:
        pend = 0.0
        c_hs = 0
        nst = 0

    for i, ex in enumerate(proto.exchanges):
        c_cpu = pend + sum(sig.sign_ms for o in ex.req_objs if o.signer == "client")
        s_cpu = sum(sig.verify_ms for o in ex.req_objs if o.signer in ("client", "pre"))
        s_cpu += sum(sig.sign_ms for o in ex.resp_objs if o.signer == "server")
        if cold and i == 0 and proto.mtls:
            s_cpu += (dc + 1) * sig.verify_ms
        rq, rs, rq_pay, rs_pay = ex_bytes[i]
        first = (cold or resumed) and i == 0
        steps += [("cpu", c_cpu), ("x", 0, rq + (c_hs if first else 0)),
                  ("cpu", s_cpu), ("x", 1, rs + (nst if first else 0))]
        # the handshake flight and the request are separate write() calls; the response is one write
        if m.app_records:
            rqw, rsw = list(record_writes(rq_pay)), list(record_writes(rs_pay))
            if first and nst and rsw:
                rsw[-1] += nst
            xw += [tuple(list(xw.pop()) + rqw) if first else tuple(rqw), tuple(rsw)]
        else:
            xw += [tuple(list(xw.pop()) + [rq]) if first else (rq,), (rs + (nst if first else 0),)]
        pend = sum(sig.verify_ms for o in ex.resp_objs if o.signer in ("server", "pre"))
    steps.append(("cpu", pend))

    sizes = dict(payload_fixed=payload_fixed, obj_alg=obj_alg, tls_cert=tls_cert,
                 tls_cv=tls_cv, tls_kex=tls_kex, tls_other=tls_other + app_rec)
    sizes["total_l7"] = sum(sizes.values())
    return Flow(mode, tuple(steps), sizes, cli_decomp, srv_decomp,
                cli_decomp, srv_decomp, tuple(xw), nst if resumed else 0)


def count_segments(flow: Flow, mtu: int, hdr: int = IP_TCP_HDR) -> int:
    mss = mtu - hdr
    return sum(-(-s[2] // mss) for s in flow.steps if s[0] == "x")


# =============================================================================
# 6. NETWORK / TCP MODEL
# =============================================================================


@dataclass(frozen=True)
class Net:
    bw_mbps: float
    rtt_ms: float
    mtu: int
    penalty_ms: float = 0.0
    thr: int = 4            # a flight with MORE segments than this pays `penalty_ms`
    init_cwnd: int = 10     # RFC 6928
    warm_cwnd: int = 10     # cwnd of a reused connection (idle restart, RFC 5681)
    hdr: int = IP_TCP_HDR
    quic: bool = False      # QUIC/HTTP-3: no TCP handshake, 3x anti-amplification limit (RFC 9000)
    # Stack behaviour, validated against real OpenSSL 3.5 transactions over a Linux link (Measurements/testbed,
    # MAE 1.1 ms on 94 configurations). The v4 closed form (ideal segmentation, cwnd += every flight) is STACKS["v4"].
    segmentation: str = "openssl"   # "openssl": segments of OpenSSL's write() pattern; "ideal": ceil(bytes / MSS) per transfer
    nst_early: bool = False         # a resumed server writes the ticket as soon as the client's Finished arrives, not with the response: it is still in flight when the response leaves only if the request flight did not need an extra round trip (Paper 2, WP5)
    srv_cwnd_acked: int = 0         # with nst_early: window (segments) the server has for the response once the ticket has been acknowledged; 0 = unchanged (stage E probes it)
    cwnd_slack: int = 0             # segments added to the test below (0: as validated for Paper 1; 2: fits the resumed flows, STACKS['linux-openssl-2'])
    cwnd_validation: bool = True    # Linux tcp_is_cwnd_limited (RFC 7661): slow start grows cwnd only while cwnd < 2 x packets in flight


QUIC_DATAGRAM = 1250    # UDP payload of a QUIC datagram (common default before path-MTU discovery)
QUIC_OVH = 40           # QUIC header + AEAD tag per datagram
QUIC_HDR = 48 + QUIC_OVH   # IPv6 + UDP + QUIC overhead per datagram
QUIC_CLIENT_INITIAL = 1200  # client Initial datagrams are padded to at least 1200 bytes


STACKS = {
    "linux-openssl": dict(cwnd_validation=True, segmentation="openssl"),     # validated on the testbed (default)
    "linux-openssl-2": dict(cwnd_validation=True, segmentation="openssl", nst_early=True),   # Paper 2: the ticket is its own, earlier write (cwnd_slack stays 0: refuted by WP5)
    "v4": dict(cwnd_validation=False, segmentation="ideal"),                 # closed form of v2-v4, kept for sensitivity
}


@lru_cache(maxsize=None)
def grow_cwnd(cw: int, n: int, slack: int = 0) -> int:
    """cwnd after a flight of n segments in slow start with Linux congestion-window validation.

    Replays the ACK clock of one flight (one ACK per segment): every ACK adds one segment to cwnd and releases
    queued data, but only while cwnd < 2 x (maximum number of segments in flight so far), the test of Linux
    tcp_is_cwnd_limited (RFC 7661). A flight smaller than half the window therefore does not grow it, and a
    window-limited flight grows it by slightly less than n (e.g. 10 -> 40 after 31 segments).
    `slack` loosens the test to cwnd < 2 x peak + slack (Net.cwnd_slack).
    """
    sent = inflight = peak = min(n, cw)
    c, acked = cw, 0
    while acked < n:
        acked += 1
        inflight -= 1
        if c < 2 * peak + slack:
            c += 1
        k = min(c - inflight, n - sent)
        if k > 0:
            sent += k
            inflight += k
            peak = max(peak, inflight)
    return c


@lru_cache(maxsize=1_000_000)
def _tcp_xfer(nbytes: int, mss: int, hdr: int, bw: float, rtt: float, cw0: int,
              gate_k: int = 1 << 30, gate_after_rtt: bool = False, sizes: tuple = ()):
    """ACK-clocked slow start, one ACK per segment, +2 segments released per ACK.

    Returns (elapsed_ms until the last byte is received, serialization_ms,
    n_segments, wire_bytes). The link is a FIFO of capacity `bw`; ACKs are
    assumed lossless and zero-size. No loss, no receive-window limit.
    """
    n = len(sizes) if sizes else -(-nbytes // mss)
    rate = bw * 1e3                                   # bits per ms
    ser_full = (mss + hdr) * 8 / rate
    ser_last = (nbytes - (n - 1) * mss + hdr) * 8 / rate
    acks = []
    link = 0.0
    ser_tot = 0.0
    for k in range(n):
        ser = (sizes[k] + hdr) * 8 / rate if sizes else (ser_last if k == n - 1 else ser_full)
        ready = 0.0 if k < cw0 else acks[(k - cw0) >> 1]
        if k >= gate_k and gate_after_rtt:      # QUIC: wait until the client's address validation
            ready = max(ready, acks[0] - 0.0 if acks else rtt)
        start = ready if ready > link else link
        link = start + ser
        acks.append(link + rtt)
        ser_tot += ser
    return link + rtt / 2, ser_tot, n, (sum(sizes) if sizes else nbytes) + n * hdr


def run_flow(flow: Flow, net: Net, cpu_scale: float = 1.0) -> dict:
    if net.quic:
        mss, hdr = min(net.mtu - 48, QUIC_DATAGRAM) - QUIC_OVH, QUIC_HDR
    else:
        mss, hdr = net.mtu - net.hdr, net.hdr
    if mss <= 0:
        raise ValueError("MTU smaller than headers")
    cw = [net.init_cwnd if flow.mode in ("cold", "resumed") else net.warm_cwnd] * 2
    half = net.rtt_ms / 2
    cpu = ser = prop = ssw = 0.0
    segs = wire = maxseg = pf = 0
    ch_bytes, first_server = None, True
    xi = -1
    n_x = sum(1 for t in flow.steps if t[0] == "x")
    client_el = 0.0
    for st in flow.steps:
        k = st[0]
        if k == "cpu":
            cpu += st[1]
        elif k == "hs":
            if not net.quic:                    # QUIC merges the transport and TLS handshakes
                prop += net.rtt_ms
        else:
            xi += 1
            side = st[1]
            gate = (1 << 30, False)
            if net.quic and flow.mode in ("cold", "resumed"):
                if side == 0 and ch_bytes is None:
                    ch_bytes = st[2]
                elif side == 1 and first_server:  # anti-amplification: 3x the client's Initial bytes
                    first_server = False
                    rx = QUIC_CLIENT_INITIAL * max(1, -(-ch_bytes // (QUIC_CLIENT_INITIAL - QUIC_OVH)))
                    gate = (max(1, (3 * rx) // (mss + QUIC_OVH)), True)
            sizes = ()
            nbytes = st[2]
            wr = flow.writes[xi] if flow.writes else ()
            if net.nst_early and flow.nst and side == 1 and xi == n_x - 1 and not net.quic:
                # the ticket left when the client's Finished arrived (the first small segment of the client flight); the
                # response leaves when the whole request has arrived. If the request flight needed another round trip,
                # the ticket has been acknowledged by then and no longer occupies the window.
                rec = wr if len(wr) > 1 else ()          # the response as one write per TLS record (Model.app_records), the ticket folded into the last
                body = tuple(rec[:-1]) + (rec[-1] - flow.nst,) if rec else ()
                if client_el - net.rtt_ms / 2 >= net.rtt_ms:
                    nbytes = st[2] - flow.nst
                    wr = body if rec else (nbytes,)
                    if net.srv_cwnd_acked:
                        cw[side] = max(cw[side], net.srv_cwnd_acked)
                else:
                    wr = ((flow.nst,) + body) if rec else (flow.nst, st[2] - flow.nst)
            if net.segmentation == "openssl" and wr and not net.quic:
                sizes = tuple(segment_sizes(wr, mss, cw[side]))
            el, s, n, w = _tcp_xfer(nbytes, mss, hdr, net.bw_mbps, net.rtt_ms, cw[side], *gate, sizes)
            if side == 0:
                client_el = el
            cw[side] = grow_cwnd(cw[side], n, net.cwnd_slack) if net.cwnd_validation else cw[side] + n
            ser += s
            prop += half
            ssw += max(0.0, el - s - half)
            segs += n
            wire += w
            if n > maxseg:
                maxseg = n
            if n > net.thr:
                pf += 1
    cpu *= cpu_scale
    pen = pf * net.penalty_ms
    return dict(total=cpu + ser + prop + ssw + pen, cpu=cpu, ser=ser, prop=prop,
                ssw=ssw, pen=pen, segs=segs, wire=wire, max_flight=maxseg, pen_flights=pf)


# =============================================================================
# 7. SWEEPS
# =============================================================================

SIZE_COLS = ["suite", "kex", "sig", "family", "protocol", "depth", "cc", "payload_fixed",
             "obj_alg", "tls_cert", "tls_cv", "tls_kex", "tls_other", "total_l7",
             "segs_1280", "segs_1500", "segs_9000", "cert_chain_bytes"]

RES_COLS = ["suite", "kex", "sig", "family", "protocol", "mode", "depth", "bw_mbps", "rtt_ms",
            "mtu", "penalty_ms", "thr", "total_ms", "cpu_ms", "ser_ms", "prop_ms", "ssw_ms",
            "pen_ms", "segs", "wire_bytes", "max_flight", "pen_flights", "l7_bytes",
            "tls_cert_bytes", "obj_alg_bytes", "cc_total_ms", "cc_saved_ms",
            "cc_cert_bytes", "decomp_kb_cli", "decomp_kb_srv", "break_even_ms_per_kb"] + \
           [f"cc_net_{k}" for k in DECOMP_PROFILES]


def _r(x, nd=4):
    return round(x, nd)


def size_rows(m: Model):
    for sn, pn, d, cc in itertools.product(SUITES, PROTOCOLS, (1, 2, 3, 4), (False, True)):
        f = build_flow(sn, pn, d, "cold", cc, m)
        su = SUITES[sn]
        sg = SIGS[su.sig]
        s = f.sizes
        yield [sn, su.kex, su.sig, sg.family, pn, d, int(cc), s["payload_fixed"], s["obj_alg"],
               s["tls_cert"], s["tls_cv"], s["tls_kex"], s["tls_other"], s["total_l7"],
               count_segments(f, 1280), count_segments(f, 1500), count_segments(f, 9000),
               sum(cert_chain(sg, d, m))]


def sweep_task(args):
    """All rows for one (suite, protocol) pair."""
    sn, pn, g, m = args
    su = SUITES[sn]
    sg = SIGS[su.sig]
    rows = []
    for mode in ("cold", "warm"):
        depths = g["depths"] if mode == "cold" else (0,)
        for d in depths:
            f = build_flow(sn, pn, d, mode, False, m)
            fc = build_flow(sn, pn, d, mode, True, m) if mode == "cold" else None
            for mtu, bw, rtt, thr in itertools.product(g["mtus"], g["bws"], g["rtts"], g["thrs"]):
                net = Net(bw, rtt, mtu, 0.0, thr, g["init_cwnd"], g["warm_cwnd"], **STACKS[g["stack"]])
                r = run_flow(f, net)
                rc = run_flow(fc, net) if fc else None
                for pen in g["pens"]:
                    tot = r["total"] + r["pen_flights"] * pen
                    row = [sn, su.kex, su.sig, sg.family, pn, mode, d, bw, rtt, mtu, pen, thr,
                           _r(tot), _r(r["cpu"]), _r(r["ser"]), _r(r["prop"]), _r(r["ssw"]),
                           _r(r["pen_flights"] * pen), r["segs"], r["wire"], r["max_flight"],
                           r["pen_flights"], f.sizes["total_l7"], f.sizes["tls_cert"],
                           f.sizes["obj_alg"]]
                    if rc is None:
                        row += [""] * (len(RES_COLS) - len(row))
                    else:
                        tot_c = rc["total"] + rc["pen_flights"] * pen
                        saved = tot - tot_c
                        cost0 = (fc.decomp_kb_srv * m.server_decomp_ms_per_kb +
                                 (fc.comp_kb_cli + fc.comp_kb_srv) * m.compress_ms_per_kb)
                        be = (saved - cost0) / fc.decomp_kb_cli if fc.decomp_kb_cli else ""
                        row += [_r(tot_c), _r(saved), fc.sizes["tls_cert"],
                                _r(fc.decomp_kb_cli), _r(fc.decomp_kb_srv),
                                _r(be) if be != "" else ""]
                        row += [_r(saved - cost0 - fc.decomp_kb_cli * rate)
                                for rate in DECOMP_PROFILES.values()]
                    rows.append(row)
    return rows


def parse_list(s, typ):
    return tuple(typ(x) for x in s.split(",") if x != "")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="results")
    ap.add_argument("--depths", default="1,2,3,4")
    ap.add_argument("--bandwidths", default="10,100,200,400,800,1600")
    ap.add_argument("--rtts", default="5,12,30,50,100")
    ap.add_argument("--mtus", default="1280,1500,9000")
    ap.add_argument("--penalties", default="0,3,6,12,24")
    ap.add_argument("--thresholds", default="4")
    ap.add_argument("--suites", default="all")
    ap.add_argument("--protocols", default="all")
    ap.add_argument("--leaf-meta", type=int, default=Model.leaf_meta)
    ap.add_argument("--ca-meta", type=int, default=Model.ca_meta)
    ap.add_argument("--r-first", type=float, default=Model.r_first)
    ap.add_argument("--r-next", type=float, default=Model.r_next)
    ap.add_argument("--compress-ms-per-kb", type=float, default=Model.compress_ms_per_kb,
                    help="0 = certificates pre-compressed (default); ~0.03 = dynamic zlib")
    ap.add_argument("--init-cwnd", type=int, default=10, help="initial cwnd of a new connection (segments)")
    ap.add_argument("--warm-cwnd", type=int, default=10,
                    help="cwnd of a reused connection; 10 = idle restart (RFC 5681), larger = busy link")
    ap.add_argument("--stack", choices=list(STACKS), default="linux-openssl",
                    help="TCP/TLS stack behaviour: linux-openssl (validated on the testbed, default) or the v4 closed form")
    ap.add_argument("--no-xmldsig-cert", action="store_true",
                    help="XMLDSig KeyInfo references the certificate instead of embedding it")
    ap.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1))
    ap.add_argument("--quick", action="store_true", help="tiny grid for smoke tests")
    a = ap.parse_args(argv)

    m = Model(leaf_meta=a.leaf_meta, ca_meta=a.ca_meta, r_first=a.r_first, r_next=a.r_next,
              compress_ms_per_kb=a.compress_ms_per_kb, xmldsig_embed_cert=not a.no_xmldsig_cert)
    g = dict(depths=parse_list(a.depths, int), bws=parse_list(a.bandwidths, float),
             rtts=parse_list(a.rtts, float), mtus=parse_list(a.mtus, int),
             pens=parse_list(a.penalties, float), thrs=parse_list(a.thresholds, int),
             init_cwnd=a.init_cwnd, warm_cwnd=a.warm_cwnd, stack=a.stack)
    if a.quick:
        g.update(bws=(10.0, 100.0, 1600.0), rtts=(12.0, 50.0), mtus=(1280, 1500, 9000), pens=(0.0, 12.0))
    suites = list(SUITES) if a.suites == "all" else a.suites.split(",")
    protos = list(PROTOCOLS) if a.protocols == "all" else a.protocols.split(",")

    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "sizes.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(SIZE_COLS)
        w.writerows(size_rows(m))

    tasks = [(s, p, g, m) for s in suites for p in protos]
    t0 = time.time()
    n = 0
    with open(os.path.join(a.out, "results.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(RES_COLS)
        if a.jobs > 1:
            with ProcessPoolExecutor(a.jobs) as ex:
                for rows in ex.map(sweep_task, tasks):
                    w.writerows(rows)
                    n += len(rows)
        else:
            for t in tasks:
                rows = sweep_task(t)
                w.writerows(rows)
                n += len(rows)
    meta = dict(model=asdict(m), grid={k: (list(v) if isinstance(v, tuple) else v) for k, v in g.items()},
                suites={k: asdict(v) for k, v in SUITES.items()},
                sigs={k: asdict(v) for k, v in SIGS.items()},
                kex={k: asdict(v) for k, v in KEXS.items()},
                protocols={k: asdict(v) for k, v in PROTOCOLS.items()},
                decomp_profiles=DECOMP_PROFILES, ip_tcp_hdr=IP_TCP_HDR,
                rows=n, seconds=round(time.time() - t0, 1))
    with open(os.path.join(a.out, "assumptions.json"), "w") as fh:
        json.dump(meta, fh, indent=1)
    print(f"[pqc_sim] {n} rows -> {a.out}/results.csv in {time.time() - t0:.1f}s "
          f"({len(tasks)} suite x protocol tasks)")


if __name__ == "__main__":
    main()
