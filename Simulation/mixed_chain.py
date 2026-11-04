#!/usr/bin/env python3
"""
mixed_chain.py - MODEL ONLY: certificate chains in which the leaf key and the CA keys use different algorithms (Paper 1 models every chain with one algorithm).

    python3 mixed_chain.py [--out mixed_chain.csv]

Scenario: SWIFT MX (mutual TLS), cold, 100 Mbit/s, RTT 30 ms, MTU 1500, initial window 10, pi = 0, chain depth d = certificates sent (leaf + d-1 intermediates, root omitted).
A certificate is DER = metadata + SPKI of ITS OWN key + signature of its ISSUER. Leaf key algorithm L, key algorithm of all CAs (intermediates and root) A:
  cert_0 (leaf) = meta + pk(L) + sig(A);  cert_i (intermediate) = meta + pk(A) + sig(A).   The CertificateVerify signature uses L.
Cases: (L, A) = (ML-DSA-65, ML-DSA-65) all post-quantum; (ML-DSA-65, ECDSA-P256) post-quantum leaf under classical CAs; (ECDSA-P256, ML-DSA-65) classical leaf under post-quantum CAs;
(ECDSA-P256, ECDSA-P256) classical baseline. Only the first is post-quantum secure end to end; the second and third are what a staged migration could look like and are NOT secure against a
quantum adversary on the part that stays classical.
How the numbers are made: build_flow gives bytes and flights with cert_chain replaced by the mixed chain (the only change); the transport part of run_flow (total - cpu) is exact for the model.
The CPU of the chain is corrected by hand: in the flow built for the leaf suite each of the d certificate signatures of an authenticated chain is verified at the cost of L; in the mixed chain it is verified
at the cost of A (client chain and server chain under mutual TLS: 2 d verifications; the CertificateVerify keeps L). Key exchange: ML-KEM-768 (leaf PQ) or X25519MLKEM768 (classical leaf; 32 bytes
more key share), so that the key exchange is post-quantum in all cases.
No measurement backs this scenario. It uses the same bytes-and-flights model as the rest of Paper 1; the direct measurements of Paper 1 cover single-algorithm chains only.
"""
import argparse, csv, os
import pqc_sim as ps

HERE = os.path.dirname(os.path.abspath(__file__))
PROTO = "SWIFT_MX"
LEAF_SUITE = {"ML-DSA-65": "ML-DSA-65|ML-KEM-768", "ECDSA-P256": "ECDSA-P256|X25519MLKEM768"}
CASES = [("ML-DSA-65", "ML-DSA-65"), ("ML-DSA-65", "ECDSA-P256"), ("ECDSA-P256", "ML-DSA-65"), ("ECDSA-P256", "ECDSA-P256")]
_orig_chain = ps.cert_chain

def mixed_chain(leaf_alg, ca_alg):
    L, A = ps.SIGS[leaf_alg], ps.SIGS[ca_alg]
    def chain(sig, depth, m):
        out = [m.leaf_meta + L.pk + L.spki_hdr + A.sig + 4]
        out += [m.ca_meta + A.pk + A.spki_hdr + A.sig + 4 for _ in range(depth - 1)]
        return out
    return chain

def run(leaf_alg, ca_alg, depth, rtt=30.0, mtu=1500, icw=10):
    suite = LEAF_SUITE[leaf_alg]
    ps.cert_chain = mixed_chain(leaf_alg, ca_alg)
    ps.build_flow.cache_clear()          # build_flow is lru_cached: the patched chain must not meet a cached flow
    try:
        flow = ps.build_flow(suite, PROTO, depth, "cold", False, ps.Model(), depth)
    finally:
        ps.cert_chain = _orig_chain
        ps.build_flow.cache_clear()
    r = ps.run_flow(flow, ps.Net(100.0, rtt, mtu, 0.0, 4, icw, icw), 1.0)
    L, A = ps.SIGS[leaf_alg], ps.SIGS[ca_alg]
    chains = 2 if ps.PROTOCOLS[PROTO].mtls else 1
    cpu = r["cpu"] + chains * depth * (A.verify_ms - L.verify_ms)
    transport = r["total"] - r["cpu"]
    return dict(chain_bytes=sum(mixed_chain(leaf_alg, ca_alg)(None, depth, ps.Model())), segs=r["segs"], max_flight=r["max_flight"], transport_ms=transport, cpu_ms=cpu, total_ms=transport + cpu)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default=os.path.join(HERE, "mixed_chain.csv")); a = ap.parse_args()
    rows = [["leaf", "ca", "depth", "chain_bytes_per_peer", "segments", "max_flight_segments", "transport_ms", "cpu_ms", "total_ms"]]
    res = {}
    for L, A in CASES:
        for d in range(1, 5):
            r = run(L, A, d); res[(L, A, d)] = r
            rows.append([L, A, d, r["chain_bytes"], r["segs"], r["max_flight"], round(r["transport_ms"], 2), round(r["cpu_ms"], 2), round(r["total_ms"], 2)])
    csv.writer(open(a.out, "w", newline="")).writerows(rows)
    print("leaf / CA keys           d  chain B  segs  maxfl  transport  cpu    total   increase vs d=1 (ms)")
    for L, A in CASES:
        for d in range(1, 5):
            r = res[(L, A, d)]
            print(f"{L:11s} / {A:11s} {d}  {r['chain_bytes']:7d} {r['segs']:5d} {r['max_flight']:6d} {r['transport_ms']:9.1f} {r['cpu_ms']:6.2f} {r['total_ms']:8.1f}  {r['total_ms'] - res[(L, A, 1)]['total_ms']:7.1f}")
    # check: the all-PQ and all-classical cases must equal the ordinary single-algorithm model (the CPU correction vanishes there)
    for L, A in ((c, c) for c in ("ML-DSA-65", "ECDSA-P256")):
        ps.cert_chain = _orig_chain
        ps.build_flow.cache_clear()
        f = ps.build_flow(LEAF_SUITE[L], PROTO, 4, "cold", False, ps.Model(), 4)
        ref = ps.run_flow(f, ps.Net(100.0, 30.0, 1500, 0.0, 4, 10, 10), 1.0)["total"]
        print(f"check {L}/{A} depth 4: mixed code {res[(L, A, 4)]['total_ms']:.3f} ms, ordinary model {ref:.3f} ms")

if __name__ == "__main__":
    main()
