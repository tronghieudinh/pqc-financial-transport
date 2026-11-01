#!/usr/bin/env python3
"""
wp6_predict.py - pre-registration of the WP6 tests (paper 2, further scenarios). Run once, COMMIT AND PUSH the files BEFORE measuring.

  results/wp6_pred_gen.csv       B3  ticket rule and server window across RTT, rate and MTU (models: joined ticket; early ticket with window 10;
                                     early ticket with the windows measured in stage E: ECDSA 10, ML-DSA-44 12, ML-DSA-65 15)
  results/wp6_pred_servonly.csv  B10 the same without client authentication (the ticket does not embed a client certificate)
  results/wp6_pred_clientalg.csv B9  mixed chains: which of the ticket (client certificate) or the server algorithm sets the server window
  results/wp6_pred_loss.csv      B2  lossy model (fast retransmit, TLP, RTO) for full and resumed transactions: mean and percentiles of the transport time

Cells are defined by the number k of response segments; a response of k segments is k*MSS-700 bytes (MSS = MTU - 60, IPv6, no timestamps).
"""
import csv, hashlib, os, statistics as st, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "Simulation"))
import analyze_testbed as A  # noqa: E402
import loss_sim as L  # noqa: E402

S = A.S
SUITES = ["ECDSA-P256|X25519", "ML-DSA-44|ML-KEM-768", "ML-DSA-65|ML-KEM-768"]
WMEAS = {"ECDSA-P256|X25519": 0, "ML-DSA-44|ML-KEM-768": 12, "ML-DSA-65|ML-KEM-768": 15}          # srv_cwnd_acked; 0 = 10
NETS = {"rtt5": (5.0, 100.0, 1500), "rtt30": (30.0, 100.0, 1500), "rate10": (100.0, 10.0, 1500), "mtu1280": (100.0, 100.0, 1280), "mtu9000": (100.0, 100.0, 9000)}
KS = list(range(9, 17))
REQS = [302, 19460]
RES = os.path.join(HERE, "results")


def rbytes(k, mtu):
    return k * (mtu - 60) - 700


def model_total(suite, mtls, req, resp, rtt, rate, mtu, **kw):
    flow = S.build_flow(suite, A.probe_protocol(str(mtls), str(req), str(resp), "2"), 2, "resumed", False)
    net = S.Net(rate, rtt, mtu, penalty_ms=0.0, thr=4, init_cwnd=10, cwnd_validation=True, segmentation="openssl", **kw)
    m = S.run_flow(flow, net)
    return round(m["total"] - m["cpu"], 2)


def gen(mtls, name):
    rows = []
    for net_id, (rtt, rate, mtu) in NETS.items():
        if mtls == 0 and net_id != "rtt30":
            continue                                      # server-only authentication: one network is enough (the ticket has one segment)
        for su in SUITES:
            for rq in REQS:
                for k in KS:
                    rs = rbytes(k, mtu)
                    r = dict(net=net_id, rtt_ms=rtt, rate_mbps=rate, mtu=mtu, suite=su, mtls=mtls, req=rq, resp=rs, resp_segments=k)
                    r["model_joined_ms"] = model_total(su, mtls, rq, rs, rtt, rate, mtu, nst_early=False)
                    r["model_early_w10_ms"] = model_total(su, mtls, rq, rs, rtt, rate, mtu, nst_early=True)
                    r["model_early_wmeas_ms"] = model_total(su, mtls, rq, rs, rtt, rate, mtu, nst_early=True, srv_cwnd_acked=WMEAS[su] if mtls else 0)
                    v = [r["model_joined_ms"], r["model_early_w10_ms"], r["model_early_wmeas_ms"]]
                    r["differ"] = int(max(v) - min(v) > 0.5 * rtt)
                    rows.append(r)
    return rows


def write(path, rows):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return path


def clientalg():
    """Which sets the server's window after an acknowledged ticket: the ticket (client certificate) or the server's algorithm?
    W (the largest response, in segments, that costs no extra round trip) was 10, 12 and 15 for tickets of 1, 4 and 5 segments (stage E)."""
    W = {"ECDSA-P256": 10, "ML-DSA-44": 12, "ML-DSA-65": 15}
    rows = []
    for srv, cli in (("ML-DSA-65", "ECDSA-P256"), ("ECDSA-P256", "ML-DSA-65"), ("ML-DSA-44", "ML-DSA-65"), ("ML-DSA-65", "ML-DSA-44")):
        rows.append(dict(server=srv, client=cli, req=19460, ks="9..18", h_ticket_fit_segments=W[cli], h_server_fit_segments=W[srv],
                         differ=int(W[cli] != W[srv]),
                         note="the request flight needs an extra round trip for every client certificate (ClientHello of 2, 5 or 6 segments, request of 15), so the ticket is acknowledged"))
    return rows


def lossy(trials=2000):
    rows = []
    for mode, resume in (("full", False), ("resumed", True)):
        for su in ("ECDSA-P256|X25519", "ML-DSA-65|ML-KEM-768"):
            for rtt in (30.0, 100.0):
                for loss in (0.0, 0.5, 1.0, 2.0):
                    flow = S.build_flow(su, A.probe_protocol("1", "302", "222", "3"), 3, "resumed" if resume else "cold", False)
                    cpu = sum(s_[1] for s_ in flow.steps if s_[0] == "cpu")
                    net = S.Net(100.0, rtt, 1500, 0.0, 4, init_cwnd=10)
                    sims = [L.run_flow_lossy(flow, net, loss / 100.0, f"wp6|{mode}|{su}|{rtt}|{loss}|{t}")["total"] - cpu for t in range(trials)]
                    q = lambda p: sorted(sims)[min(len(sims) - 1, int(p * len(sims)))]
                    rows.append(dict(mode=mode, suite=su, depth=3, rtt_ms=rtt, loss_pct=loss, model_mean_ms=round(st.mean(sims), 2), model_p50_ms=round(q(.5), 2),
                                     model_p95_ms=round(q(.95), 2), model_p99_ms=round(q(.99), 2)))
    return rows


def main():
    outs = {"wp6_pred_gen.csv": lambda: gen(1, "gen"), "wp6_pred_servonly.csv": lambda: gen(0, "servonly"),
            "wp6_pred_clientalg.csv": clientalg, "wp6_pred_loss.csv": lossy}
    for fn in outs:
        if os.path.exists(os.path.join(RES, fn)) and "--force" not in sys.argv:
            sys.exit(f"{fn} exists (pre-registered); delete it deliberately to redo")
    sim = os.path.join(HERE, "..", "..", "Simulation", "pqc_sim.py")
    print(f"written {time.strftime('%Y-%m-%d %H:%M:%S')}  pqc_sim.py sha256 {hashlib.sha256(open(sim, 'rb').read()).hexdigest()}")
    for fn, mk in outs.items():
        rows = mk()
        write(os.path.join(RES, fn), rows)
        extra = f", {sum(r['differ'] for r in rows)} cells on which the models differ by a round trip" if "differ" in rows[0] else ""
        print(f"{fn}: {len(rows)} rows{extra}")


if __name__ == "__main__":
    main()
