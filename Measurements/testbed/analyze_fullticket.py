#!/usr/bin/env python3
"""analyze_fullticket.py - can a ticket modelled as a separate write explain why a FULL handshake that also issues a session
ticket is slower than the ticketless one (Paper 1, supplementary Appendix E; referee comment on session tickets)?

    python3 analyze_fullticket.py [--out results/fullticket_model.txt]

Data: results/resume_summary.csv. `prime_excess` is the excess latency of the full transaction that obtained the ticket (it
issues one); `full_excess` the ticketless reference of the same configuration (full_source == "ref": 40 configurations with
302/222-byte transactions). The model option Model(full_ticket=True) (pqc_sim.py) makes the server of a cold flow send a
ticket of the size used for resumed flows: joined with the first response (nst_early off) or as its own write when the
client's Finished arrives (nst_early on). Nothing is fitted. A mode that explains the effect would predict +0.5 RTT in the six
slow configurations; the script reports what each mode predicts.
"""
import argparse, csv, dataclasses, os, statistics as st, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "..", "Simulation"))
import analyze_testbed as A  # noqa: E402
import pqc_sim as S  # noqa: E402

MODES = {"no ticket": (False, False), "ticket joined with the response": (True, False), "ticket written on Finished": (True, True)}


def pred(c, ticket, early):
    m = dataclasses.replace(S.Model(), full_ticket=ticket)
    flow = S.build_flow(c["suite"], A.probe_protocol(c["mtls"], c["req"], c["resp"], c["depth"]), int(c["depth"]), "cold", False, m)
    net = S.Net(float(c["rate_mbps"]), float(c["rtt_ms"]), int(c["mtu"]), penalty_ms=0.0, thr=4, init_cwnd=int(c["icw"]),
                cwnd_validation=True, segmentation="openssl", cwnd_slack=0, nst_early=early)
    r = S.run_flow(flow, net)
    return r["total"] - r["cpu"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "results", "fullticket_model.txt"))
    a = ap.parse_args()
    rows = list(csv.DictReader(open(os.path.join(HERE, "results", "resume_summary.csv"))))
    ref = [c for c in rows if c["full_source"] == "ref" and c["req"] == "302"]
    slow = [c for c in ref if float(c["prime_excess"]) - float(c["full_excess"]) > 3]
    L = [f"{len(ref)} configurations with a ticketless reference; {len(slow)} where the transaction with a ticket is slower by more than 3 ms"]
    for name, (t, e) in MODES.items():
        err = [pred(c, t, e) - float(c["prime_excess"]) for c in ref]
        L.append(f"{name:34s} MAE over the {len(ref)}: {st.mean(abs(x) for x in err):.2f} ms; configurations off by more than 5 ms: {sum(abs(x) > 5 for x in err)}")
    L.append("the slow configurations (measured: ticket minus no ticket, and the model's change with a ticket):")
    for c in slow:
        d = float(c["prime_excess"]) - float(c["full_excess"])
        ch = {n: pred(c, t, e) - pred(c, False, False) for n, (t, e) in MODES.items() if t}
        L.append(f"  {c['suite'].split('|')[0]:12s} depth {c['depth']} MTU {c['mtu']} RTT {c['rtt_ms']:>3s}: measured +{d:5.1f} ms; model "
                 + "; ".join(f"{n}: {v:+.1f}" for n, v in ch.items()))
    open(a.out, "w").write("\n".join(L) + "\n"); print("\n".join(L))


if __name__ == "__main__":
    main()
