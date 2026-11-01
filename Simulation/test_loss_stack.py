"""loss_sim.run_flow_lossy with loss 0 must reproduce pqc_sim.run_flow exactly, under the validated stack and the idealised one."""
import itertools
import random

import loss_sim as L
import pqc_sim as S


def test_zero_loss_matches_closed_form():
    rng = random.Random(3)
    suites = rng.sample(list(S.SUITES), 5)
    protos = list(S.PROTOCOLS)
    worst = 0.0
    n = 0
    for _ in range(300):
        su, pr = rng.choice(suites), rng.choice(protos)
        d = rng.choice([1, 2, 3, 4])
        mode = rng.choice(["cold", "resumed"])
        f = S.build_flow(su, pr, d, mode, False)
        bw, rtt, mtu = rng.choice([10.0, 100.0, 1000.0]), rng.choice([5.0, 30.0, 100.0]), rng.choice([1280, 1500, 9000])
        icw = rng.choice([10, 32])
        for stk in ("linux-openssl", "v4"):
            net = S.Net(bw, rtt, mtu, 0.0, 4, init_cwnd=icw, **S.STACKS[stk])
            a = S.run_flow(f, net)["total"]
            b = L.run_flow_lossy(f, net, 0.0, "t")["total"]
            worst = max(worst, abs(a - b))
            n += 1
    assert worst < 1e-6, worst
    print(f"{n} flows, max |difference| {worst:.2e} ms")


if __name__ == "__main__":
    test_zero_loss_matches_closed_form()
