import unittest

import pqc_sim as S
import loss_sim as L

# loss_sim.py still implements the v4 stack (ideal segmentation, cwnd += every flight): compare it with the v4 closed form
V4 = S.STACKS["v4"]
NET = S.Net(100.0, 30.0, 1500, 6.0, 4, **V4)
ML = "ML-DSA-65|ML-KEM-768"


def xfers(f):
    return [s[2] for s in f.steps if s[0] == "x"]


class LossFree(unittest.TestCase):
    def test_zero_loss_equals_closed_form(self):
        for su in (S.BASELINE, ML, "SLH-DSA-128f|ML-KEM-768"):
            for pr, d, mode in (("FAPI2", 2, "cold"), ("SWIFT_MX", 4, "cold"), ("ISO_20022", 0, "warm")):
                for net in (NET, S.Net(10.0, 100.0, 1280, 24.0, 4, **V4)):
                    f = S.build_flow(su, pr, d, mode, False)
                    self.assertAlmostEqual(L.run_flow_lossy(f, net, 0.0, "x")["total"], S.run_flow(f, net)["total"], places=6)

    def test_loss_never_helps(self):
        f = S.build_flow(ML, "SWIFT_MX", 3, "cold", False)
        base = S.run_flow(f, NET)["total"]
        for t in range(50):
            self.assertGreaterEqual(L.run_flow_lossy(f, NET, 0.02, t)["total"], base - 1e-9)


class Resumption(unittest.TestCase):
    def test_no_certificates_and_faster(self):
        for su in (S.BASELINE, ML):
            c = S.build_flow(su, "FAPI2", 3, "cold", False)
            r = S.build_flow(su, "FAPI2", 3, "resumed", False)
            self.assertEqual(r.sizes["tls_cert"], 0)
            self.assertLess(S.run_flow(r, NET)["total"], S.run_flow(c, NET)["total"])

    def test_mtls_ticket_carries_client_leaf(self):
        a = xfers(S.build_flow(ML, "FAPI2", 2, "resumed", False))[0]      # mutual TLS
        b = xfers(S.build_flow(ML, "OIDC", 2, "resumed", False))[0]       # server-only
        self.assertGreater(a - b, S.cert_len(S.SIGS["ML-DSA-65"], True, S.Model()))


class Quic(unittest.TestCase):
    def test_saves_one_rtt_when_not_amplification_limited(self):
        f = S.build_flow(S.BASELINE, "FAPI2", 1, "cold", False)
        q = S.Net(100.0, 30.0, 1500, 0.0, 99, quic=True)
        t = S.Net(100.0, 30.0, 1500, 0.0, 99)
        # QUIC datagrams are smaller, so allow a few ms of extra serialisation
        self.assertAlmostEqual(S.run_flow(f, q)["total"], S.run_flow(f, t)["total"] - 30.0, delta=1.0)

    def test_amplification_limit_binds_only_with_large_initial_window(self):
        f = S.build_flow(ML, "FAPI2", 2, "cold", False)

        def gate_cost(icw):
            net = S.Net(100.0, 30.0, 1500, 0.0, 99, init_cwnd=icw, quic=True)
            with_gate = S.run_flow(f, net)["total"]
            old, S.QUIC_CLIENT_INITIAL = S.QUIC_CLIENT_INITIAL, 10 ** 9      # disable the gate
            try:
                return with_gate - S.run_flow(f, net)["total"]
            finally:
                S.QUIC_CLIENT_INITIAL = old

        self.assertLess(gate_cost(10), 2.0)          # window already limits the first flight
        self.assertGreater(gate_cost(32), 25.0)      # gate then costs one round trip


class Certificates(unittest.TestCase):
    def test_cached_info_and_mtc_shrink_server_flight(self):
        base = xfers(S.build_flow(ML, "OIDC", 3, "cold", False))[1]
        ci = xfers(S.build_flow(ML, "OIDC", 3, "cold", False, S.Model(cached_info=True)))[1]
        mtc = xfers(S.build_flow(ML, "OIDC", 3, "cold", False, S.Model(mtc=True)))[1]
        self.assertLess(ci, mtc)
        self.assertLess(mtc, base)

    def test_composite_sizes(self):
        c = S.SIGS["ML-DSA-65+ECDSA-P256"]
        self.assertEqual(c.sig, S.SIGS["ML-DSA-65"].sig + S.SIGS["ECDSA-P256"].sig)
        self.assertEqual(c.pk, S.SIGS["ML-DSA-65"].pk + S.SIGS["ECDSA-P256"].pk)


if __name__ == "__main__":
    unittest.main()
