import unittest

import pqc_sim as S

M = S.Model()


class TcpModel(unittest.TestCase):
    def test_single_segment(self):
        el, ser, n, wire = S._tcp_xfer(1000, 1220, 60, 100.0, 30.0, 10)
        self.assertEqual(n, 1)
        self.assertAlmostEqual(ser, (1000 + 60) * 8 / 1e5)
        self.assertAlmostEqual(el, ser + 15.0)

    def test_initial_window_has_no_wait(self):
        mss = 1220
        el, ser, n, _ = S._tcp_xfer(10 * mss, mss, 60, 100.0, 30.0, 10)
        self.assertEqual(n, 10)
        self.assertAlmostEqual(el, ser + 15.0)

    def test_eleventh_segment_waits_for_first_ack(self):
        mss = 1220
        el, ser, n, _ = S._tcp_xfer(11 * mss, mss, 60, 1600.0, 30.0, 10)
        one = (mss + 60) * 8 / 1.6e6
        self.assertEqual(n, 11)
        # segment 11 is released by ACK 0 at one + RTT
        self.assertAlmostEqual(el, one + 30.0 + one + 15.0)

    def test_bandwidth_limited_has_no_idle(self):
        mss = 1220
        el, ser, n, _ = S._tcp_xfer(40 * mss, mss, 60, 1.0, 5.0, 10)
        self.assertAlmostEqual(el, ser + 2.5)


class Sizes(unittest.TestCase):
    def test_der_cert_sizes(self):
        ec = S.SIGS["ECDSA-P256"]
        self.assertEqual(S.cert_len(ec, True, M), M.leaf_meta + 91 + 72 + 4)
        ml = S.SIGS["ML-DSA-65"]
        self.assertEqual(S.cert_len(ml, False, M), M.ca_meta + 1952 + 22 + 3309 + 4)

    def test_chain_depth(self):
        sg = S.SIGS["ML-DSA-65"]
        self.assertEqual(len(S.cert_chain(sg, 3, M)), 3)

    def test_breakdown_equals_transferred_bytes(self):
        for sn in S.SUITES:
            for pn in S.PROTOCOLS:
                for mode, d in (("cold", 1), ("cold", 4), ("warm", 0)):
                    for cc in (False, True) if mode == "cold" else (False,):
                        f = S.build_flow(sn, pn, d, mode, cc, M)
                        xfer = sum(s[2] for s in f.steps if s[0] == "x")
                        self.assertEqual(xfer, f.sizes["total_l7"], (sn, pn, d, mode, cc))

    def test_pq_is_larger_than_classical(self):
        base = S.build_flow(S.BASELINE, "SWIFT_MX", 3, "cold", False, M).sizes["total_l7"]
        for sn in ("ML-DSA-44|ML-KEM-768", "ML-DSA-65|ML-KEM-768", "SLH-DSA-128f|ML-KEM-768"):
            self.assertGreater(S.build_flow(sn, "SWIFT_MX", 3, "cold", False, M).sizes["total_l7"], base)

    def test_compression_never_expands(self):
        for sn in S.SUITES:
            for d in (1, 2, 3, 4):
                a = S.build_flow(sn, "ISO_20022", d, "cold", False, M).sizes["tls_cert"]
                b = S.build_flow(sn, "ISO_20022", d, "cold", True, M).sizes["tls_cert"]
                self.assertLessEqual(b, a)


class Flows(unittest.TestCase):
    NET = S.Net(100.0, 30.0, 1500, 6.0, 4)

    def test_components_sum_to_total(self):
        for sn in S.SUITES:
            r = S.run_flow(S.build_flow(sn, "FAPI2", 3, "cold", False, M), self.NET)
            self.assertAlmostEqual(r["total"], r["cpu"] + r["ser"] + r["prop"] + r["ssw"] + r["pen"])

    def test_latency_monotone_in_depth(self):
        for sn in S.SUITES:
            prev = 0
            for d in (1, 2, 3, 4):
                t = S.run_flow(S.build_flow(sn, "SWIFT_MX", d, "cold", False, M), self.NET)["total"]
                self.assertGreaterEqual(t, prev)
                prev = t

    def test_warm_faster_than_cold(self):
        for sn in S.SUITES:
            c = S.run_flow(S.build_flow(sn, "ISO_20022", 2, "cold", False, M), self.NET)["total"]
            w = S.run_flow(S.build_flow(sn, "ISO_20022", 0, "warm", False, M), self.NET)["total"]
            self.assertLess(w, c)

    def test_penalty_is_linear_in_flights(self):
        f = S.build_flow("ML-DSA-65|ML-KEM-768", "SWIFT_MX", 3, "cold", False, M)
        a = S.run_flow(f, S.Net(100, 30, 1500, 0.0, 4))
        b = S.run_flow(f, S.Net(100, 30, 1500, 12.0, 4))
        self.assertAlmostEqual(b["total"] - a["total"], 12.0 * a["pen_flights"])

    def test_bigger_mtu_never_slower(self):
        for sn in S.SUITES:
            f = S.build_flow(sn, "SWIFT_MX", 3, "cold", False, M)
            t = [S.run_flow(f, S.Net(100, 30, mtu, 6.0, 4))["total"] for mtu in (1280, 1500, 9000)]
            self.assertGreaterEqual(t[0], t[1])
            self.assertGreaterEqual(t[1], t[2])

    def test_cold_handshake_lower_bound(self):
        # TCP + TLS 1.3 + request/response = at least 3 RTT.
        r = S.run_flow(S.build_flow(S.BASELINE, "ISO_8583", 1, "cold", False, M), self.NET)
        self.assertGreaterEqual(r["total"], 3 * 30.0)


try:
    import simpy  # noqa: F401
    import crosscheck_simpy as X
except ImportError:
    X = None


@unittest.skipIf(X is None, "simpy not installed")
class SimPyCrossCheck(unittest.TestCase):
    def test_des_matches_closed_form(self):
        import itertools
        import random
        pool = list(X.all_cases((10.0, 400.0), (5.0, 100.0), (1280, 1500, 9000), (0.0, 12.0), (4,)))
        for stack in S.STACKS:                      # the validated stack and the v4 closed form
            for case in random.Random(7).sample(pool, 300):
                r = X.compare(case, 1, stack)
                self.assertLess(abs(r["d_total"]), X.TOL_MS, (stack, case))
                self.assertEqual((r["d_segs"], r["d_wire"], r["d_pen"]), (0, 0, 0), (stack, case))


class TestAsymmetricDepth(unittest.TestCase):
    """build_flow(depth_client=) lifts the symmetric-depth assumption without changing the symmetric case."""

    def test_default_is_symmetric(self):
        a = S.build_flow("ML-DSA-65|ML-KEM-768", "SWIFT_MX", 3, "cold", False)
        b = S.build_flow("ML-DSA-65|ML-KEM-768", "SWIFT_MX", 3, "cold", False, S.Model(), 3)
        self.assertEqual(a, b)

    def test_client_chain_changes_only_client_side(self):
        s = "ML-DSA-65|ML-KEM-768"
        sym = S.build_flow(s, "SWIFT_MX", 2, "cold", False)
        asy = S.build_flow(s, "SWIFT_MX", 2, "cold", False, S.Model(), 4)
        self.assertGreater(asy.sizes["total_l7"], sym.sizes["total_l7"])
        extra = 2 * (S.cert_len(S.SIGS["ML-DSA-65"], False, S.Model()) + 5)   # + 3-byte length and 2-byte extensions per entry
        self.assertEqual(asy.sizes["tls_cert"] - sym.sizes["tls_cert"], extra)

    def test_no_effect_without_client_chain(self):
        a = S.build_flow("ML-DSA-65|ML-KEM-768", "OAUTH2_RFC6749", 2, "cold", False)
        b = S.build_flow("ML-DSA-65|ML-KEM-768", "OAUTH2_RFC6749", 2, "cold", False, S.Model(), 4)
        self.assertEqual(a.sizes["tls_cert"], b.sizes["tls_cert"])


if __name__ == "__main__":
    unittest.main()
