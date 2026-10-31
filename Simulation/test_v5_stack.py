"""Tests of the stack-level options added in v5 (Linux cwnd validation, OpenSSL write pattern).

Expected values come from the testbed (Measurements/testbed): strace of OpenSSL 3.5 and the kernel counters
TCP_INFO data_segs_out/in of real transactions over a veth link (client/server segments per transaction).
"""
import unittest

import pqc_sim as S

ISO = "ISO_8583"          # CH, server flight, client flight + request, response: same exchange as tls_probe 302/222


def segs_per_side(suite, depth, mtu):
    f = S.build_flow(suite, ISO, depth, "cold", False)
    mss, cw = mtu - 60, [10, 10]
    c = s = 0
    for st, w in zip([x for x in f.steps if x[0] == "x"], f.writes):
        n = S.segments_of_writes(w, mss, cw[st[1]])
        if st[1] == 0:
            c += n
        else:
            s += n
        cw[st[1]] = S.grow_cwnd(cw[st[1]], n)
    return c, s


class TestBioBuffer(unittest.TestCase):
    def test_sum_preserved(self):
        for msgs in ([100], [4096], [5000], [1185, 32, 75, 5900, 3300, 74], [20000, 10]):
            self.assertEqual(sum(S.bio_buffer(msgs)), sum(msgs))

    def test_small_messages_are_one_write(self):
        self.assertEqual(S.bio_buffer([1000, 500, 200]), [1700])

    def test_large_message_remainder_is_written_directly(self):
        self.assertEqual(S.bio_buffer([1000, 12000]), [4096, 8904])

    def test_writes_match_the_flight_bytes(self):
        for suite in ("ECDSA-P256|X25519", "ML-DSA-65|ML-KEM-768", "ML-DSA-87|ML-KEM-1024"):
            for depth in (1, 3):
                f = S.build_flow(suite, ISO, depth, "cold", False)
                xs = [x for x in f.steps if x[0] == "x"]
                self.assertEqual([x[2] for x in xs], [sum(w) for w in f.writes])


class TestSegments(unittest.TestCase):
    def test_nodelay_tails_and_coalescing(self):
        self.assertEqual(S.segments_of_writes([4096], 1440, 10), 3)          # 2 full + tail
        self.assertEqual(S.segments_of_writes([4096, 4096], 1440, 10), 6)    # each tail leaves at once
        self.assertEqual(S.segments_of_writes([4096, 4096], 1440, 2), 6)     # window exhausted: tails coalesce

    def test_matches_kernel_counters(self):
        # (suite, depth, mtu): (client data segments, server data segments) measured with TCP_INFO
        for key, (c, s) in {("ML-DSA-65|ML-KEM-768", 1, 1280): (13, 12), ("ML-DSA-87|ML-KEM-1024", 1, 1280): (15, 14),
                            ("ML-DSA-87|ML-KEM-1024", 1, 1500): (13, 13)}.items():
            self.assertEqual(segs_per_side(*key), (c, s), key)


class TestRunFlowOptions(unittest.TestCase):
    f = S.build_flow("ML-DSA-65|ML-KEM-768", ISO, 2, "cold", False)

    def test_defaults_are_the_validated_stack(self):
        n = S.Net(100, 30, 1500)
        self.assertEqual(n.segmentation, "openssl")
        self.assertTrue(n.cwnd_validation)
        self.assertEqual(S.Net(100, 30, 1500, **S.STACKS["v4"]).segmentation, "ideal")

    def test_linux_rule_adds_a_round_trip_for_a_flight_that_only_fitted_after_growth(self):
        # measured (testbed): ML-DSA-65 depth 2, 30 ms RTT, MTU 1500 -> 148.6 ms of transport time (v4 rule: 121.8)
        v4 = S.run_flow(self.f, S.Net(100, 30, 1500, **S.STACKS["v4"]))
        lin = S.run_flow(self.f, S.Net(100, 30, 1500, cwnd_validation=True, segmentation="ideal"))
        self.assertAlmostEqual((v4["total"] - v4["cpu"]), 121.8, delta=0.5)
        self.assertGreater(lin["total"] - v4["total"], 25)

    def test_openssl_segmentation_adds_segments(self):
        f = S.build_flow("ML-DSA-65|ML-KEM-768", ISO, 1, "cold", False)
        a = S.run_flow(f, S.Net(100, 30, 1280, cwnd_validation=True, segmentation="ideal"))
        b = S.run_flow(f, S.Net(100, 30, 1280))
        self.assertEqual(b["segs"], 25)               # 13 client + 12 server segments counted by the kernel
        self.assertGreater(b["total"] - b["cpu"], a["total"] - a["cpu"] + 50)    # two extra window waits (measured +55.6 ms)


if __name__ == "__main__":
    unittest.main()


class TestGrowCwnd(unittest.TestCase):
    def test_small_flights_do_not_grow_the_window(self):
        self.assertEqual(S.grow_cwnd(10, 1), 10)
        self.assertEqual(S.grow_cwnd(10, 4), 10)

    def test_window_limited_flight_stops_at_twice_the_peak_in_flight(self):
        self.assertEqual(S.grow_cwnd(10, 31), 40)       # the DES cross-check case (peak 20 segments in flight)
        self.assertEqual(S.grow_cwnd(10, 10), 20)

    def test_never_shrinks(self):
        for cw in (4, 10, 32):
            for n in range(1, 80):
                self.assertGreaterEqual(S.grow_cwnd(cw, n), cw)
                self.assertLessEqual(S.grow_cwnd(cw, n), cw + n)
