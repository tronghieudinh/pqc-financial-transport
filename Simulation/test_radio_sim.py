import dataclasses
import random
import unittest

import radio_sim as R
import pqc_sim as S

BASE = R.PROFILES["5G-NR sub-6 (eMBB)"]


class Ideal(unittest.TestCase):
    """With no errors and a fixed symmetric rate the DES must equal pqc_sim.run_flow."""

    def test_matches_closed_form(self):
        prof = dataclasses.replace(BASE, ul_base_ms=3.0, dl_base_ms=3.0, p_block=0.0)
        for sn, pn, mode, d in [("ECDSA-P256|X25519", "ISO_20022", "cold", 2),
                                ("ML-DSA-65|ML-KEM-768", "SWIFT_MX", "cold", 3),
                                ("Falcon-512|ML-KEM-768", "FAPI2", "cold", 4),
                                ("SLH-DSA-128f|ML-KEM-768", "OIDC", "warm", 0)]:
            for bw, wired, mtu in [(100.0, 24.0, 1500), (10.0, 94.0, 1280), (1600.0, 4.0, 9000)]:
                f = S.build_flow(sn, pn, d, mode, False)
                a = S.run_flow(f, S.Net(bw, wired + 6.0, mtu, 0.0, 4, **S.STACKS["v4"]))["total"]   # radio_sim still implements the v4 stack
                b = R.run_radio_flow(f, prof, 20.0, wired, mtu, "e", "p", fixed_rate_mbps=bw)["total"]
                self.assertAlmostEqual(a, b, places=6, msg=(sn, pn, bw))


class LinkMath(unittest.TestCase):
    def test_bler_anchor_and_monotone(self):
        self.assertAlmostEqual(R.bler(0.0, 2.2), 0.1)
        self.assertGreater(R.bler(-2, 2.2), R.bler(0, 2.2))
        self.assertGreater(R.bler(0, 2.2), R.bler(2, 2.2))

    def test_calibration_hits_target(self):
        zs, ws = R._quad()
        for sig, tgt in [(1.0, 0.1), (3.0, 0.1), (3.6, 1e-3)]:
            b = R.calibrate_backoff(sig, tgt, 2.2)
            mean = sum(w * R.bler(b + sig * z, 2.2) for z, w in zip(zs, ws))
            self.assertAlmostEqual(mean, tgt, delta=tgt * 0.01)

    def test_rate_and_bler_fall_with_noise(self):
        prev_rate = 1e18
        for s in (30, 20, 10, 5, 0, -5):
            d = R.link_summary(BASE, s, samples=120)
            self.assertLess(d["dl_mbps"], prev_rate)
            prev_rate = d["dl_mbps"]
            self.assertLess(d["bler_first_tx"], 0.5)      # link adaptation keeps BLER sane

    def test_blockage_fraction(self):
        rng = random.Random(3)
        frac = 0.0
        for _ in range(300):
            b = R.Blockage(rng, 0.1, 80.0, horizon=8000.0)
            frac += sum(min(e, 8000.0) - s for s, e in b.iv) / 8000.0
        self.assertAlmostEqual(frac / 300, 0.1, delta=0.02)


class Flows(unittest.TestCase):
    def test_reproducible(self):
        f = S.build_flow("ML-DSA-65|ML-KEM-768", "FAPI2", 2, "cold", False)
        a = R.run_radio_flow(f, BASE, 5.0, 20.0, 1500, "e1", "p1")
        b = R.run_radio_flow(f, BASE, 5.0, 20.0, 1500, "e1", "p1")
        self.assertEqual(a, b)

    def test_noise_never_helps_on_average(self):
        f = S.build_flow("ML-DSA-65|ML-KEM-768", "ISO_20022", 2, "cold", False)
        mean = lambda s: sum(R.run_radio_flow(f, BASE, s, 20.0, 1500, f"e{t}", f"p{t}")["total"]
                             for t in range(60)) / 60
        self.assertLess(mean(30), mean(5))
        self.assertLess(mean(5), mean(-5))


if __name__ == "__main__":
    unittest.main()
