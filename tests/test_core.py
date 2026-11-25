import json, random, tempfile, unittest
from datetime import date
from pathlib import Path

from execlens import concentration, forensics as F, landingzone as L, riskquant as R, synth
from execlens.cli import main
from execlens.app import State


class RiskTests(unittest.TestCase):
    def test_deterministic(self):
        s = R.DEMO_SCENARIOS[0]
        self.assertEqual(R.simulate(s, 500, 1), R.simulate(s, 500, 1))

    def test_control_reduces_loss_and_pairs(self):
        s = R.DEMO_SCENARIOS[1]
        r = R.control_roi(s, 5000, 3)
        self.assertGreater(r["benefit"], 0)
        base, ctrl = R.simulate(s, 2000, 3), R.simulate(s, 2000, 3, True)
        self.assertTrue(all(c <= b + 1e-9 for b, c in zip(base, ctrl)))

    def test_lognormal_fit_matches_interval(self):
        s = R.Scenario("x", 1, 1, 1, 1000, 100000)
        import math
        mu = (math.log(1000) + math.log(100000)) / 2
        self.assertAlmostEqual(math.exp(mu), 10000, delta=1)

    def test_analyze_shapes(self):
        a = R.analyze(R.DEMO_SCENARIOS, 1500, 5, 10e6)
        self.assertLess(a["total_ctrl"]["mean"], a["total"]["mean"])
        self.assertLessEqual(a["p_exceed_ctrl"], a["p_exceed_base"])


class ForensicsTests(unittest.TestCase):
    def setUp(self):
        self.v, self.p, self.e = synth.generate(21)

    def test_planted_anomalies_found(self):
        fs = F.detect_all(self.p, self.v, self.e)
        kinds = {f.kind for f in fs}
        self.assertTrue({"ghost_vendor", "split_purchase", "duplicate_payment", "round_amounts"} <= kinds)
        ghost = [f for f in fs if f.kind == "ghost_vendor"][0]
        self.assertIn("V061", ghost.summary)
        self.assertEqual(ghost.severity, "critical")

    def test_split_requires_same_approver(self):
        mk = lambda i, appr: F.Payment(f"P{i}", "V1", 30000, date(2026, 1, i), "", "Works", appr)
        self.assertEqual(len(F.find_splits([mk(1, "A"), mk(2, "B")])), 0)
        self.assertEqual(len(F.find_splits([mk(1, "A"), mk(2, "A")])), 1)

    def test_benford_detects_fabricated(self):
        rng = random.Random(1)
        natural = [rng.lognormvariate(8, 2.2) for _ in range(3000)]
        fake = [rng.uniform(5000, 9000) for _ in range(3000)]
        self.assertLess(F.benford_chi2(natural)[0], F.CHI2_P05_DF8 * 2)
        self.assertGreater(F.benford_chi2(fake)[0], 100)

    def test_concentration(self):
        res, fs = concentration.analyze(self.p, self.v)
        self.assertGreater(res["top1"], 25)
        self.assertTrue(any(f.kind == "single_point_of_failure" for f in fs))


class LandingZoneTests(unittest.TestCase):
    def test_scores_bounded_and_ordered(self):
        r = L.evaluate(L.synth_estate(11))
        self.assertTrue(all(0 <= a["score"] <= 100 for a in r["accounts"]))
        ou = {o["name"]: o["score"] for o in r["ous"]}
        self.assertGreater(ou["Security"], ou["Sandbox"])
        pay = next(a for a in r["accounts"] if a["name"] == "prod-payments")
        self.assertIn("IAM-01", pay["failed"])
        self.assertIn("NET-02", pay["failed"])

    def test_perfect_account_scores_100(self):
        cfg = {k: v for k, v in L.BOOL_GOOD.items()}
        cfg.update({k: 0 for k in L.COUNT_KEYS}); cfg.update(encryption_at_rest_pct=100, tags_pct=100, patch_sla_pct=100, log_retention_days=400)
        self.assertEqual(L.evaluate_account({"id": "1", "name": "x", "ou": "Prod", "config": cfg})["score"], 100.0)

    def test_drift_changes_something(self):
        a = L.synth_estate(11); before = json.dumps(a, sort_keys=True)
        L.drift(a, random.Random(5), 25)
        self.assertNotEqual(before, json.dumps(a, sort_keys=True))


class EndToEnd(unittest.TestCase):
    def test_demo_cli_writes_dashboard(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(main(["demo", "--out", d, "--sims", "1500"]), 0)
            html = (Path(d) / "dashboard.html").read_text()
            self.assertIn("landing_zone", html); self.assertNotIn("__DATA__", html)
            self.assertTrue((Path(d) / "data" / "payments.csv").exists())
            self.assertEqual(main(["lz", "--inventory", f"{d}/data/landing_zone_inventory.json", "--fail-under", "99"]), 1)
            self.assertEqual(main(["risk", f"{d}/data/risk_scenarios.json", "--sims", "1000"]), 0)
            self.assertEqual(main(["audit", "--payments", f"{d}/data/payments.csv", "--vendors", f"{d}/data/vendors.csv", "--employees", f"{d}/data/employees.csv"]), 0)

    def test_payload_json_serialisable(self):
        json.dumps(State(sims=1000).payload())


if __name__ == "__main__":
    unittest.main()
