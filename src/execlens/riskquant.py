"""FAIR-style quantitative risk: Monte Carlo loss simulation with control ROI.

Each scenario has an annual event frequency (triangular low/mode/high) and a
per-event loss magnitude (lognormal fitted to a 90% interval, p5..p95).
A control reduces event frequency (thinning) and/or loss magnitude. Baseline
and controlled runs share random draws, so the benefit estimate is paired
and much less noisy than two independent simulations.
"""
from __future__ import annotations

import bisect
import math
import random
from dataclasses import dataclass
from typing import Optional

Z95 = 1.6449


@dataclass(frozen=True)
class Control:
    name: str
    annual_cost: float
    freq_reduction: float = 0.0
    impact_reduction: float = 0.0


@dataclass(frozen=True)
class Scenario:
    name: str
    freq_low: float
    freq_mode: float
    freq_high: float
    loss_p5: float
    loss_p95: float
    control: Optional[Control] = None


def _poisson(rng: random.Random, lam: float) -> int:
    if lam <= 0:
        return 0
    if lam > 30:
        return max(0, round(rng.gauss(lam, math.sqrt(lam))))
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def simulate(s: Scenario, n: int, seed: int, with_control: bool = False) -> list[float]:
    rng = random.Random(seed)
    mu = (math.log(s.loss_p5) + math.log(s.loss_p95)) / 2
    sigma = (math.log(s.loss_p95) - math.log(s.loss_p5)) / (2 * Z95)
    c = s.control if with_control else None
    fr = c.freq_reduction if c else 0.0
    ir = c.impact_reduction if c else 0.0
    out = []
    for _ in range(n):
        lam = rng.triangular(s.freq_low, s.freq_high, s.freq_mode)
        total = 0.0
        for _ in range(_poisson(rng, lam)):
            keep = rng.random()
            mag = rng.lognormvariate(mu, sigma)
            if keep >= fr:
                total += mag * (1 - ir)
        out.append(total)
    return out


def quantile(sorted_vals: list[float], q: float) -> float:
    return sorted_vals[int(q * (len(sorted_vals) - 1))]


def summarize(losses: list[float]) -> dict:
    s = sorted(losses)
    return {
        "mean": sum(s) / len(s),
        "p50": quantile(s, 0.50),
        "p90": quantile(s, 0.90),
        "p95": quantile(s, 0.95),
        "p99": quantile(s, 0.99),
    }


def exceedance(sorted_vals: list[float], x: float) -> float:
    return 1 - bisect.bisect_right(sorted_vals, x) / len(sorted_vals)


def control_roi(s: Scenario, n: int = 20000, seed: int = 7) -> dict:
    if not s.control:
        raise ValueError("scenario has no control")
    base, ctrl = simulate(s, n, seed), simulate(s, n, seed, True)
    benefit = sum(base) / n - sum(ctrl) / n
    cost = s.control.annual_cost
    return {"benefit": benefit, "cost": cost, "roi": (benefit - cost) / cost if cost else float("inf")}


def analyze(scenarios: list[Scenario], n: int = 20000, seed: int = 7, appetite: float | None = None) -> dict:
    base_runs, ctrl_runs, rows = [], [], []
    for i, s in enumerate(scenarios):
        b = simulate(s, n, seed + i)
        c = simulate(s, n, seed + i, True) if s.control else b
        base_runs.append(b)
        ctrl_runs.append(c)
        sb = summarize(b)
        row = {"name": s.name, "mean": sb["mean"], "p95": sb["p95"], "p99": sb["p99"], "control": None}
        if s.control:
            benefit = sb["mean"] - sum(c) / n
            row["control"] = {
                "name": s.control.name, "cost": s.control.annual_cost, "benefit": benefit,
                "roi": (benefit - s.control.annual_cost) / s.control.annual_cost,
                "residual_mean": sum(c) / n,
                "p95_before": sb["p95"], "p95_after": summarize(c)["p95"],
            }
        rows.append(row)
    tot_b = sorted(sum(x) for x in zip(*base_runs))
    tot_c = sorted(sum(x) for x in zip(*ctrl_runs))
    lo, hi = max(1.0, quantile(tot_b, 0.2) * 0.3), quantile(tot_b, 0.995) * 1.3
    xs = [lo * (hi / lo) ** (i / 39) for i in range(40)]
    out = {
        "scenarios": rows,
        "total": summarize(tot_b), "total_ctrl": summarize(tot_c),
        "curve": {"x": xs, "base": [exceedance(tot_b, x) for x in xs], "ctrl": [exceedance(tot_c, x) for x in xs]},
        "appetite": appetite, "p_exceed_base": None, "p_exceed_ctrl": None,
        "control_spend": sum(s.control.annual_cost for s in scenarios if s.control),
    }
    if appetite:
        out["p_exceed_base"] = exceedance(tot_b, appetite)
        out["p_exceed_ctrl"] = exceedance(tot_c, appetite)
    return out


def scenarios_from_dict(cfg: dict) -> list[Scenario]:
    out = []
    for d in cfg["scenarios"]:
        ctl = Control(**d["control"]) if d.get("control") else None
        out.append(Scenario(d["name"], d["freq_low"], d["freq_mode"], d["freq_high"],
                            d["loss_p5"], d["loss_p95"], ctl))
    return out


DEMO_SCENARIOS = [
    Scenario("Ransomware outage", 0.05, 0.15, 0.40, 400_000, 12_000_000,
             Control("EDR + immutable backups", 380_000, 0.35, 0.50)),
    Scenario("Payment fraud / BEC", 0.5, 1.2, 3.0, 20_000, 900_000,
             Control("Dual approval + call-back", 120_000, 0.60, 0.30)),
    Scenario("AML/KYC regulatory sanction", 0.05, 0.10, 0.30, 500_000, 25_000_000,
             Control("Automated screening", 520_000, 0.50, 0.20)),
    Scenario("Critical supplier failure", 0.10, 0.25, 0.60, 300_000, 8_000_000,
             Control("Dual-source critical inputs", 400_000, 0.40, 0.50)),
    Scenario("Insider data leak", 0.10, 0.30, 0.80, 100_000, 4_000_000,
             Control("DLP + least privilege", 150_000, 0.30, 0.30)),
]
