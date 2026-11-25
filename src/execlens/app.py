"""Builds the single JSON payload that drives the dashboard."""
from __future__ import annotations

import copy
import random
import threading
from datetime import datetime, timezone

from . import concentration, forensics, landingzone, riskquant, synth

TITLE = "ExecLens Command Center"
LEAKAGE_KINDS = {"duplicate_payment", "split_purchase", "ghost_vendor", "round_amounts"}


class State:
    def __init__(self, seed: int = 21, sims: int = 20000, accounts=None, scenarios=None, currency: str = "$",
                 appetite: float = 10_000_000, finance=None):
        self.lock = threading.Lock()
        self.currency, self.appetite = currency, appetite
        self.accounts = accounts if accounts is not None else landingzone.synth_estate()
        scen = scenarios if scenarios is not None else riskquant.DEMO_SCENARIOS
        self.risk = riskquant.analyze(scen, sims, seed, appetite)
        vendors, payments, employees = finance if finance else synth.generate(seed)
        self.vendors, self.payments, self.employees = vendors, payments, employees
        conc, cfind = concentration.analyze(payments, vendors)
        fs = forensics.detect_all(payments, vendors, employees, synth.THRESHOLD) + cfind
        self.findings = sorted(fs, key=lambda f: (forensics.SEV_RANK[f.severity], -f.exposure))
        self.conc = conc
        self.rng = random.Random(seed)

    def payload(self) -> dict:
        with self.lock:
            lz = landingzone.evaluate(self.accounts)
        leak = [f for f in self.findings if f.kind in LEAKAGE_KINDS or f.kind == "benford"]
        by_kind: dict = {}
        for f in leak:
            if f.kind != "benford":
                by_kind[f.kind] = by_kind.get(f.kind, 0.0) + f.exposure
        return {
            "meta": {"title": TITLE, "currency": self.currency, "generated": datetime.now(timezone.utc).isoformat(timespec="seconds")},
            "risk": self.risk,
            "forensics": {"findings": [f.to_dict() for f in leak[:80]], "by_kind": by_kind,
                          "count": len(leak), "payments": len(self.payments)},
            "concentration": copy.deepcopy(self.conc),
            "landing_zone": lz,
        }

    def tick(self, steps: int = 2) -> list[str]:
        with self.lock:
            return landingzone.drift(self.accounts, self.rng, steps)
