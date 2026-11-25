"""Command line: demo | serve | lz | risk | audit."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__, dashboard, forensics, landingzone, riskquant, synth
from .app import State


def _money(x: float, c: str = "$") -> str:
    for d, s in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(x) >= d:
            return f"{c}{x / d:.1f}{s}"
    return f"{c}{x:,.0f}"


def cmd_demo(a) -> int:
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    st = State(seed=a.seed, sims=a.sims)
    synth.write_csvs(out / "data", st.vendors, st.payments, st.employees)
    (out / "data" / "landing_zone_inventory.json").write_text(json.dumps({"accounts": st.accounts}, indent=1))
    (out / "data" / "risk_scenarios.json").write_text(json.dumps({"scenarios": [
        {**{k: v for k, v in s.__dict__.items() if k != "control"},
         "control": s.control.__dict__ if s.control else None} for s in riskquant.DEMO_SCENARIOS]}, indent=1))
    payload = st.payload()
    (out / "dashboard.html").write_text(dashboard.render(payload), encoding="utf-8")
    (out / "payload.json").write_text(json.dumps(payload, indent=1))
    print(f"Wrote {out}/dashboard.html (open in a browser), payload.json and data/ sample inputs")
    print(f"Landing zone score {payload['landing_zone']['overall']} | expected annual loss {_money(payload['risk']['total']['mean'])}"
          f" -> {_money(payload['risk']['total_ctrl']['mean'])} | leakage findings {payload['forensics']['count']}")
    return 0


def cmd_serve(a) -> int:
    from .server import serve
    accounts = json.loads(Path(a.inventory).read_text())["accounts"] if a.inventory else None
    serve(State(seed=a.seed, sims=a.sims, accounts=accounts), a.host, a.port, a.simulate)
    return 0


def cmd_lz(a) -> int:
    accounts = json.loads(Path(a.inventory).read_text())["accounts"]
    r = landingzone.evaluate(accounts)
    print(f"Landing zone score: {r['overall']} ({r['rag']})")
    for d in r["domains"]:
        print(f"  {d['name']:<11}{d['score']:>6}")
    print("Worst accounts:")
    for x in sorted(r["accounts"], key=lambda x: x["score"])[:5]:
        print(f"  {x['name']:<30}{x['score']:>6}  failing: {', '.join(x['failed'][:6])}")
    if a.json:
        Path(a.json).write_text(json.dumps(r, indent=1))
    return 1 if (a.fail_under and r["overall"] < a.fail_under) else 0


def cmd_risk(a) -> int:
    scen = riskquant.scenarios_from_dict(json.loads(Path(a.scenarios).read_text()))
    r = riskquant.analyze(scen, a.sims, a.seed, a.appetite)
    print(f"Expected annual loss {_money(r['total']['mean'])} -> {_money(r['total_ctrl']['mean'])} with controls; p95 {_money(r['total']['p95'])} -> {_money(r['total_ctrl']['p95'])}")
    for s in sorted(r["scenarios"], key=lambda s: -(s["control"] or {}).get("roi", -9)):
        c = s["control"]
        print(f"  {s['name']:<32}EAL {_money(s['mean']):>8}" + (f"  {c['name']}: ROI {c['roi'] * 100:.0f}%" if c else ""))
    return 0


def cmd_audit(a) -> int:
    pays, vens, emps = (forensics.load_payments(a.payments), forensics.load_vendors(a.vendors),
                        forensics.load_employees(a.employees) if a.employees else [])
    fs = forensics.detect_all(pays, vens, emps, a.threshold)
    for f in fs[: a.top]:
        print(f"[{f.severity:8}] {f.kind:<18} {_money(f.exposure):>8}  {f.summary}")
    print(f"{len(fs)} findings, {_money(sum(f.exposure for f in fs))} flagged exposure")
    if a.json:
        Path(a.json).write_text(json.dumps([f.to_dict() for f in fs], indent=1))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="execlens", description="Executive decision intelligence toolkit")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="generate sample data + static dashboard")
    d.add_argument("--out", default="out"); d.add_argument("--seed", type=int, default=21); d.add_argument("--sims", type=int, default=20000)
    d.set_defaults(fn=cmd_demo)
    s = sub.add_parser("serve", help="live dashboard server")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8080)
    s.add_argument("--simulate", action="store_true", help="drift the sample estate so the dashboard visibly changes")
    s.add_argument("--inventory", help="landing zone inventory JSON to monitor instead of sample data")
    s.add_argument("--seed", type=int, default=21); s.add_argument("--sims", type=int, default=20000)
    s.set_defaults(fn=cmd_serve)
    l = sub.add_parser("lz", help="score a landing zone inventory (CI-friendly exit code)")
    l.add_argument("--inventory", required=True); l.add_argument("--json"); l.add_argument("--fail-under", type=float, default=0)
    l.set_defaults(fn=cmd_lz)
    r = sub.add_parser("risk", help="Monte Carlo risk quantification from a scenarios JSON")
    r.add_argument("scenarios"); r.add_argument("--sims", type=int, default=20000); r.add_argument("--seed", type=int, default=7)
    r.add_argument("--appetite", type=float, default=None)
    r.set_defaults(fn=cmd_risk)
    u = sub.add_parser("audit", help="payment forensics on CSV exports")
    u.add_argument("--payments", required=True); u.add_argument("--vendors", required=True); u.add_argument("--employees")
    u.add_argument("--threshold", type=float, default=50_000); u.add_argument("--top", type=int, default=25); u.add_argument("--json")
    u.set_defaults(fn=cmd_audit)
    a = p.parse_args(argv)
    return a.fn(a)
