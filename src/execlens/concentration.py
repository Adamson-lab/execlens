"""Vendor concentration and single-point-of-failure analysis."""
from __future__ import annotations

from collections import defaultdict

from .forensics import Finding


def _hhi(values) -> float:
    t = sum(values)
    return sum((v / t * 100) ** 2 for v in values) if t else 0.0


def analyze(payments, vendors) -> tuple[dict, list[Finding]]:
    vmap = {v.id: v for v in vendors}
    spend = defaultdict(float)
    for p in payments:
        spend[p.vendor_id] += p.amount
    total = sum(spend.values())
    ranked = sorted(spend.items(), key=lambda kv: -kv[1])
    cat = defaultdict(lambda: defaultdict(float))
    for vid, amt in spend.items():
        cat[vmap[vid].category if vid in vmap else "Unknown"][vid] += amt
    cats = sorted(({"name": c, "hhi": _hhi(d.values()), "spend": sum(d.values())} for c, d in cat.items()),
                  key=lambda r: -r["hhi"])
    top = [{"id": vid, "name": vmap[vid].name if vid in vmap else vid, "spend": amt, "share": amt / total * 100,
            "critical": vid in vmap and vmap[vid].critical, "sole_source": vid in vmap and vmap[vid].sole_source}
           for vid, amt in ranked[:12]]
    res = {"total": total, "hhi": _hhi(spend.values()), "top1": ranked[0][1] / total * 100 if ranked else 0,
           "top5": sum(a for _, a in ranked[:5]) / total * 100 if ranked else 0,
           "vendors": len(spend), "top_vendors": top, "categories": cats}
    findings = []
    if res["top1"] > 25:
        findings.append(Finding("concentration", "high", ranked[0][1], f"Top vendor takes {res['top1']:.0f}% of spend"))
    elif res["top1"] > 15:
        findings.append(Finding("concentration", "medium", ranked[0][1], f"Top vendor takes {res['top1']:.0f}% of spend"))
    for vid, amt in ranked:
        v = vmap.get(vid)
        if v and v.critical and v.sole_source:
            sev = "high" if amt / total >= 0.05 else "medium"
            findings.append(Finding("single_point_of_failure", sev, amt,
                                    f"{v.name} is critical AND sole-source ({amt / total * 100:.1f}% of spend)"))
    res["spof"] = [f.to_dict() for f in findings if f.kind == "single_point_of_failure"]
    return res, findings
