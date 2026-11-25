"""Cloud landing zone compliance scorecard.

Evaluates an offline inventory snapshot (one dict of settings per account or
subscription) against 30 controls mapped to common frameworks, and rolls the
results up by domain, OU and framework. No cloud credentials are needed:
export the inventory with your own collector (see docs/collectors.md).
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

DOMAINS = ["Identity", "Logging", "Network", "Data", "Governance", "Resilience"]
WEIGHT_LABEL = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "low"}


@dataclass(frozen=True)
class LzControl:
    id: str
    title: str
    domain: str
    weight: int
    frameworks: tuple
    remediation: str
    check: Callable[[dict], bool]


def _c(id, title, domain, weight, fw, fix, check):
    return LzControl(id, title, domain, weight, tuple(fw), fix, check)


CONTROLS: list[LzControl] = [
    _c("IAM-01", "Root/owner account protected by MFA", "Identity", 5, ["CIS", "NIST 800-53", "ISO 27001", "SOC 2", "PCI DSS"], "Enforce hardware MFA on root; vault credentials", lambda a: a["root_mfa"]),
    _c("IAM-02", "No console users without MFA", "Identity", 4, ["CIS", "NIST 800-53", "SOC 2", "PCI DSS"], "Block console sign-in without MFA via policy", lambda a: a["users_without_mfa"] == 0),
    _c("IAM-03", "Access via central SSO, not local users", "Identity", 3, ["NIST 800-53", "ISO 27001", "SOC 2"], "Federate to the corporate IdP; remove local users", lambda a: a["sso_federated"]),
    _c("IAM-04", "No privileged identity idle > 90 days", "Identity", 3, ["CIS", "NIST 800-53", "ISO 27001"], "Run quarterly access reviews; auto-disable idle admins", lambda a: a["unused_privileged_90d"] == 0),
    _c("IAM-05", "Credential policy meets baseline", "Identity", 2, ["CIS", "PCI DSS"], "Apply organization password/key rotation policy", lambda a: a["password_policy_ok"]),
    _c("LOG-01", "Organization-wide audit trail enabled", "Logging", 5, ["CIS", "NIST 800-53", "ISO 27001", "SOC 2", "PCI DSS"], "Enable org trail to the log-archive account", lambda a: a["org_trail"]),
    _c("LOG-02", "Log retention at least 365 days", "Logging", 3, ["NIST 800-53", "ISO 27001", "PCI DSS"], "Set retention policy to 365d or longer", lambda a: a["log_retention_days"] >= 365),
    _c("LOG-03", "Logs immutable and centrally stored", "Logging", 4, ["NIST 800-53", "ISO 27001", "SOC 2"], "Object-lock/WORM bucket in dedicated account", lambda a: a["log_immutable"]),
    _c("LOG-04", "Managed threat detection enabled", "Logging", 4, ["NIST 800-53", "ISO 27001", "SOC 2"], "Enable threat detection service org-wide", lambda a: a["threat_detection"]),
    _c("LOG-05", "Security alerts routed to the SOC", "Logging", 3, ["NIST 800-53", "SOC 2"], "Wire findings to SIEM/ticketing with on-call", lambda a: a["alerting_wired"]),
    _c("NET-01", "No admin ports open to the internet", "Network", 5, ["CIS", "NIST 800-53", "PCI DSS", "SOC 2"], "Remove 0.0.0.0/0 on 22/3389; use bastion/session manager", lambda a: a["open_admin_ports"] == 0),
    _c("NET-02", "No publicly readable storage", "Network", 5, ["CIS", "NIST 800-53", "ISO 27001", "GDPR", "PCI DSS"], "Block public access at org level", lambda a: a["public_buckets"] == 0),
    _c("NET-03", "Connected to hub with inspected egress", "Network", 3, ["NIST 800-53", "ISO 27001"], "Attach spoke to hub transit; remove direct egress", lambda a: a["hub_peered"]),
    _c("NET-04", "Network flow logs enabled", "Network", 3, ["CIS", "NIST 800-53", "PCI DSS"], "Enable flow logs to central archive", lambda a: a["flow_logs"]),
    _c("NET-05", "Default network not in use", "Network", 2, ["CIS"], "Delete default VPC/VNet; use vended network", lambda a: not a["default_vpc_used"]),
    _c("NET-06", "WAF on public endpoints", "Network", 3, ["PCI DSS", "NIST 800-53", "SOC 2"], "Front public apps with WAF and DDoS protection", lambda a: a["waf"]),
    _c("DAT-01", "At least 99% of storage encrypted at rest", "Data", 4, ["CIS", "NIST 800-53", "ISO 27001", "GDPR", "PCI DSS"], "Default-encrypt; remediate unencrypted volumes", lambda a: a["encryption_at_rest_pct"] >= 99),
    _c("DAT-02", "Customer-managed key rotation enabled", "Data", 2, ["CIS", "PCI DSS"], "Turn on automatic annual key rotation", lambda a: a["kms_rotation"]),
    _c("DAT-03", "TLS 1.2 or higher enforced", "Data", 3, ["NIST 800-53", "PCI DSS", "ISO 27001"], "Set minimum TLS policy on all endpoints", lambda a: a["tls_min_12"]),
    _c("DAT-04", "Data stays in approved jurisdictions", "Data", 4, ["GDPR", "ISO 27001", "SOC 2"], "Deny non-approved regions; audit replication", lambda a: a["data_residency_ok"]),
    _c("DAT-05", "No hard-coded secrets found", "Data", 4, ["NIST 800-53", "SOC 2", "PCI DSS"], "Rotate leaked secrets; move to a secrets manager", lambda a: a["secrets_in_code"] == 0),
    _c("GOV-01", "Preventive guardrails (SCP/Policy) attached", "Governance", 4, ["NIST 800-53", "ISO 27001", "SOC 2"], "Attach baseline guardrails to the OU", lambda a: a["scp_guardrails"]),
    _c("GOV-02", "At least 95% of resources tagged", "Governance", 2, ["ISO 27001"], "Enforce tag policy with deny-on-create", lambda a: a["tags_pct"] >= 95),
    _c("GOV-03", "Budget alerts configured", "Governance", 2, ["SOC 2"], "Create budgets with 80/100% alerts", lambda a: a["budget_alerts"]),
    _c("GOV-04", "Only approved regions enabled", "Governance", 3, ["CIS", "GDPR", "ISO 27001"], "Region-deny guardrail at the OU", lambda a: a["allowed_regions_only"]),
    _c("GOV-05", "Business owner assigned", "Governance", 2, ["ISO 27001", "SOC 2"], "Record owner and cost center at vending time", lambda a: a["owner_assigned"]),
    _c("RES-01", "Backup policy applied", "Resilience", 4, ["NIST 800-53", "ISO 27001", "SOC 2", "PCI DSS"], "Attach org backup policy to tagged resources", lambda a: a["backup_policy"]),
    _c("RES-02", "Restore tested in the last 90 days", "Resilience", 3, ["NIST 800-53", "ISO 27001"], "Schedule quarterly restore tests", lambda a: a["restore_tested_90d"]),
    _c("RES-03", "Workloads span multiple zones", "Resilience", 3, ["NIST 800-53", "SOC 2"], "Re-deploy single-zone workloads across 2+ zones", lambda a: a["multi_az"]),
    _c("RES-04", "At least 95% patched within SLA", "Resilience", 4, ["CIS", "NIST 800-53", "PCI DSS", "ISO 27001"], "Automate patch baselines; track SLA", lambda a: a["patch_sla_pct"] >= 95),
    _c("RES-05", "DR runbook exists and is current", "Resilience", 2, ["ISO 27001", "SOC 2"], "Write and exercise a DR runbook yearly", lambda a: a["dr_runbook"]),
]
FRAMEWORKS = sorted({f for c in CONTROLS for f in c.frameworks})


def rag(score: float) -> str:
    return "green" if score >= 90 else "amber" if score >= 75 else "red"


def evaluate_account(acct: dict) -> dict:
    cfg = acct["config"]
    failed, dom_w, dom_p = [], {d: 0 for d in DOMAINS}, {d: 0 for d in DOMAINS}
    tw = tp = 0
    for c in CONTROLS:
        ok = bool(c.check(cfg))
        dom_w[c.domain] += c.weight
        tw += c.weight
        if ok:
            dom_p[c.domain] += c.weight
            tp += c.weight
        else:
            failed.append(c.id)
    score = 100 * tp / tw
    return {"id": acct["id"], "name": acct["name"], "ou": acct["ou"], "env": acct.get("env", ""),
            "score": round(score, 1), "rag": rag(score), "failed": failed,
            "domains": {d: round(100 * dom_p[d] / dom_w[d], 1) for d in DOMAINS}}


def evaluate(accounts: list[dict]) -> dict:
    res = [evaluate_account(a) for a in accounts]
    n = len(res)
    overall = sum(r["score"] for r in res) / n
    ous = {}
    for r in res:
        ous.setdefault(r["ou"], []).append(r["score"])
    return {
        "overall": round(overall, 1), "rag": rag(overall), "accounts": res,
        "domains": [{"name": d, "score": round(sum(r["domains"][d] for r in res) / n, 1)} for d in DOMAINS],
        "ous": [{"name": o, "score": round(sum(v) / len(v), 1), "count": len(v)} for o, v in ous.items()],
        "controls": [{"id": c.id, "title": c.title, "domain": c.domain, "weight": c.weight,
                      "severity": WEIGHT_LABEL[c.weight], "frameworks": list(c.frameworks),
                      "remediation": c.remediation} for c in CONTROLS],
        "frameworks": FRAMEWORKS,
    }


# ----------------------------------------------------------------- synthetic estate
OU_QUALITY = {"Security": 0.97, "Shared-Services": 0.93, "Prod": 0.88, "NonProd": 0.75, "Sandbox": 0.55}
OU_ACCOUNTS = {"Security": ["log-archive", "audit"], "Shared-Services": ["network-hub", "identity", "tooling"],
               "Prod": ["payments", "core-banking", "crm", "data-lake", "api-gw", "portal", "risk-engine", "reporting"],
               "NonProd": ["payments-dev", "core-dev", "crm-test", "data-dev", "qa", "perf"],
               "Sandbox": ["innovation-1", "innovation-2", "training", "poc-ai", "vendor-eval"]}

BOOL_GOOD = {"root_mfa": True, "sso_federated": True, "password_policy_ok": True, "org_trail": True,
             "log_immutable": True, "threat_detection": True, "alerting_wired": True, "hub_peered": True,
             "flow_logs": True, "default_vpc_used": False, "waf": True, "kms_rotation": True, "tls_min_12": True,
             "data_residency_ok": True, "scp_guardrails": True, "budget_alerts": True, "allowed_regions_only": True,
             "owner_assigned": True, "backup_policy": True, "restore_tested_90d": True, "multi_az": True,
             "dr_runbook": True}
COUNT_KEYS = ["users_without_mfa", "unused_privileged_90d", "open_admin_ports", "public_buckets", "secrets_in_code"]
PCT_KEYS = {"encryption_at_rest_pct": (99.5, 100.0, 60.0, 98.0), "tags_pct": (95.0, 100.0, 40.0, 94.0),
            "patch_sla_pct": (95.0, 100.0, 55.0, 94.0)}


def _config(rng: random.Random, q: float) -> dict:
    cfg = {}
    for k, good in BOOL_GOOD.items():
        cfg[k] = good if rng.random() < q else (not good)
    for k in COUNT_KEYS:
        cfg[k] = 0 if rng.random() < q else rng.randint(1, 6)
    for k, (gl, gh, bl, bh) in PCT_KEYS.items():
        cfg[k] = round(rng.uniform(gl, gh) if rng.random() < q else rng.uniform(bl, bh), 1)
    cfg["log_retention_days"] = 365 if rng.random() < q else rng.choice([30, 90, 180])
    return cfg


def synth_estate(seed: int = 11) -> list[dict]:
    rng = random.Random(seed)
    accts = []
    for ou, names in OU_ACCOUNTS.items():
        for i, nm in enumerate(names, 1):
            accts.append({"id": f"{rng.randint(10**11, 10**12 - 1)}", "name": f"{ou.lower()}-{nm}",
                          "ou": ou, "env": "prod" if ou == "Prod" else "non-prod",
                          "config": _config(rng, OU_QUALITY[ou])})
    for a in accts:  # one deliberately bad crown-jewel account: the board-level story
        if a["name"] == "prod-payments":
            a["config"].update(root_mfa=False, open_admin_ports=2, public_buckets=1, secrets_in_code=3)
    return accts


def drift(accounts: list[dict], rng: random.Random, steps: int = 1) -> list[str]:
    """Randomly improve or degrade settings; used by `serve --simulate` to show a live estate."""
    log = []
    keys = list(BOOL_GOOD) + COUNT_KEYS + list(PCT_KEYS) + ["log_retention_days"]
    for _ in range(steps):
        a = rng.choice(accounts)
        k = rng.choice(keys)
        worsen = rng.random() < 0.5
        cfg = a["config"]
        if k in BOOL_GOOD:
            cfg[k] = (not BOOL_GOOD[k]) if worsen else BOOL_GOOD[k]
        elif k in COUNT_KEYS:
            cfg[k] = cfg[k] + 1 if worsen else 0
        elif k in PCT_KEYS:
            cfg[k] = round(max(30.0, cfg[k] - rng.uniform(2, 12)), 1) if worsen else 100.0
        else:
            cfg[k] = 90 if worsen else 365
        log.append(f"{a['name']}: {k} {'degraded' if worsen else 'remediated'}")
    return log
