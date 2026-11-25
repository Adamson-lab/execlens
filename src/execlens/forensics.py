"""Payment forensics: duplicates, split purchases, ghost vendors, Benford, round amounts."""
from __future__ import annotations

import csv
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
BENFORD = [math.log10(1 + 1 / d) for d in range(1, 10)]
CHI2_P05_DF8 = 15.507   # overall test
CHI2_P001_DF8 = 26.125  # per-vendor test (stricter: many tests run)


@dataclass(frozen=True)
class Payment:
    id: str
    vendor_id: str
    amount: float
    date: date
    invoice_no: str = ""
    department: str = ""
    approver: str = ""


@dataclass(frozen=True)
class Vendor:
    id: str
    name: str
    category: str = ""
    bank_account: str = ""
    address: str = ""
    critical: bool = False
    sole_source: bool = False


@dataclass(frozen=True)
class Employee:
    id: str
    bank_account: str = ""
    address: str = ""


@dataclass
class Finding:
    kind: str
    severity: str
    exposure: float
    summary: str
    evidence: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "severity": self.severity, "exposure": round(self.exposure, 2),
                "summary": self.summary, "evidence": self.evidence}


def _truthy(v: str) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "y"}


def load_payments(path) -> list[Payment]:
    with open(path, newline="", encoding="utf-8") as f:
        return [Payment(r["id"], r["vendor_id"], float(r["amount"]), date.fromisoformat(r["date"]),
                        r.get("invoice_no", ""), r.get("department", ""), r.get("approver", ""))
                for r in csv.DictReader(f)]


def load_vendors(path) -> list[Vendor]:
    with open(path, newline="", encoding="utf-8") as f:
        return [Vendor(r["id"], r["name"], r.get("category", ""), r.get("bank_account", ""),
                       r.get("address", ""), _truthy(r.get("critical", "")), _truthy(r.get("sole_source", "")))
                for r in csv.DictReader(f)]


def load_employees(path) -> list[Employee]:
    with open(path, newline="", encoding="utf-8") as f:
        return [Employee(r["id"], r.get("bank_account", ""), r.get("address", "")) for r in csv.DictReader(f)]


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def first_digit(x: float) -> int:
    return int(f"{abs(x):.6e}"[0])


def benford_chi2(amounts) -> tuple[float, int]:
    digs = [first_digit(a) for a in amounts if abs(a) >= 0.01]
    n = len(digs)
    if n == 0:
        return 0.0, 0
    c = Counter(digs)
    return sum((c.get(d, 0) - n * BENFORD[d - 1]) ** 2 / (n * BENFORD[d - 1]) for d in range(1, 10)), n


def find_duplicates(payments, window_days: int = 14) -> list[Finding]:
    out, flagged = [], set()
    by_inv = defaultdict(list)
    for p in payments:
        if p.invoice_no:
            by_inv[(p.vendor_id, p.invoice_no)].append(p)
    for (vid, inv), grp in by_inv.items():
        if len(grp) > 1:
            grp.sort(key=lambda p: p.date)
            flagged.update(p.id for p in grp)
            exp = sum(p.amount for p in grp[1:])
            out.append(Finding("duplicate_payment", "high", exp,
                               f"Invoice {inv} to vendor {vid} paid {len(grp)} times",
                               [f"{p.id} {p.date} {p.amount:,.2f}" for p in grp]))
    by_amt = defaultdict(list)
    for p in payments:
        by_amt[(p.vendor_id, round(p.amount, 2))].append(p)
    for (vid, amt), grp in by_amt.items():
        grp.sort(key=lambda p: p.date)
        for a, b in zip(grp, grp[1:]):
            if (b.date - a.date) <= timedelta(days=window_days) and not ({a.id, b.id} & flagged):
                flagged.update({a.id, b.id})
                out.append(Finding("duplicate_payment", "high", b.amount,
                                   f"Same amount {amt:,.2f} paid to vendor {vid} twice within {(b.date - a.date).days}d",
                                   [f"{a.id} {a.date}", f"{b.id} {b.date}"]))
    return out


def find_splits(payments, threshold: float = 50_000, window_days: int = 7, min_share: float = 0.2) -> list[Finding]:
    """Same vendor + department + approver, several sub-threshold payments inside a short window."""
    out = []
    groups = defaultdict(list)
    for p in payments:
        if min_share * threshold <= p.amount < threshold:
            groups[(p.vendor_id, p.department, p.approver)].append(p)
    for (vid, dept, _appr), grp in groups.items():
        grp.sort(key=lambda p: p.date)
        i = 0
        while i < len(grp):
            j, total = i, 0.0
            while j < len(grp) and (grp[j].date - grp[i].date) <= timedelta(days=window_days):
                total += grp[j].amount
                j += 1
            if j - i >= 2 and total >= threshold:
                chunk = grp[i:j]
                out.append(Finding("split_purchase", "high", total,
                                   f"{len(chunk)} payments to {vid} ({dept}) within {window_days}d total {total:,.0f}, "
                                   f"each under the {threshold:,.0f} approval limit",
                                   [f"{p.id} {p.date} {p.amount:,.2f} by {p.approver}" for p in chunk]))
                i = j
            else:
                i += 1
    return out


def find_ghost_vendors(payments, vendors, employees) -> list[Finding]:
    paid = defaultdict(float)
    for p in payments:
        paid[p.vendor_id] += p.amount
    emp_bank = {_norm(e.bank_account): e.id for e in employees if e.bank_account}
    emp_addr = {_norm(e.address): e.id for e in employees if e.address}
    out = []
    for v in vendors:
        hits = []
        if v.bank_account and _norm(v.bank_account) in emp_bank:
            hits.append(f"bank account matches employee {emp_bank[_norm(v.bank_account)]}")
        if v.address and _norm(v.address) in emp_addr:
            hits.append(f"address matches employee {emp_addr[_norm(v.address)]}")
        if hits:
            out.append(Finding("ghost_vendor", "critical", paid.get(v.id, 0.0),
                               f"Vendor {v.name} ({v.id}) shares details with staff; {paid.get(v.id, 0):,.0f} paid", hits))
    return out


def find_round_amounts(payments, min_n: int = 5, share: float = 0.6) -> list[Finding]:
    by_v = defaultdict(list)
    for p in payments:
        by_v[p.vendor_id].append(p)
    out = []
    for vid, grp in by_v.items():
        if len(grp) >= min_n:
            r = [p for p in grp if p.amount % 1000 == 0]
            if len(r) / len(grp) >= share:
                out.append(Finding("round_amounts", "medium", sum(p.amount for p in r),
                                   f"{len(r)}/{len(grp)} payments to {vid} are exact multiples of 1,000",
                                   [f"{p.id} {p.amount:,.0f}" for p in r[:6]]))
    return out


def find_benford(payments, min_vendor_n: int = 40) -> list[Finding]:
    out = []
    chi, n = benford_chi2([p.amount for p in payments])
    if n >= 200 and chi > CHI2_P05_DF8:
        out.append(Finding("benford", "medium", 0.0, f"Portfolio first-digit distribution deviates from Benford (chi2={chi:.1f}, n={n})"))
    by_v = defaultdict(list)
    for p in payments:
        by_v[p.vendor_id].append(p.amount)
    for vid, amts in by_v.items():
        if len(amts) >= min_vendor_n:
            chi, n = benford_chi2(amts)
            if chi > CHI2_P001_DF8:
                out.append(Finding("benford", "medium", sum(amts), f"Vendor {vid} amounts violate Benford (chi2={chi:.1f}, n={n})"))
    return out


def detect_all(payments, vendors, employees, threshold: float = 50_000) -> list[Finding]:
    fs = (find_ghost_vendors(payments, vendors, employees) + find_duplicates(payments)
          + find_splits(payments, threshold) + find_round_amounts(payments) + find_benford(payments))
    return sorted(fs, key=lambda f: (SEV_RANK[f.severity], -f.exposure))
