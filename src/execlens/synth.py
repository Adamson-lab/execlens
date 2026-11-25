"""Deterministic synthetic finance data with planted anomalies (so the demo has a story)."""
from __future__ import annotations

import csv
import random
from datetime import date, timedelta
from pathlib import Path

from .forensics import Employee, Payment, Vendor

ADJ = ["Apex", "Bluewave", "Crown", "Delta", "Evergreen", "Falcon", "Granite", "Horizon", "Ivory", "Jade",
       "Keystone", "Lumen", "Meridian", "Nimbus", "Orion", "Pinnacle", "Quartz", "Redwood", "Summit", "Titan"]
NOUN = ["Systems", "Logistics", "Consulting", "Works", "Supplies", "Facilities", "Digital", "Engineering"]
CATS = ["IT", "Facilities", "Logistics", "Consulting", "Works", "Supplies"]
THRESHOLD = 50_000


def generate(seed: int = 21):
    rng = random.Random(seed)
    vendors, payments, employees = [], [], []
    employees = [Employee(f"E{i:03d}", f"ACC{rng.randint(10**9, 10**10 - 1)}", f"{rng.randint(1, 99)} Staff Lane {i}")
                 for i in range(1, 41)]
    names = [f"{a} {n} Ltd" for a in ADJ for n in NOUN]
    rng.shuffle(names)
    for i in range(1, 61):
        vendors.append(Vendor(f"V{i:03d}", names[i], CATS[i % len(CATS)], f"ACC{rng.randint(10**9, 10**10 - 1)}",
                              f"{rng.randint(100, 999)} Commerce Road {i}", critical=i in (1, 2, 5, 9, 14, 20),
                              sole_source=i in (1, 5, 14)))
    vendors[0] = Vendor("V001", "Titan Core Systems Ltd", "IT", vendors[0].bank_account, vendors[0].address, True, True)
    vendors.append(Vendor("V061", "Apex Prime Services Ltd", "Consulting", employees[16].bank_account, "9 Offshore Plaza", False, False))

    start, n = date(2026, 1, 1), 0
    approvers = [f"A{i:02d}" for i in range(1, 9)]

    def pay(vid, amt, d, inv=None, dept=None, appr=None):
        nonlocal n
        n += 1
        payments.append(Payment(f"P{n:05d}", vid, round(amt, 2), d, inv or f"INV-{vid}-{n}", dept or rng.choice(["Ops", "Finance", "Works", "IT", "HR"]),
                                appr or rng.choice(approvers)))

    for v in vendors[:60]:
        mu = 12.4 if v.id == "V001" else rng.uniform(7.5, 11.0)
        for _ in range(rng.randint(30, 70) if v.id != "V001" else 160):
            pay(v.id, rng.lognormvariate(mu, 1.8) + rng.uniform(100, 150), start + timedelta(days=rng.randint(0, 300)))
    base = list(payments)
    for p in rng.sample(base, 6):                      # duplicate payments
        pay(p.vendor_id, p.amount, p.date + timedelta(days=rng.randint(2, 6)), inv=p.invoice_no if p.id[-1] in "13579" else None,
            dept=p.department, appr=p.approver)
    for vid, d0 in (("V010", date(2026, 3, 9)), ("V023", date(2026, 7, 14))):    # split purchases under the limit
        for k in range(4):
            pay(vid, rng.uniform(12_000, 14_900), d0 + timedelta(days=k + 1), dept="Works", appr="A03")
    for k in range(14):                                # ghost vendor with round amounts
        pay("V061", rng.choice([20_000, 25_000, 30_000]), start + timedelta(days=20 * k + 5), dept="Finance", appr="A07")
    return vendors, payments, employees


def write_csvs(out: Path, vendors, payments, employees) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "payments.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["id", "vendor_id", "amount", "date", "invoice_no", "department", "approver"])
        w.writerows([[p.id, p.vendor_id, p.amount, p.date.isoformat(), p.invoice_no, p.department, p.approver] for p in payments])
    with open(out / "vendors.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["id", "name", "category", "bank_account", "address", "critical", "sole_source"])
        w.writerows([[v.id, v.name, v.category, v.bank_account, v.address, int(v.critical), int(v.sole_source)] for v in vendors])
    with open(out / "employees.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(["id", "bank_account", "address"])
        w.writerows([[e.id, e.bank_account, e.address] for e in employees])
