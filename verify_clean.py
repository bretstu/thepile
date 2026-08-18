"""
Audit the clean-block rate.

    python verify_clean.py                 rate from the CSVs, several windows
    python verify_clean.py --node 144      ALSO re-derive the last 144 blocks
                                           straight from the node
    python verify_clean.py --node 144 --list-all

WHY THIS EXISTS
---------------
The site claims a clean-block rate ("1 in N recent blocks"). Seeing two
clean blocks in an afternoon is either bad luck, a rate that has moved, or
a bug — and those three look identical from the dashboard. This tells them
apart:

  1. It recomputes the rate over several windows, so a rate that is RISING
     shows up as a disagreement between the year and the last 1,000 blocks.
  2. It runs a binomial test on what you actually saw, so "two in a few
     hours" gets a probability instead of a hunch.
  3. With --node it re-derives recent blocks from the node using the same
     classifiers the poller uses, and compares that verdict against the
     CSVs. A disagreement there is a real bug, not variance.

DEFINITION, and the one place the two halves of this project could differ:

    CLEAN = envelope_bytes == 0 AND opreturn excess_bytes == 0

export.py additionally requires tx_count > 0, because an EMPTY block is
clean by accident — nobody chose not to put data in it. The live poller
does not apply that filter, so an empty block shows CLEAN on the dashboard
while never counting toward the historical rate. This script reports empty
blocks separately so that asymmetry is visible rather than assumed.
"""

import csv
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

DATA = "data"


def load(name, cols):
    path = os.path.join(DATA, f"{name}.csv")
    if not os.path.exists(path):
        raise SystemExit(f"Missing {path}. Run the builders first.")
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out.append({c: int(r[c]) if r.get(c) not in ("", None) else 0
                        for c in cols})
    return out


def when(ts):
    return datetime.fromtimestamp(ts, timezone.utc)


def rate(rows):
    """(clean, total, one_in) over rows already filtered to non-empty."""
    n = len(rows)
    c = sum(1 for r in rows if r["clean"])
    return c, n, (round(n / c) if c else None)


def show(label, rows):
    c, n, one_in = rate(rows)
    if not n:
        print(f"  {label:<26}      no blocks")
        return
    pct = c / n * 100
    print(f"  {label:<26}{c:>6,} / {n:>7,}   {pct:>6.2f}%   "
          + (f"1 in {one_in}" if one_in else "none"))


def binom_at_least(k, n, p):
    """P(X >= k) for X ~ Binomial(n, p), computed exactly."""
    from math import comb
    return sum(comb(n, i) * p**i * (1 - p)**(n - i) for i in range(k, n + 1))


# --------------------------------------------------------------------------
# 1. THE HISTORICAL RATE, FROM THE CSVs
# --------------------------------------------------------------------------

ob = load("opreturn_blocks", ["height", "block_time", "tx_count", "excess_bytes"])
wb = load("witness_blocks", ["height", "envelope_bytes"])
wenv = {r["height"]: r["envelope_bytes"] for r in wb}

joined = []
for r in ob:
    h = r["height"]
    if h not in wenv:
        continue
    r["envelope_bytes"] = wenv[h]
    r["clean"] = (r["excess_bytes"] == 0 and wenv[h] == 0)
    joined.append(r)
joined.sort(key=lambda r: r["height"])

if not joined:
    raise SystemExit("No blocks present in BOTH CSVs — build both datasets.")

empty = [r for r in joined if r["tx_count"] == 0]
rows = [r for r in joined if r["tx_count"] > 0]

print(f"\nCOVERAGE  {len(joined):,} blocks in both datasets  "
      f"({joined[0]['height']:,} – {joined[-1]['height']:,})")
print(f"          {when(joined[0]['block_time']):%Y-%m-%d} to "
      f"{when(joined[-1]['block_time']):%Y-%m-%d}")
print(f"          {len(empty):,} empty blocks excluded "
      f"({sum(1 for r in empty if r['clean']):,} of them clean by default)")

print("\nCLEAN RATE BY WINDOW              clean /  blocks     share")
print("  " + "-" * 62)
for w in (500, 1000, 2000, 5000, 10000, 20000):
    if len(rows) >= w:
        show(f"last {w:,} blocks", rows[-w:])
show("all blocks measured", rows)

print("\nBY YEAR")
by_year = defaultdict(list)
for r in rows:
    by_year[when(r["block_time"]).year].append(r)
for y in sorted(by_year):
    show(str(y), by_year[y])

print("\nBY MONTH, LAST 8")
by_month = defaultdict(list)
for r in rows:
    by_month[when(r["block_time"]).strftime("%Y-%m")].append(r)
for m in sorted(by_month)[-8:]:
    show(m, by_month[m])

# --------------------------------------------------------------------------
# 2. THE MOST RECENT CLEAN BLOCKS — check these against what you saw
# --------------------------------------------------------------------------

recent_clean = [r for r in rows if r["clean"]][-12:]
print(f"\nMOST RECENT CLEAN BLOCKS IN THE CSVs")
if not recent_clean:
    print("  none in range")
for r in recent_clean:
    print(f"  {r['height']:>9,}  {when(r['block_time']):%Y-%m-%d %H:%M} UTC  "
          f"{r['tx_count']:>6,} txs")

# --------------------------------------------------------------------------
# 3. IS WHAT YOU SAW SURPRISING?
# --------------------------------------------------------------------------

w20 = rows[-20000:] if len(rows) >= 20000 else rows
c20, n20, one_in20 = rate(w20)
p = c20 / n20
print(f"\nWAS 'TWO IN A FEW HOURS' STRANGE?")
print(f"  using the last {n20:,} blocks: p = {p*100:.2f}%  (1 in {one_in20})")
for hours in (2, 4, 6, 12):
    n = round(hours * 6)                      # ~6 blocks an hour
    print(f"  in {hours:>2}h (~{n:>3} blocks):  P(>=1) = {binom_at_least(1,n,p)*100:>5.1f}%   "
          f"P(>=2) = {binom_at_least(2,n,p)*100:>5.1f}%   "
          f"P(>=3) = {binom_at_least(3,n,p)*100:>5.1f}%")
print("  Two clean blocks in an afternoon is ordinary if P(>=2) is not tiny.")
print("  A rate that has RISEN shows up above as the recent windows")
print("  disagreeing with the yearly figure.")

# --------------------------------------------------------------------------
# 4. OPTIONAL: RE-DERIVE FROM THE NODE
# --------------------------------------------------------------------------

if "--node" in sys.argv:
    n = int(sys.argv[sys.argv.index("--node") + 1])
    from rpc import rpc
    from witness_classifier import classify_tx_witness
    from opreturn_classifier import classify_tx as classify_opreturn

    tip = rpc("getblockcount")
    print(f"\nRE-DERIVING {n} BLOCKS FROM THE NODE  ({tip-n+1:,} – {tip:,})")
    print("  height        txs   envelope  or_excess  verdict     csv")
    print("  " + "-" * 62)
    csv_by_height = {r["height"]: r for r in joined}
    agree = disagree = 0

    for h in range(tip - n + 1, tip + 1):
        blk = rpc("getblock", [rpc("getblockhash", [h]), 3])
        txs = blk["tx"][1:]
        env = exc = 0
        for tx in txs:
            w = classify_tx_witness(tx)
            if w:
                env += w["envelope_bytes"]
            o = classify_opreturn(tx)
            if o:
                exc += o["excess_bytes"]
        clean = (env == 0 and exc == 0)
        verdict = "CLEAN" if clean else "-"
        if clean and not txs:
            verdict = "CLEAN(empty)"

        ref = csv_by_height.get(h)
        if ref is None:
            mark = "not in csv"
        elif ref["clean"] == clean:
            mark = "agrees"; agree += 1
        else:
            mark = f"DISAGREES (csv={'clean' if ref['clean'] else 'dirty'})"
            disagree += 1

        print(f"  {h:>9,} {len(txs):>6,} {env:>10,} {exc:>10,}  "
              f"{verdict:<12}{mark}")

    print(f"\n  {agree} agree, {disagree} disagree with the CSVs")
    if disagree:
        print("  A disagreement is a real bug — the builders and the live")
        print("  classifiers should never differ on the same block.")
    else:
        print("  No disagreement: the live view and the historical rate are")
        print("  measuring the same thing, so any surprise is variance or a")
        print("  genuine change in the rate.")

print()
