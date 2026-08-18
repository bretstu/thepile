"""
Find blocks that carried ZERO non-monetary bytes.

    python find_pure_blocks.py

Joins opreturn_blocks.csv and witness_blocks.csv on height and reports
every block where or_bytes == 0 AND envelope_bytes == 0 — a block whose
entire contents were monetary.

Only heights present in BOTH datasets can be judged, so while the witness
scan is still running the answer covers the overlap, not the full range.
That overlap is reported explicitly rather than assumed.
"""

import csv
import os
from datetime import datetime, timezone

DATA = "data"


def load(name, cols):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        raise SystemExit(f"Missing {path}. Run the builders first.")
    out = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out[int(r["height"])] = {c: int(r[c] or 0) for c in cols}
    return out


def main():
    orb = load("opreturn_blocks.csv", ["block_time", "or_bytes", "tx_count"])
    wit = load("witness_blocks.csv", ["block_time", "envelope_bytes",
                                      "block_size"])

    both = sorted(set(orb) & set(wit))
    if not both:
        raise SystemExit("No overlapping heights between the two datasets yet.")

    print(f"\nOverlap: {len(both):,} blocks  "
          f"({both[0]:,} - {both[-1]:,})")
    print(f"  opreturn dataset: {len(orb):,} blocks")
    print(f"  witness dataset:  {len(wit):,} blocks")

    # Empty blocks (no transactions) are mined before validation finishes.
    # They are pure by accident, not by demand, so they are counted
    # separately — mixing them in overstates how often real clean blocks
    # occur.
    pure, empty, near = [], [], []
    for h in both:
        data = orb[h]["or_bytes"] + wit[h]["envelope_bytes"]
        if data == 0:
            (empty if orb[h]["tx_count"] == 0 else pure).append(h)
        elif data < 1000:
            near.append((h, data))

    now = datetime.now(timezone.utc)

    # If one dataset extends well past the other, "most recent" is an
    # artifact of the scan frontier, not a fact about the chain.
    frontier_gap = max(orb) - both[-1]
    if frontier_gap > 100:
        print(f"\n  ** The overlap ends at {both[-1]:,}, but the OP_RETURN")
        print(f"     dataset reaches {max(orb):,} — {frontier_gap:,} blocks")
        print(f"     beyond. 'Most recent' below is the scan frontier, NOT")
        print(f"     a finding. Re-run when the witness scan completes. **")

    total_zero = len(pure) + len(empty)
    print(f"\nZERO NON-MONETARY BYTES: {total_zero:,}"
          f"  ({total_zero / len(both) * 100:.4f}% of the overlap)")
    print(f"  empty blocks (0 txs, mining artifact)   {len(empty):>8,}")
    print(f"  REAL CLEAN BLOCKS (>=1 tx, no data)     {len(pure):>8,}"
          f"  ({len(pure) / len(both) * 100:.4f}%)")

    if pure:
        print(f"\n{'height':>10}  {'date':<20}{'txs':>8}  age")
        print("-" * 56)
        for h in pure[-15:]:
            t = datetime.fromtimestamp(orb[h]["block_time"], timezone.utc)
            age = (now - t).days
            print(f"{h:>10,}  {t:%Y-%m-%d %H:%M} UTC  "
                  f"{orb[h]['tx_count']:>7,}  {age:,} days ago")
        last = pure[-1]
        t = datetime.fromtimestamp(orb[last]["block_time"], timezone.utc)
        print(f"\nMost recent clean block: {last:,} — "
              f"{(now - t).days:,} days ago ({t:%Y-%m-%d})")
    else:
        print("\n  None. Every block in the overlap carried non-monetary data.")

    print(f"\nNEAR-PURE (under 1,000 bytes): {len(near):,}")
    for h, d in near[-8:]:
        t = datetime.fromtimestamp(orb[h]["block_time"], timezone.utc)
        print(f"  {h:>10,}  {t:%Y-%m-%d}  {d:>6,} B")

    # yearly breakdown — when did clean blocks stop happening?
    by_year = {}
    pure_set, empty_set = set(pure), set(empty)
    for h in both:
        y = datetime.fromtimestamp(orb[h]["block_time"], timezone.utc).year
        d = by_year.setdefault(y, {"n": 0, "clean": 0, "empty": 0})
        d["n"] += 1
        if h in pure_set:
            d["clean"] += 1
        elif h in empty_set:
            d["empty"] += 1

    print(f"\n{'year':<7}{'blocks':>10}{'clean':>8}{'share':>10}{'empty':>8}")
    print("-" * 44)
    for y in sorted(by_year):
        d = by_year[y]
        print(f"{y:<7}{d['n']:>10,}{d['clean']:>8,}"
              f"{d['clean'] / d['n'] * 100:>9.4f}%{d['empty']:>8,}")
    print("\nclean = at least one transaction and zero non-monetary bytes.")
    print("empty = no transactions at all; a mining artifact, not demand.\n")


if __name__ == "__main__":
    main()
