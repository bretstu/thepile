"""
Query and drill into the OP_RETURN dataset.

    python opreturn_explore.py summary            headline numbers, pre/post v30
    python opreturn_explore.py monthly            month-by-month trend table
    python opreturn_explore.py protocols          protocol leaderboard
    python opreturn_explore.py timeline           when each protocol first appeared
    python opreturn_explore.py top [n]            largest OP_RETURN outputs
    python opreturn_explore.py block <height>     everything about one block
    python opreturn_explore.py tx <txid>          everything about one transaction
    python opreturn_explore.py unknown [n]        biggest unclassified prefixes

Reads data/*.csv. No node required.
"""

import csv
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

DATA = "data"
V30_DATE = datetime(2025, 10, 10, tzinfo=timezone.utc)  # Bitcoin Core v30

INT_COLS = {
    "height", "block_time", "tx_count", "block_vsize", "block_weight",
    "or_txs", "or_outputs", "or_bytes", "or_max_size", "nonstandard_txs",
    "nonstandard_vsize", "excess_bytes", "over_by_size_txs",
    "over_by_count_txs", "or_fees_sat", "nonstandard_fees_sat",
    "block_fees_sat", "outputs", "bytes", "max_size", "over_83_outputs",
    "vout", "size_bytes", "tx_vsize", "tx_fee_sat", "tx_opreturn_count",
    "tx_total_bytes", "tx_excess_bytes",
}


def load(name):
    path = os.path.join(DATA, f"{name}.csv")
    if not os.path.exists(path):
        raise SystemExit(f"Missing {path}. Run opreturn_build_dataset.py first.")
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            for k, v in r.items():
                if k in INT_COLS:
                    r[k] = int(v) if v not in ("", None) else 0
            rows.append(r)
    return rows


def when(ts):
    return datetime.fromtimestamp(ts, timezone.utc)


def month(ts):
    return when(ts).strftime("%Y-%m")


def pct(a, b):
    return f"{a / b * 100:.4f}%" if b else "n/a"


# --------------------------------------------------------------------------

def cmd_summary():
    b = load("opreturn_blocks")
    pre = [r for r in b if when(r["block_time"]) < V30_DATE]
    post = [r for r in b if when(r["block_time"]) >= V30_DATE]

    print(f"\n{len(b):,} blocks | {when(min(r['block_time'] for r in b)):%Y-%m-%d}"
          f" to {when(max(r['block_time'] for r in b)):%Y-%m-%d}")
    print(f"Sampled, not exhaustive — check the step used in build_dataset.\n")

    for label, g in (("PRE-v30", pre), ("POST-v30", post)):
        if not g:
            continue
        txs = sum(r["tx_count"] for r in g)
        vsize = sum(r["block_vsize"] for r in g)
        print(f"--- {label}  ({len(g):,} blocks) ---")
        print(f"  transactions            {txs:>14,}")
        print(f"  with OP_RETURN          {sum(r['or_txs'] for r in g):>14,}"
              f"  ({pct(sum(r['or_txs'] for r in g), txs)})")
        print(f"  OP_RETURN outputs       {sum(r['or_outputs'] for r in g):>14,}")
        print(f"  OP_RETURN bytes         {sum(r['or_bytes'] for r in g):>14,}"
              f"  ({pct(sum(r['or_bytes'] for r in g), vsize)} of vsize)")
        print(f"  nonstandard pre-v30 txs {sum(r['nonstandard_txs'] for r in g):>14,}"
              f"  ({pct(sum(r['nonstandard_txs'] for r in g), txs)})")
        print(f"  EXCESS BYTES            {sum(r['excess_bytes'] for r in g):>14,}"
              f"  ({pct(sum(r['excess_bytes'] for r in g), vsize)} of vsize)")
        print(f"  fees paid, nonstandard  {sum(r['nonstandard_fees_sat'] for r in g):>14,} sat")
        print(f"  blocks w/ any excess    {sum(1 for r in g if r['excess_bytes']):>14,}"
              f"  ({pct(sum(1 for r in g if r['excess_bytes']), len(g))})")
        print()

    print("EXCESS BYTES = OP_RETURN scriptPubKey bytes beyond what pre-v30")
    print("default relay policy permitted (one output, 83 bytes).")
    print("This is NOT 'bytes that would not exist' — see opreturn_classifier.py.\n")


def cmd_monthly():
    b = load("opreturn_blocks")
    m = defaultdict(lambda: defaultdict(int))
    for r in b:
        k = month(r["block_time"])
        for f in ("tx_count", "block_vsize", "or_txs", "or_outputs",
                  "or_bytes", "nonstandard_txs", "excess_bytes",
                  "over_by_size_txs", "over_by_count_txs"):
            m[k][f] += r[f]
        m[k]["blocks"] += 1
        m[k]["max"] = max(m[k]["max"], r["or_max_size"])

    print(f"\n{'month':<9}{'blks':>6}{'or_bytes':>11}{'or%vsz':>8}"
          f"{'nonstd':>8}{'excess_B':>11}{'bysize':>8}{'bycount':>9}{'max_B':>9}")
    print("-" * 79)
    for k in sorted(m):
        d = m[k]
        marker = "  <- v30" if k == "2025-10" else ""
        print(f"{k:<9}{d['blocks']:>6}{d['or_bytes']:>11,}"
              f"{d['or_bytes']/d['block_vsize']*100:>7.2f}%"
              f"{d['nonstandard_txs']:>8,}{d['excess_bytes']:>11,}"
              f"{d['over_by_size_txs']:>8,}{d['over_by_count_txs']:>9,}"
              f"{d['max']:>9,}{marker}")
    print()


def cmd_protocols():
    p = load("opreturn_protocols")
    agg = defaultdict(lambda: defaultdict(int))
    for r in p:
        a = agg[r["protocol"]]
        a["outputs"] += r["outputs"]
        a["bytes"] += r["bytes"]
        a["over"] += r["over_83_outputs"]
        a["max"] = max(a["max"], r["max_size"])
        a["blocks"] += 1

    total = sum(a["bytes"] for a in agg.values())
    print(f"\n{'protocol':<18}{'outputs':>11}{'bytes':>13}{'share':>8}"
          f"{'over83':>9}{'max_B':>9}{'blocks':>8}")
    print("-" * 76)
    for name, a in sorted(agg.items(), key=lambda kv: -kv[1]["bytes"])[:25]:
        print(f"{name:<18}{a['outputs']:>11,}{a['bytes']:>13,}"
              f"{a['bytes']/total*100:>7.1f}%{a['over']:>9,}"
              f"{a['max']:>9,}{a['blocks']:>8,}")
    print(f"\n{len(agg)} distinct protocol tags. Tags are heuristic —")
    print("treat unfamiliar ones as unclassified rather than asserting.\n")


def cmd_timeline():
    """First and last appearance of each protocol that ever exceeded 83 bytes."""
    p = load("opreturn_protocols")
    seen = defaultdict(lambda: {"first": None, "last": None, "over": 0})
    for r in p:
        s = seen[r["protocol"]]
        t = r["block_time"]
        s["first"] = t if s["first"] is None else min(s["first"], t)
        s["last"] = max(s["last"] or 0, t)
        s["over"] += r["over_83_outputs"]

    rows = [(n, v) for n, v in seen.items() if v["over"] > 0]
    rows.sort(key=lambda kv: kv[1]["first"])

    print(f"\nPROTOCOLS THAT PRODUCED OVERSIZED (>83B) OUTPUTS")
    print(f"{'protocol':<18}{'first seen':<13}{'last seen':<13}{'oversized':>11}")
    print("-" * 55)
    for name, v in rows:
        print(f"{name:<18}{when(v['first']):%Y-%m-%d}   "
              f"{when(v['last']):%Y-%m-%d}   {v['over']:>10,}")
    print("\nFirst-seen is bounded by your sampling step — a protocol may")
    print("predate the first block you happened to scan.\n")


def cmd_top(n=20):
    n = int(n)  # argv values arrive as strings
    o = load("opreturn_outputs")
    o.sort(key=lambda r: -r["size_bytes"])
    print(f"\n{'height':>9}  {'date':<11}{'size':>8}{'proto':>12}  {'preview':<30} txid")
    print("-" * 118)
    for r in o[:n]:
        print(f"{r['height']:>9,}  {when(r['block_time']):%Y-%m-%d} "
              f"{r['size_bytes']:>8,}{r['protocol']:>12}  "
              f"{r['ascii_preview'][:30]:<30} {r['txid'][:20]}...")
    print()


def cmd_block(height):
    height = int(height)
    b = next((r for r in load("opreturn_blocks") if r["height"] == height), None)
    if not b:
        raise SystemExit(f"Block {height:,} not in dataset.")

    print(f"\nBLOCK {height:,}   {when(b['block_time']):%Y-%m-%d %H:%M:%S} UTC")
    print(f"  hash {b['block_hash']}")
    print(f"  {b['tx_count']:,} txs | {b['block_vsize']:,} vB | "
          f"{b['block_fees_sat']:,} sat fees")
    print(f"\n  OP_RETURN")
    print(f"    txs                {b['or_txs']:>10,}")
    print(f"    outputs            {b['or_outputs']:>10,}")
    print(f"    bytes              {b['or_bytes']:>10,}")
    print(f"    largest output     {b['or_max_size']:>10,} B")
    print(f"\n  PRE-v30 COUNTERFACTUAL")
    print(f"    nonstandard txs    {b['nonstandard_txs']:>10,}")
    print(f"    excess bytes       {b['excess_bytes']:>10,}")
    print(f"    over by size       {b['over_by_size_txs']:>10,}")
    print(f"    over by count      {b['over_by_count_txs']:>10,}")
    print(f"    fees they paid     {b['nonstandard_fees_sat']:>10,} sat")

    ps = [r for r in load("opreturn_protocols") if r["height"] == height]
    if ps:
        print(f"\n  PROTOCOLS")
        for r in sorted(ps, key=lambda r: -r["bytes"]):
            print(f"    {r['protocol']:<16}{r['outputs']:>7,} outputs "
                  f"{r['bytes']:>9,} B  max {r['max_size']:>6,}")

    os_ = [r for r in load("opreturn_outputs") if r["height"] == height]
    if os_:
        print(f"\n  OVERSIZED OUTPUTS ({len(os_)})")
        for r in sorted(os_, key=lambda r: -r["size_bytes"]):
            print(f"    {r['size_bytes']:>7,} B  {r['protocol']:<12} "
                  f"vout[{r['vout']}]  {r['ascii_preview'][:34]}")
            print(f"             {r['txid']}")
    print()


def cmd_tx(txid):
    rows = [r for r in load("opreturn_outputs") if r["txid"].startswith(txid)]
    if not rows:
        raise SystemExit(f"No detail rows for {txid}. Only oversized "
                         f"outputs are stored — see DETAIL_THRESHOLD.")
    r0 = rows[0]
    print(f"\nTX {r0['txid']}")
    print(f"  block {r0['height']:,}  {when(r0['block_time']):%Y-%m-%d %H:%M} UTC")
    print(f"  vsize {r0['tx_vsize']:,} vB | fee {r0['tx_fee_sat'] or 0:,} sat")
    print(f"  {r0['tx_opreturn_count']} OP_RETURN outputs, "
          f"{r0['tx_total_bytes']:,} B total, "
          f"{r0['tx_excess_bytes']:,} B beyond pre-v30 policy")
    print(f"\n  OVERSIZED OUTPUTS")
    for r in sorted(rows, key=lambda r: r["vout"]):
        print(f"    vout[{r['vout']}]  {r['size_bytes']:>7,} B  {r['protocol']}")
        print(f"      ascii: {r['ascii_preview']}")
        print(f"      hex:   {r['script_hex'][:80]}...")
    print(f"\n  https://mempool.space/tx/{r0['txid']}\n")


def cmd_unknown(n=25):
    """Biggest unclassified payload prefixes — the identification worklist.

    Protocol tags are deliberately conservative, so most traffic lands in
    a bucket. This ranks the raw prefixes inside those buckets by volume,
    so identification effort goes to whatever actually matters. Work down
    this list and promote confident findings into KNOWN_PAYLOAD_PREFIXES
    in opreturn_classifier.py.
    """
    n = int(n)
    rows = load("opreturn_prefixes")
    agg = defaultdict(lambda: defaultdict(int))
    sample = {}
    for r in rows:
        if not r["protocol"].startswith(("unclassified", "json", "marker", "empty")):
            continue
        k = (r["prefix"], r["protocol"])
        agg[k]["outputs"] += r["outputs"]
        agg[k]["bytes"] += r["bytes"]
        agg[k]["over"] += r["over_83_outputs"]
        agg[k]["max"] = max(agg[k]["max"], r["max_size"])
        agg[k]["blocks"] += 1
        first = agg[k].get("first") or r["block_time"]
        agg[k]["first"] = min(first, r["block_time"])
        if k not in sample and r["sample_ascii"].strip("."):
            sample[k] = r["sample_ascii"]

    ranked = sorted(agg.items(), key=lambda kv: -kv[1]["bytes"])
    total = sum(v["bytes"] for v in agg.values())

    print(f"\nUNCLASSIFIED PAYLOAD PREFIXES BY VOLUME")
    print(f"{len(agg):,} distinct prefixes, {total:,} bytes total\n")
    print(f"{'prefix':<14}{'bucket':<21}{'outputs':>10}{'bytes':>11}"
          f"{'over83':>8}{'blks':>6}  {'first':<11}{'ascii'}")
    print("-" * 104)
    for (pfx, proto), v in ranked[:n]:
        print(f"{pfx:<14}{proto:<21}{v['outputs']:>10,}{v['bytes']:>11,}"
              f"{v['over']:>8,}{v['blocks']:>6,}  "
              f"{when(v['first']):%Y-%m-%d} {sample.get((pfx, proto), '')[:22]}")
    print("\nPromote confident identifications into KNOWN_PAYLOAD_PREFIXES")
    print("in opreturn_classifier.py, then rebuild. Leave the rest bucketed.\n")


COMMANDS = {
    "summary": cmd_summary, "monthly": cmd_monthly, "unknown": cmd_unknown,
    "protocols": cmd_protocols, "timeline": cmd_timeline,
    "top": cmd_top, "block": cmd_block, "tx": cmd_tx,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        raise SystemExit(1)
    COMMANDS[sys.argv[1]](*sys.argv[2:])
