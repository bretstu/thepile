"""
Audit one block: recompute both measures and cross-check the datasets.

    python verify_block.py 963029

Pulls the block from the node, recomputes every component from scratch,
and — if the height is present in the CSVs — compares against what the
builders independently recorded. Two separately written code paths
agreeing is real evidence; one path agreeing with itself is not.

Prints the full arithmetic so any number on the dashboard can be traced
to specific transactions.
"""

import csv
import os
import sys

from rpc import rpc, CLIENT
from witness_classifier import classify_tx_witness
from opreturn_classifier import classify_tx as classify_opreturn

DATA = "data"


def csv_row(name, height):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return None
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if int(r["height"]) == height:
                return r
    return None


def main(height):
    block_hash = rpc("getblockhash", [height])
    block = rpc("getblock", [block_hash, 3])
    txs = block["tx"][1:]
    size = block.get("size", 0)

    envelope = content = 0
    or_bytes = or_excess = 0
    or_outputs = 0
    env_txs = []
    excess_txs = []

    for tx in txs:
        w = classify_tx_witness(tx)
        if w and w["envelope_bytes"]:
            envelope += w["envelope_bytes"]
            content += w["content_bytes"]
            env_txs.append((tx.get("txid", "")[:16], w["envelope_bytes"],
                            w["envelope_count"]))
        o = classify_opreturn(tx)
        if o:
            or_bytes += o["total_bytes"]
            or_outputs += o["opreturn_count"]
            if o["excess_bytes"]:
                or_excess += o["excess_bytes"]
                excess_txs.append((tx.get("txid", "")[:16], o["excess_bytes"],
                                   o["opreturn_count"]))

    data_bytes = envelope + or_bytes
    beyond_bytes = envelope + or_excess

    print(f"\nBLOCK {height:,}   {block_hash[:32]}...")
    print(f"  client {CLIENT}")
    print(f"  {len(txs):,} txs (coinbase excluded) | size {size:,} B")

    print(f"\n  COMPONENTS")
    print(f"    inscription envelope bytes      {envelope:>12,}")
    print(f"      (of which stored content)     {content:>12,}")
    print(f"    OP_RETURN bytes, all sizes      {or_bytes:>12,}"
          f"   in {or_outputs:,} outputs")
    print(f"    OP_RETURN beyond old allowance  {or_excess:>12,}")

    print(f"\n  MEASURE 1 — all non-monetary (pile, odometer)")
    print(f"    envelope + all OP_RETURN        {data_bytes:>12,}"
          f"   = {data_bytes / size * 100:.3f}% of block" if size else "")

    print(f"\n  MEASURE 2 — beyond old limits (tiers, pure clock)")
    print(f"    envelope + OP_RETURN excess     {beyond_bytes:>12,}"
          f"   = {beyond_bytes / size * 100:.3f}% of block" if size else "")
    print(f"    difference is ordinary OP_RETURN traffic:"
          f" {data_bytes - beyond_bytes:,} B")
    if beyond_bytes == 0:
        print(f"    -> PURE: nothing here the pre-2023 rules would have blocked")

    if env_txs:
        env_txs.sort(key=lambda x: -x[1])
        print(f"\n  TOP ENVELOPE-CARRYING TXS ({len(env_txs)} total)")
        for txid, b, n in env_txs[:6]:
            print(f"    {txid}...  {b:>9,} B  {n} envelope(s)")
    else:
        print(f"\n  No inscription envelopes in this block.")

    if excess_txs:
        print(f"\n  TXS EXCEEDING THE OLD OP_RETURN ALLOWANCE ({len(excess_txs)})")
        for txid, b, n in excess_txs[:6]:
            print(f"    {txid}...  {b:>9,} B excess  {n} output(s)")

    # ---- independent cross-check against the builders' output ----
    wb = csv_row("witness_blocks.csv", height)
    ob = csv_row("opreturn_blocks.csv", height)
    if wb or ob:
        print(f"\n  CROSS-CHECK vs CSVs (written by the builders, separate code path)")
        ok = True
        if wb:
            for label, mine, theirs in (
                ("envelope_bytes", envelope, int(wb["envelope_bytes"])),
                ("content_bytes", content, int(wb["content_bytes"])),
                ("block_size", size, int(wb["block_size"])),
            ):
                match = mine == theirs
                ok &= match
                print(f"    {label:<18}{mine:>12,}  vs {theirs:>12,}"
                      f"   {'match' if match else '*** MISMATCH ***'}")
        if ob:
            for label, mine, theirs in (
                ("or_bytes", or_bytes, int(ob["or_bytes"])),
                ("excess_bytes", or_excess, int(ob["excess_bytes"])),
            ):
                match = mine == theirs
                ok &= match
                print(f"    {label:<18}{mine:>12,}  vs {theirs:>12,}"
                      f"   {'match' if match else '*** MISMATCH ***'}")
        print(f"    {'all components agree' if ok else 'INVESTIGATE THE MISMATCH'}")
    else:
        print(f"\n  (height not in the CSVs yet — no cross-check available)")

    print(f"\n  https://mempool.space/block/{block_hash}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    main(int(sys.argv[1]))
