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
    or_bytes = or_excess = or_outside = 0
    or_outputs = 0
    insc_tx = 0
    env_txs = []
    excess_txs = []

    for tx in txs:
        w = classify_tx_witness(tx)
        has_envelope = bool(w and w["envelope_bytes"])
        if has_envelope:
            envelope += w["envelope_bytes"]
            content += w["content_bytes"]
            # Whole serialized transaction. This is the published
            # inscription measure: the transaction exists only to carry
            # the payload, so every byte of it is attributable.
            insc_tx += tx.get("size", 0)
            env_txs.append((tx.get("txid", "")[:16], w["envelope_bytes"],
                            w["envelope_count"], tx.get("size", 0)))
        o = classify_opreturn(tx)
        if o:
            or_bytes += o["total_bytes"]
            or_outputs += o["opreturn_count"]
            # Bytes inside a transaction already charged whole above are
            # not charged a second time here.
            if not has_envelope:
                or_outside += o["total_bytes"]
            if o["excess_bytes"]:
                or_excess += o["excess_bytes"]
                excess_txs.append((tx.get("txid", "")[:16], o["excess_bytes"],
                                   o["opreturn_count"]))

    # Transfers are not recomputed here: identifying them needs the tagged
    # outpoint set, which is state this one-block tool does not carry. The
    # figure below is therefore the reveal side only, and the CSV's
    # transfer_tx_bytes is printed beside it rather than folded in.
    data_bytes = insc_tx + or_outside
    beyond_bytes = envelope + or_excess

    print(f"\nBLOCK {height:,}   {block_hash[:32]}...")
    print(f"  client {CLIENT}")
    print(f"  {len(txs):,} txs (coinbase excluded) | size {size:,} B")

    print(f"\n  COMPONENTS")
    print(f"    inscription transaction bytes   {insc_tx:>12,}"
          f"   in {len(env_txs):,} txs")
    print(f"      (of which envelope)           {envelope:>12,}")
    print(f"      (of which stored content)     {content:>12,}")
    print(f"    OP_RETURN bytes, all sizes      {or_bytes:>12,}"
          f"   in {or_outputs:,} outputs")
    print(f"      (inside inscription txs)      {or_bytes - or_outside:>12,}"
          f"   deducted, already charged above")
    print(f"    OP_RETURN beyond old allowance  {or_excess:>12,}")

    print(f"\n  MEASURE 1 — all non-monetary (pile, odometer)")
    print(f"    insc txs + OP_RETURN outside    {data_bytes:>12,}"
          f"   = {data_bytes / size * 100:.3f}% of block" if size else "")
    print(f"    (reveals only — transfers need the tagged set)")

    print(f"\n  MEASURE 2 — beyond old limits (tiers, pure clock)")
    print(f"    envelope + OP_RETURN excess     {beyond_bytes:>12,}"
          f"   = {beyond_bytes / size * 100:.3f}% of block" if size else "")
    print(f"    difference is ordinary OP_RETURN traffic:"
          f" {data_bytes - beyond_bytes:,} B")
    if beyond_bytes == 0:
        print(f"    -> PURE: nothing here the pre-2023 rules would have blocked")

    if env_txs:
        env_txs.sort(key=lambda x: -x[3])
        print(f"\n  TOP ENVELOPE-CARRYING TXS ({len(env_txs)} total)")
        for txid, b, n, sz in env_txs[:6]:
            print(f"    {txid}...  {sz:>9,} B tx  {b:>9,} B envelope"
                  f"  {n} envelope(s)")
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
            ) + ((("reveal_tx_bytes", insc_tx, int(wb["reveal_tx_bytes"])),)
                 if "reveal_tx_bytes" in wb else ()):
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
        if wb and "transfer_tx_bytes" in wb:
            print(f"    {'transfer_tx_bytes':<18}{'':>12}  vs "
                  f"{int(wb['transfer_tx_bytes']):>12,}   (CSV only — needs "
                  f"the tagged set)")
        print(f"    {'all components agree' if ok else 'INVESTIGATE THE MISMATCH'}")
    else:
        print(f"\n  (height not in the CSVs yet — no cross-check available)")

    print(f"\n  https://mempool.space/block/{block_hash}\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    main(int(sys.argv[1]))
