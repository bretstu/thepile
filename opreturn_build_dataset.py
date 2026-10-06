"""
Build the OP_RETURN dataset from a Bitcoin node.

Writes one CSV:

  data/opreturn_blocks.csv
                     One row per block. OP_RETURN bytes at script and
                     stored size, counts, the pre-v30 policy figures
                     (kept in the data, shown nowhere), fee context, and
                     the block's serialized size — which, because this
                     scan runs from genesis, is the whole-chain
                     denominator for the scale bar.

Usage:
    python opreturn_build_dataset.py 900000 962100         # start end
    python opreturn_build_dataset.py 900000 962100 6       # 6 prefetch workers

Every block in the range is scanned; there is no sampling mode. Argument
three is the worker count, and only overlaps the RPC fetch — classification
and writing stay strictly in height order.

Safe to interrupt. Re-running skips heights already recorded.
"""

import csv
import os
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from rpc import rpc, CLIENT
from opreturn_classifier import classify_tx

OUTDIR = "data"
BLOCKS_CSV = os.path.join(OUTDIR, "opreturn_blocks.csv")

# Progress bar characters. Swap to "#" and "-" if your terminal
# renders the block glyphs as garbage.
BAR_FULL = "\u2588"
BAR_EMPTY = "\u2591"

BLOCK_FIELDS = [
    "height", "block_time", "block_hash",
    "tx_count", "block_vsize", "block_weight",
    # Serialized block size, straight from the node. Cheap to record here
    # and impossible to add later without another full scan — and it is
    # the only honest denominator for "what share of the chain is this",
    # since size_on_disk counts undo files the chain does not contain.
    "block_size", "block_strippedsize",
    # OP_RETURN volume
    "or_txs", "or_outputs", "or_bytes", "or_stored_bytes", "or_max_size",
    # the pre-v30 counterfactual
    "nonstandard_txs", "nonstandard_vsize", "excess_bytes",
    "over_by_size_txs", "over_by_count_txs",
    # fee context
    "or_fees_sat", "nonstandard_fees_sat", "block_fees_sat",
    "client",
]

def fetch_block(height):
    """Network-only step, safe to run on prefetch threads."""
    block_hash = rpc("getblockhash", [height])
    return height, block_hash, rpc("getblock", [block_hash, 2])


def analyze_block(height, block_hash=None, block=None):
    """Return the block's row."""
    if block is None:
        _, block_hash, block = fetch_block(height)

    # Skip the coinbase. Its OP_RETURN is the SegWit witness commitment,
    # which is protocol machinery, not data carriage.
    txs = block["tx"][1:]
    t = block["time"]

    block_vsize = block_weight = block_fees = 0
    or_txs = or_outputs = or_bytes = or_max = 0
    or_stored = 0
    nonstd_txs = nonstd_vsize = excess = 0
    over_size = over_count = 0
    or_fees = nonstd_fees = 0

    for tx in txs:
        block_vsize += tx.get("vsize", 0)
        block_weight += tx.get("weight", 0)
        if tx.get("fee") is not None:
            block_fees += int(round(tx["fee"] * 1e8))

        c = classify_tx(tx)
        if c is None:
            continue

        or_txs += 1
        or_outputs += c["opreturn_count"]
        or_bytes += c["total_bytes"]
        or_stored += c["stored_bytes"]
        or_max = max(or_max, c["max_output_bytes"])
        excess += c["excess_bytes"]
        if c["fee_sat"]:
            or_fees += c["fee_sat"]

        if not c["standard_pre_v30"]:
            nonstd_txs += 1
            nonstd_vsize += c["vsize"]
            if c["fee_sat"]:
                nonstd_fees += c["fee_sat"]
        over_size += c["over_by_size"]
        over_count += c["over_by_count"]

    return {
        "height": height,
        "block_time": t,
        "block_hash": block_hash,
        "tx_count": len(txs),
        "block_vsize": block_vsize,
        "block_weight": block_weight,
        "block_size": block.get("size", 0),
        "block_strippedsize": block.get("strippedsize", 0),
        "or_txs": or_txs,
        "or_outputs": or_outputs,
        "or_bytes": or_bytes,
        "or_stored_bytes": or_stored,
        "or_max_size": or_max,
        "nonstandard_txs": nonstd_txs,
        "nonstandard_vsize": nonstd_vsize,
        "excess_bytes": excess,
        "over_by_size_txs": over_size,
        "over_by_count_txs": over_count,
        "or_fees_sat": or_fees,
        "nonstandard_fees_sat": nonstd_fees,
        "block_fees_sat": block_fees,
        "client": CLIENT,
    }


def done_heights():
    if not os.path.exists(BLOCKS_CSV):
        return set()
    with open(BLOCKS_CSV, newline="") as f:
        return {int(r["height"]) for r in csv.DictReader(f)}


def _writer(path, fields):
    """Append-mode writer, refusing to append a different schema.

    DictWriter emits values in `fields` order regardless of what header
    the file already carries, so appending after a column is added
    produces a file whose rows are silently shifted against its own
    header — readable, plausible, and wrong in every column past the
    insertion point.
    """
    fresh = not os.path.exists(path)
    if not fresh:
        with open(path, newline="", encoding="utf-8") as chk:
            header = next(csv.reader(chk), [])
        if header and header != list(fields):
            added = [c for c in fields if c not in header]
            gone = [c for c in header if c not in fields]
            raise SystemExit(
                f"\n{path} was written with a different set of columns.\n"
                + (f"  new: {', '.join(added)}\n" if added else "")
                + (f"  missing: {', '.join(gone)}\n" if gone else "")
                + "Appending would shift every row against the header.\n"
                  "Move data/ aside and rebuild, or re-run against a copy."
            )
    f = open(path, "a", newline="", encoding="utf-8")
    w = csv.DictWriter(f, fieldnames=fields)
    if fresh:
        w.writeheader()
    return f, w


def render_progress(i, total, height, rate, nonstd_total, excess_total):
    """Single-line progress bar that overwrites itself in place."""
    frac = i / total
    filled = int(frac * 30)
    bar = BAR_FULL * filled + BAR_EMPTY * (30 - filled)
    eta_s = (total - i) / rate if rate else 0
    eta = f"{eta_s / 60:.1f}m" if eta_s >= 60 else f"{eta_s:.0f}s"
    line = (
        f"\r  {bar} {frac * 100:5.1f}%  "
        f"{i:>4}/{total}  blk {height:,}  "
        f"{rate:.1f}/s  eta {eta:>6}  "
        f"nonstd {nonstd_total:,}  excess {excess_total:,}B"
    )
    # Pad so a shorter line can't leave characters from a longer one behind.
    print(line.ljust(118), end="", flush=True)


def build(start, end, workers=5):
    os.makedirs(OUTDIR, exist_ok=True)

    tip = rpc("getblockcount")
    if end > tip:
        print(f"Note: end {end:,} above tip {tip:,}; clamping.")
        end = tip

    already = done_heights()
    targets = [h for h in range(start, end + 1) if h not in already]

    print(f"Client:  {CLIENT}")
    print(f"Tip:     {tip:,}")
    print(f"Range:   {start:,} - {end:,}  (every block)")
    print(f"Workers: {workers} (prefetch; classification stays in-order)")
    if workers > 8:
        print(f"         NOTE: {workers * 2} decoded blocks are held in memory "
              f"at once.\n         Above ~8 workers that is usually the "
              f"binding constraint, not the node.")
    print(f"To scan: {len(targets):,}  (already have {len(already):,})\n")

    if not targets:
        print("Nothing to do.")
        return

    bf, bw = _writer(BLOCKS_CSV, BLOCK_FIELDS)

    t0 = time.time()
    nonstd_running = 0
    excess_running = 0

    # Prefetch pipeline: worker threads fetch upcoming blocks over RPC
    # while THIS thread classifies and writes strictly in height order.
    ex = ThreadPoolExecutor(max_workers=max(1, workers))
    futures = deque()
    next_idx = 0

    def top_up():
        nonlocal next_idx
        while next_idx < len(targets) and len(futures) < max(1, workers) * 2:
            futures.append(ex.submit(fetch_block, targets[next_idx]))
            next_idx += 1

    top_up()
    try:
        i = 0
        while futures:
            height, bhash, block = futures.popleft().result()
            top_up()
            i += 1
            brow = analyze_block(height, bhash, block)
            bw.writerow(brow)
            bf.flush()  # survive an interrupt

            nonstd_running += brow["nonstandard_txs"]
            excess_running += brow["excess_bytes"]
            rate = i / (time.time() - t0)

            # Blocks containing something over the legacy limit get a
            # permanent line above the bar, so the scroll history becomes
            # a log of exactly the blocks this project is about.
            if brow["excess_bytes"] > 0:
                print("\r" + " " * 118 + "\r", end="")
                print(
                    f"  -> {height:,}  "
                    f"{brow['nonstandard_txs']} nonstandard tx, "
                    f"{brow['excess_bytes']:,} excess bytes, "
                    f"max {brow['or_max_size']:,}B"
                )

            render_progress(i, len(targets), height, rate,
                            nonstd_running, excess_running)
    except KeyboardInterrupt:
        print("\n\nInterrupted. Progress saved; rerun to resume.")
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
        bf.close()

    print()  # move off the progress bar line
    print(f"Totals: {nonstd_running:,} nonstandard txs, "
          f"{excess_running:,} excess bytes")
    print(f"Done in {(time.time() - t0) / 60:.1f} min")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(1)
    a = int(sys.argv[1])
    b = int(sys.argv[2])
    if len(sys.argv) > 3 and int(sys.argv[3]) > 16:
        raise SystemExit(
            f"\nArgument 3 is now the worker count, not a sampling step.\n"
            f"  {sys.argv[3]} looks like an old step value. Sampling was "
            f"removed; every block is scanned.\n"
            f"  Use: python opreturn_build_dataset.py {a} {b} 5\n")
    w = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    build(a, b, w)
