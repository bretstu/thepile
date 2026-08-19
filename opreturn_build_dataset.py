"""
Build the OP_RETURN dataset from a Bitcoin node.

Writes three linked CSVs at different grains:

  data/opreturn_blocks.csv
                     One row per block. Totals, excess bytes, fee context.
                     This is what the time-series charts read.

  data/opreturn_protocols.csv
                     One row per (block, protocol). Enables
                     protocol-share-over-time and "who is responsible."

  data/opreturn_prefixes.csv
                     One row per (block, payload prefix). High cardinality
                     on purpose — this is the research table. Protocol tags
                     are deliberately conservative, so when you want to
                     identify the unclassified population later, group by
                     prefix here instead of re-scanning the chain.

  data/opreturn_outputs.csv
                     One row per OP_RETURN output above DETAIL_THRESHOLD,
                     with txid, size, and payload preview. This is the
                     drill-down table — every headline number traces back
                     to specific transactions you can open in an explorer.

Every file this builder writes is prefixed `opreturn_` so its origin is
obvious next to the witness pipeline's files. The one exception is
miners.csv: pool attribution is block-level metadata, not OP_RETURN
data, and other pipelines will join against it.

Join key is `height` throughout; outputs.csv also carries `txid`.

Detail rows are thresholded because storing every OP_RETURN output would
be ~1,800 rows per block. Oversized ones are rare, so the detail table
stays small while covering exactly the population the project is about.
Set DETAIL_THRESHOLD = 0 to capture everything.

Also writes:
  data/opreturn_graffiti.csv  Every decodable OP_RETURN text, labeled
                              human/bridge/json/tag. Display filters, not
                              storage.
  data/miners.csv             Pool attribution per block, with the raw
                              coinbase ASCII so tags can be re-derived
                              later without a rescan.

Usage:
    python opreturn_build_dataset.py 900000 962100         # start end
    python opreturn_build_dataset.py 900000 962100 3       # 3 prefetch workers

Every block in the range is scanned; there is no sampling mode.
    python opreturn_build_dataset.py 767400 962100 1 3     # 3 prefetch workers

Safe to interrupt. Re-running skips heights already recorded.
"""

import csv
import os
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from rpc import rpc, CLIENT
from opreturn_classifier import classify_tx, ascii_preview, LEGACY_MAX_SCRIPT_BYTES
from graffiti_classifier import opreturn_text, miner_from_coinbase, coinbase_ascii

OUTDIR = "data"
BLOCKS_CSV = os.path.join(OUTDIR, "opreturn_blocks.csv")
PROTOCOLS_CSV = os.path.join(OUTDIR, "opreturn_protocols.csv")
OUTPUTS_CSV = os.path.join(OUTDIR, "opreturn_outputs.csv")
PREFIXES_CSV = os.path.join(OUTDIR, "opreturn_prefixes.csv")
GRAFFITI_CSV = os.path.join(OUTDIR, "opreturn_graffiti.csv")
MINERS_CSV = os.path.join(OUTDIR, "miners.csv")

# Graffiti archive: every decodable OP_RETURN text, labeled by category
# (human / bridge / json / tag). Storage never gatekeeps — display does.
GRAFFITI_MAX_PER_BLOCK = 50

# Only write per-output detail rows above this script size.
# 83 = pre-v30 limit, so detail covers exactly the nonstandard population.
DETAIL_THRESHOLD = LEGACY_MAX_SCRIPT_BYTES

# Truncate stored hex so one 100KB output can't bloat the CSV.
MAX_STORED_HEX = 200

# Progress bar characters. Swap to "#" and "-" if your terminal
# renders the block glyphs as garbage.
BAR_FULL = "\u2588"
BAR_EMPTY = "\u2591"

BLOCK_FIELDS = [
    "height", "block_time", "block_hash",
    "tx_count", "block_vsize", "block_weight",
    # OP_RETURN volume
    "or_txs", "or_outputs", "or_bytes", "or_max_size",
    # the pre-v30 counterfactual
    "nonstandard_txs", "nonstandard_vsize", "excess_bytes",
    "over_by_size_txs", "over_by_count_txs",
    # fee context
    "or_fees_sat", "nonstandard_fees_sat", "block_fees_sat",
    "client",
]

PROTOCOL_FIELDS = [
    "height", "block_time", "protocol",
    "outputs", "bytes", "max_size", "over_83_outputs",
    "client",
]

OUTPUT_FIELDS = [
    "height", "block_time", "txid", "vout",
    "size_bytes", "protocol", "prefix", "tx_vsize", "tx_fee_sat",
    "tx_opreturn_count", "tx_total_bytes", "tx_excess_bytes",
    "ascii_preview", "script_hex",
]

GRAFFITI_FIELDS = [
    "height", "block_time", "txid", "vout", "category", "size_bytes", "text",
]

MINER_FIELDS = [
    # coinbase_ascii is stored raw so pool attribution can be re-derived
    # later (pool tags change) without a rescan. payout_spk is the durable
    # pool identifier (tags are spoofable; ~10% of blocks are untagged).
    # version_hex captures miner signaling (BIP-110 history, etc.).
    "height", "block_time", "miner", "coinbase_ascii",
    "payout_spk", "coinbase_value_sat", "version_hex",
]

PREFIX_FIELDS = [
    "height", "block_time", "prefix", "protocol",
    "outputs", "bytes", "max_size", "over_83_outputs",
    "sample_ascii",
]


def fetch_block(height):
    """Network-only step, safe to run on prefetch threads."""
    block_hash = rpc("getblockhash", [height])
    return height, block_hash, rpc("getblock", [block_hash, 2])


def analyze_block(height, block_hash=None, block=None):
    """Return the per-grain row sets for one height."""
    if block is None:
        _, block_hash, block = fetch_block(height)

    # Skip the coinbase. Its OP_RETURN is the SegWit witness commitment,
    # which is protocol machinery, not data carriage.
    txs = block["tx"][1:]
    t = block["time"]

    block_vsize = block_weight = block_fees = 0
    or_txs = or_outputs = or_bytes = or_max = 0
    nonstd_txs = nonstd_vsize = excess = 0
    over_size = over_count = 0
    or_fees = nonstd_fees = 0

    protos = {}
    prefixes = {}
    output_rows = []
    graffiti_rows = []

    cb_vouts = block["tx"][0].get("vout", []) if block.get("tx") else []
    payout_spk = next(
        (v.get("scriptPubKey", {}).get("hex", "")
         for v in cb_vouts
         if v.get("value", 0) > 0
         and not v.get("scriptPubKey", {}).get("hex", "").startswith("6a")),
        "")
    miner_row = {
        "height": height, "block_time": t,
        "miner": miner_from_coinbase(block),
        "coinbase_ascii": coinbase_ascii(block),
        "payout_spk": payout_spk,
        "coinbase_value_sat": int(round(
            sum(v.get("value", 0) for v in cb_vouts) * 1e8)),
        "version_hex": block.get("versionHex", ""),
    }

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

        for o in c["outputs"]:
            if len(graffiti_rows) < GRAFFITI_MAX_PER_BLOCK:
                cat, text = opreturn_text(o["hex"])
                if cat:
                    graffiti_rows.append({
                        "height": height, "block_time": t,
                        "txid": c["txid"], "vout": o["vout"],
                        "category": cat, "size_bytes": o["size"],
                        "text": text,
                    })
            p = protos.setdefault(
                o["protocol"], {"n": 0, "bytes": 0, "max": 0, "over": 0}
            )
            p["n"] += 1
            p["bytes"] += o["size"]
            p["max"] = max(p["max"], o["size"])
            if o["size"] > LEGACY_MAX_SCRIPT_BYTES:
                p["over"] += 1

            k = (o["prefix"], o["protocol"])
            q = prefixes.setdefault(
                k, {"n": 0, "bytes": 0, "max": 0, "over": 0, "ascii": ""}
            )
            q["n"] += 1
            q["bytes"] += o["size"]
            q["max"] = max(q["max"], o["size"])
            if o["size"] > LEGACY_MAX_SCRIPT_BYTES:
                q["over"] += 1
            if not q["ascii"]:
                q["ascii"] = ascii_preview(o["hex"], 24)

            if o["size"] > DETAIL_THRESHOLD:
                output_rows.append({
                    "height": height,
                    "block_time": t,
                    "txid": c["txid"],
                    "vout": o["vout"],
                    "size_bytes": o["size"],
                    "protocol": o["protocol"],
                    "prefix": o["prefix"],
                    "tx_vsize": c["vsize"],
                    "tx_fee_sat": c["fee_sat"],
                    "tx_opreturn_count": c["opreturn_count"],
                    "tx_total_bytes": c["total_bytes"],
                    "tx_excess_bytes": c["excess_bytes"],
                    "ascii_preview": ascii_preview(o["hex"]),
                    "script_hex": o["hex"][:MAX_STORED_HEX],
                })

    block_row = {
        "height": height,
        "block_time": t,
        "block_hash": block_hash,
        "tx_count": len(txs),
        "block_vsize": block_vsize,
        "block_weight": block_weight,
        "or_txs": or_txs,
        "or_outputs": or_outputs,
        "or_bytes": or_bytes,
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

    protocol_rows = [
        {
            "height": height,
            "block_time": t,
            "protocol": name,
            "outputs": v["n"],
            "bytes": v["bytes"],
            "max_size": v["max"],
            "over_83_outputs": v["over"],
            "client": CLIENT,
        }
        for name, v in sorted(protos.items())
    ]

    prefix_rows = [
        {
            "height": height,
            "block_time": t,
            "prefix": pfx,
            "protocol": proto,
            "outputs": v["n"],
            "bytes": v["bytes"],
            "max_size": v["max"],
            "over_83_outputs": v["over"],
            "sample_ascii": v["ascii"],
        }
        for (pfx, proto), v in sorted(prefixes.items())
    ]

    return (block_row, protocol_rows, output_rows, prefix_rows,
            graffiti_rows, miner_row)


def done_heights():
    if not os.path.exists(BLOCKS_CSV):
        return set()
    with open(BLOCKS_CSV, newline="") as f:
        return {int(r["height"]) for r in csv.DictReader(f)}


def _writer(path, fields):
    """Open in append mode, writing the header only on first creation."""
    fresh = not os.path.exists(path)
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


def build(start, end, workers=3):
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
    print(f"To scan: {len(targets):,}  (already have {len(already):,})\n")

    if not targets:
        print("Nothing to do.")
        return

    bf, bw = _writer(BLOCKS_CSV, BLOCK_FIELDS)
    pf, pw = _writer(PROTOCOLS_CSV, PROTOCOL_FIELDS)
    of, ow = _writer(OUTPUTS_CSV, OUTPUT_FIELDS)
    xf, xw = _writer(PREFIXES_CSV, PREFIX_FIELDS)
    gf, gw = _writer(GRAFFITI_CSV, GRAFFITI_FIELDS)
    mf, mw = _writer(MINERS_CSV, MINER_FIELDS)

    t0 = time.time()
    detail_total = 0
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
            brow, prows, orows, xrows, grows, mrow = \
                analyze_block(height, bhash, block)
            bw.writerow(brow)
            pw.writerows(prows)
            ow.writerows(orows)
            xw.writerows(xrows)
            gw.writerows(grows)
            mw.writerow(mrow)
            for f in (bf, pf, of, xf, gf, mf):
                f.flush()  # survive an interrupt

            detail_total += len(orows)
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
        for f in (bf, pf, of, xf, gf, mf):
            f.close()

    print()  # move off the progress bar line
    print(f"Wrote {detail_total:,} detail rows to {OUTPUTS_CSV}")
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
            f"  Use: python opreturn_build_dataset.py {a} {b} 3\n")
    w = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    build(a, b, w)
