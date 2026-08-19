"""
Build the witness/inscription dataset from a Bitcoin node.

Companion to build_dataset.py (OP_RETURN). Same philosophy: linked CSVs
at different grains, exact byte accounting, resumable, provenance on
every row.

  data/witness_blocks.csv   One row per block. The time-series source.
                            Includes the accounting buckets AND the
                            node-reported size/strippedsize, so the
                            parser can be validated against an
                            independent measure on every single block.

  data/witness_content_types.csv
                            One row per (block, protocol, content_type).
                            "What is stored on Bitcoin" — images vs text
                            vs JSON — over time.

  data/witness_inscription_details.csv
                            One row per envelope with content above
                            DETAIL_CONTENT_BYTES. Drill-down with txid.

REQUIRES getblock verbosity 3 (Bitcoin Core/Knots 25.0+), which includes
each input's prevout. Checked at startup with a clear error.

Also writes data/witness_graffiti.csv: every decodable text/plain
inscription body (JSON mints excluded — already counted in types),
labeled human/bridge/tag. Display layers choose what to show.

Usage:
    python witness_build_dataset.py 767400 962100
    python witness_build_dataset.py 767400 962100 3        # 3 prefetch workers

Every block in the range is scanned. Sampling was removed: a standing
UTXO count cannot be reconstructed from a subset of blocks, and a gapped
dataset exports numbers that look complete and are short.

Suggested first run: start at 767,400 (first inscription is 767,430).
To include a pre-inscription zero baseline, start at 709,600 (Taproot
activation is 709,632). Safe to interrupt; rerunning resumes.
"""

import csv
import os
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

from rpc import rpc, CLIENT
from witness_classifier import classify_tx_witness
from graffiti_classifier import inscribed_texts
import utxo_track
from utxo_track import UTXOTracker

OUTDIR = "data"
BLOCKS_CSV = os.path.join(OUTDIR, "witness_blocks.csv")
TYPES_CSV = os.path.join(OUTDIR, "witness_content_types.csv")
DETAILS_CSV = os.path.join(OUTDIR, "witness_inscription_details.csv")
GRAFFITI_CSV = os.path.join(OUTDIR, "witness_graffiti.csv")

# Graffiti archive: every decodable text/plain inscription body, labeled
# by category. JSON bodies (BRC-20 mints) are counted in the types CSV
# already and number in the thousands per block at their peak — storing
# each one would bloat the archive without adding information, so they
# are skipped HERE ONLY.
GRAFFITI_MAX_PER_BLOCK = 50
GRAFFITI_SKIP_CATEGORIES = {"json"}

# Envelopes with at least this much body content get a detail row.
DETAIL_CONTENT_BYTES = 10_000

BAR_FULL = "\u2588"
BAR_EMPTY = "\u2591"

BLOCK_FIELDS = [
    "height", "block_time", "block_hash",
    "tx_count", "block_weight", "block_vsize",
    # independent node-reported measures (parser validation)
    "block_size", "block_strippedsize", "witness_serialized_bytes",
    # our exact accounting (element bytes)
    "witness_bytes", "envelope_bytes", "content_bytes", "payload_bytes",
    "overhead_bytes", "residual_bytes", "annex_bytes",
    # activity
    "envelope_txs", "envelope_count", "largest_content_bytes",
    "envelope_fees_sat", "envelope_vsize",
    # input mix
    "p2tr_keypath_inputs", "p2tr_scriptpath_inputs", "p2wsh_inputs",
    "p2wpkh_inputs", "other_witness_inputs",
    "client",
] + utxo_track.FIELDS

TYPE_FIELDS = [
    "height", "block_time", "protocol", "content_type",
    "envelopes", "content_bytes", "envelope_bytes",
]

GRAFFITI_FIELDS = [
    "height", "block_time", "txid", "content_type", "category", "text",
]

DETAIL_FIELDS = [
    "height", "block_time", "txid",
    "protocol", "content_type", "content_bytes", "envelope_bytes",
    "payload_bytes", "tx_vsize", "tx_weight", "tx_fee_sat",
    "tx_envelope_count",
]


def check_verbosity_3():
    """Fail fast with a useful message if the node lacks verbosity 3."""
    tip_hash = rpc("getblockhash", [rpc("getblockcount")])
    try:
        block = rpc("getblock", [tip_hash, 3])
    except RuntimeError as e:
        raise SystemExit(
            "This builder needs `getblock <hash> 3` (verbosity 3), which "
            "includes prevout data for classifying witness structures. "
            "It requires Bitcoin Core/Knots 25.0 or newer.\n"
            f"Node said: {e}"
        )
    for tx in block.get("tx", [])[1:3]:
        for vin in tx.get("vin", []):
            if "prevout" in vin:
                return
    raise SystemExit(
        "getblock verbosity 3 succeeded but returned no prevout fields — "
        "unexpected node behavior; cannot classify witness structures."
    )


def fetch_block(height):
    """Network-only step, safe to run on prefetch threads."""
    block_hash = rpc("getblockhash", [height])
    return height, block_hash, rpc("getblock", [block_hash, 3])


def analyze_block(height, block_hash=None, block=None, tracker=None):
    if block is None:
        _, block_hash, block = fetch_block(height)
    txs = block["tx"][1:]  # skip coinbase (its witness is the commitment nonce)
    t = block["time"]

    agg = {k: 0 for k in (
        "witness_bytes", "envelope_bytes", "content_bytes", "payload_bytes",
        "overhead_bytes", "residual_bytes", "annex_bytes",
        "envelope_txs", "envelope_count", "envelope_fees_sat",
        "envelope_vsize",
        "p2tr_keypath", "p2tr_scriptpath", "p2wsh", "p2wpkh",
        "other_witness",
    )}
    largest = 0
    block_vsize = 0
    types = {}
    detail_rows = []
    graffiti_rows = []
    envelope_txids = set()

    for tx in txs:
        block_vsize += tx.get("vsize", 0)
        c = classify_tx_witness(tx)
        if c is None:
            continue

        if c["envelope_count"] and len(graffiti_rows) < GRAFFITI_MAX_PER_BLOCK:
            for ctype, cat, text in inscribed_texts(tx):
                if cat in GRAFFITI_SKIP_CATEGORIES:
                    continue
                graffiti_rows.append({
                    "height": height, "block_time": t, "txid": c["txid"],
                    "content_type": ctype, "category": cat, "text": text,
                })
                if len(graffiti_rows) >= GRAFFITI_MAX_PER_BLOCK:
                    break

        for k in ("witness_bytes", "envelope_bytes", "content_bytes",
                  "payload_bytes", "overhead_bytes", "residual_bytes",
                  "annex_bytes", "envelope_count",
                  "p2tr_keypath", "p2tr_scriptpath", "p2wsh", "p2wpkh",
                  "other_witness"):
            agg[k] += c[k]

        if c["envelope_count"]:
            envelope_txids.add(c["txid"])
            agg["envelope_txs"] += 1
            agg["envelope_vsize"] += c["vsize"]
            if c["fee_sat"]:
                agg["envelope_fees_sat"] += c["fee_sat"]

        for env in c["envelopes"]:
            largest = max(largest, env["content_bytes"])
            key = (env["protocol"], env["content_type"])
            ty = types.setdefault(key, {"n": 0, "content": 0, "envelope": 0})
            ty["n"] += 1
            ty["content"] += env["content_bytes"]
            ty["envelope"] += env["envelope_bytes"]

            if env["content_bytes"] >= DETAIL_CONTENT_BYTES:
                detail_rows.append({
                    "height": height,
                    "block_time": t,
                    "txid": c["txid"],
                    "protocol": env["protocol"],
                    "content_type": env["content_type"],
                    "content_bytes": env["content_bytes"],
                    "envelope_bytes": env["envelope_bytes"],
                    "payload_bytes": env["payload_bytes"],
                    "tx_vsize": c["vsize"],
                    "tx_weight": c["weight"],
                    "tx_fee_sat": c["fee_sat"],
                    "tx_envelope_count": c["envelope_count"],
                })

    size = block.get("size", 0)
    stripped = block.get("strippedsize", 0)

    # UTXO accounting runs over the WHOLE block, coinbase included: its
    # outputs enter the set even though its witness is not payload. The
    # tracker walks block["tx"] itself so that inputs are seen before
    # outputs and transactions in order — which is what makes a
    # create-and-spend inside one block come out right.
    utxo_row = (tracker.process_block(block, envelope_txids) if tracker
                else dict(utxo_track.ZERO_ROW))

    block_row = {
        "height": height,
        "block_time": t,
        "block_hash": block_hash,
        "tx_count": len(txs),
        "block_weight": block.get("weight", 0),
        "block_vsize": block_vsize,
        "block_size": size,
        "block_strippedsize": stripped,
        "witness_serialized_bytes": size - stripped,
        "witness_bytes": agg["witness_bytes"],
        "envelope_bytes": agg["envelope_bytes"],
        "content_bytes": agg["content_bytes"],
        "payload_bytes": agg["payload_bytes"],
        "overhead_bytes": agg["overhead_bytes"],
        "residual_bytes": agg["residual_bytes"],
        "annex_bytes": agg["annex_bytes"],
        "envelope_txs": agg["envelope_txs"],
        "envelope_count": agg["envelope_count"],
        "largest_content_bytes": largest,
        "envelope_fees_sat": agg["envelope_fees_sat"],
        "envelope_vsize": agg["envelope_vsize"],
        "p2tr_keypath_inputs": agg["p2tr_keypath"],
        "p2tr_scriptpath_inputs": agg["p2tr_scriptpath"],
        "p2wsh_inputs": agg["p2wsh"],
        "p2wpkh_inputs": agg["p2wpkh"],
        "other_witness_inputs": agg["other_witness"],
        "client": CLIENT,
        **utxo_row,
    }

    type_rows = [
        {
            "height": height,
            "block_time": t,
            "protocol": proto,
            "content_type": ctype,
            "envelopes": v["n"],
            "content_bytes": v["content"],
            "envelope_bytes": v["envelope"],
        }
        for (proto, ctype), v in sorted(types.items())
    ]

    return block_row, type_rows, detail_rows, graffiti_rows


def done_heights():
    if not os.path.exists(BLOCKS_CSV):
        return set()
    with open(BLOCKS_CSV, newline="") as f:
        return {int(r["height"]) for r in csv.DictReader(f)}


def _writer(path, fields):
    fresh = not os.path.exists(path)
    f = open(path, "a", newline="", encoding="utf-8")
    w = csv.DictWriter(f, fieldnames=fields)
    if fresh:
        w.writeheader()
    return f, w


def render_progress(i, total, height, rate, env_bytes, content_bytes):
    frac = i / total
    filled = int(frac * 30)
    bar = BAR_FULL * filled + BAR_EMPTY * (30 - filled)
    eta_s = (total - i) / rate if rate else 0
    eta = f"{eta_s / 60:.1f}m" if eta_s >= 60 else f"{eta_s:.0f}s"
    line = (
        f"\r  {bar} {frac * 100:5.1f}%  "
        f"{i:>5}/{total}  blk {height:,}  "
        f"{rate:.2f}/s  eta {eta:>6}  "
        f"env {env_bytes / 1e6:,.1f}MB  content {content_bytes / 1e6:,.1f}MB"
    )
    print(line.ljust(120), end="", flush=True)


def _utxo_setup(start, already):
    """Prepare the tracker, or explain precisely why it cannot run.

    The counters are a running total, so they are only meaningful if the
    chain is walked contiguously from a height where the tagged set is
    known to be empty. Anything else would silently produce a plausible
    but wrong series, which is worse than producing none.
    """
    tracker = UTXOTracker()
    saved = tracker.height          # the database IS the state

    if saved is None:
        if start > utxo_track.ANCHOR_HEIGHT:
            print(f"UTXO tracking OFF: no saved state, and start {start:,} is\n"
                  f"above the anchor {utxo_track.ANCHOR_HEIGHT:,}. The tagged\n"
                  f"set can only begin empty at or below the first\n"
                  f"inscription (767,430).\n")
            return None
        if already:
            print(f"UTXO tracking OFF: {BLOCKS_CSV} already holds rows but the\n"
                  f"tracking database is empty, so earlier blocks were counted\n"
                  f"without it. Delete data/*.csv and data/utxo_track.db,\n"
                  f"then rebuild.\n")
            tracker.close()
            return None
        print(f"UTXO tracking ON: starting from an empty set at {start:,}.\n")
        return tracker

    # Resuming. The state must line up exactly with the CSV, or the
    # running totals are wrong from here on.
    csv_max = max(already) if already else saved
    if saved != csv_max:
        print(f"UTXO tracking OFF: the tracking database is at block\n"
              f"{saved:,} but {BLOCKS_CSV} runs to {csv_max:,}. Delete rows\n"
              f"above {saved:,}, or delete data/utxo_track.db and\n"
              f"data/*.csv to start clean.\n")
        tracker.close()
        return None
    st = tracker.standing()
    print(f"UTXO tracking ON: resumed at {saved:,} with "
          f"{st['tainted']:,} tagged outpoints on disk.\n")
    return tracker


def build(start, end, workers=3):
    os.makedirs(OUTDIR, exist_ok=True)
    check_verbosity_3()

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
    print(f"To scan: {len(targets):,}  (already have {len(already):,})")
    print(f"Note: verbosity-3 blocks are heavy; expect this to run slower")
    print(f"than the OP_RETURN scan.\n")

    if not targets:
        print("Nothing to do.")
        return

    tracker = _utxo_setup(start, already)

    bf, bw = _writer(BLOCKS_CSV, BLOCK_FIELDS)
    tf, tw = _writer(TYPES_CSV, TYPE_FIELDS)
    df, dw = _writer(DETAILS_CSV, DETAIL_FIELDS)
    gf, gw = _writer(GRAFFITI_CSV, GRAFFITI_FIELDS)

    t0 = time.time()
    last_done = None
    env_running = 0
    content_running = 0
    detail_total = 0

    # Prefetch pipeline: worker threads fetch upcoming blocks over RPC
    # while THIS thread classifies and writes strictly in height order.
    # The accounting path is untouched — only the network wait overlaps.
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
            brow, trows, drows, grows = analyze_block(height, bhash, block,
                                                     tracker)
            bw.writerow(brow)
            tw.writerows(trows)
            dw.writerows(drows)
            gw.writerows(grows)
            for f in (bf, tf, df, gf):
                f.flush()
            last_done = height

            # Commit the block's tagged-outpoint changes only AFTER its
            # CSV rows are on disk, so the recorded height can never run
            # ahead of the data. Resuming from a state that had would
            # double-count.
            if tracker is not None:
                tracker.commit(height)

            env_running += brow["envelope_bytes"]
            content_running += brow["content_bytes"]
            detail_total += len(drows)
            rate = i / (time.time() - t0)

            # Big-content blocks get a permanent line above the bar.
            if brow["content_bytes"] >= 100_000:
                print("\r" + " " * 120 + "\r", end="")
                print(
                    f"  -> {height:,}  "
                    f"{brow['envelope_count']:,} envelopes, "
                    f"{brow['content_bytes'] / 1e3:,.0f}KB content, "
                    f"largest {brow['largest_content_bytes'] / 1e3:,.0f}KB"
                )

            render_progress(i, len(targets), height, rate,
                            env_running, content_running)
    except KeyboardInterrupt:
        print("\n\nInterrupted. Progress saved; rerun to resume.")
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
        for f in (bf, tf, df, gf):
            f.close()
        if tracker is not None:
            if last_done is not None:
                tracker.commit(last_done)
                st = tracker.standing()
                print(f"UTXO tracking stopped at block {last_done:,}: "
                      f"{st['tainted']:,} tagged outpoints standing "
                      f"({st['reveal']:,} reveal-created).")
            tracker.close()

    print()
    print(f"\nWrote {detail_total:,} detail rows to {DETAILS_CSV}")
    print(f"Totals: {env_running / 1e6:,.1f}MB envelope bytes, "
          f"{content_running / 1e6:,.1f}MB content bytes")
    print(f"Done in {(time.time() - t0) / 60:.1f} min")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(1)
    # A third argument used to be the sampling step. If an old command
    # line supplies one, say so rather than silently treating it as a
    # worker count and scanning with three hundred threads.
    if len(sys.argv) > 3 and int(sys.argv[3]) > 16:
        raise SystemExit(
            f"\nArgument 3 is now the worker count, not a sampling step.\n"
            f"  {sys.argv[3]} looks like an old step value. Sampling was "
            f"removed; every block is scanned.\n"
            f"  Use: python witness_build_dataset.py {sys.argv[1]} "
            f"{sys.argv[2]} 3\n")
    build(int(sys.argv[1]), int(sys.argv[2]),
          int(sys.argv[3]) if len(sys.argv) > 3 else 3)
