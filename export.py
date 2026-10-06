"""
Export chart-ready JSON from the pipeline CSVs.

    python export.py

Reads  data/*.csv          (whichever pipelines have been built)
Writes dashboard/data/*.json

The JSON files are the contract between the pipelines and the frontend:
the dashboard reads ONLY these files, never the CSVs, so either side can
be rewritten independently. Every file carries generated_at and the
generation timestamp.

All aggregation happens here, in Python. The browser gets pre-chewed
numbers and does no math beyond drawing.

NO SAMPLING
-----------
Every block in range is parsed, so every total is a count rather than an
estimate. Sampling used to be supported and was removed: scaling a sum by
the step is defensible, but a standing UTXO count cannot be scaled at all
(set membership is not a sum), and publishing a confidence interval
invites a reader to treat an extrapolation as a measurement.

A gap in the height sequence is therefore an ERROR, not a mode. See
check_contiguous — a gapped dataset exports smooth, plausible, wrong
curves, and refusing is better than scaling.
"""

import csv
import json
import os
import random
import statistics
from collections import defaultdict
from datetime import datetime, timezone

DATA = "data"
OUT = os.path.join("dashboard", "data")

# The UTXO columns are optional: datasets built before the tracker existed
# do not have them, and this export must still run against those. Taken
# from the builder's own list so the two cannot drift apart.
try:
    from utxo_track import FIELDS as UTXO_COLS, BAND_NAMES as UTXO_BANDS
except ImportError:                       # pragma: no cover
    UTXO_COLS, UTXO_BANDS = [], ()

# Event annotations for chart timelines. Dates are UTC.
EVENTS = [
    {"date": "2022-12-14", "label": "First inscription", "detail": "block 767,430"},
    {"date": "2023-03-08", "label": "BRC-20 launches", "detail": "text mint era begins"},
    {"date": "2024-04-20", "label": "Runes launches", "detail": "halving block 840,000"},
    {"date": "2025-10-10", "label": "Core v30", "detail": "OP_RETURN limit lifted"},
    {"date": "2026-08-08", "label": "BIP-110 activation attempt", "detail": "block 961,632"},
]


def read_csv(name, int_cols):
    """Load a CSV with integer coercion. Returns [] if absent."""
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            for k in int_cols:
                if k in r:
                    r[k] = int(r[k]) if r[k] not in ("", None) else 0
            rows.append(r)
    return rows


def read_first(names, int_cols):
    """Try several filenames (pre/post rename compatibility)."""
    for n in names:
        rows = read_csv(n, int_cols)
        if rows:
            return rows, n
    return [], None


# Bootstrap cost is iters x n. A sampled dataset (~2k blocks) can afford
# 2000 iterations; a 200k-block dataset cannot — that is a billion
# operations in pure Python. Cap total work and scale iterations down,
# with a floor that still gives a usable interval.
BOOTSTRAP_MAX_OPS = 8_000_000

BOOTSTRAP_MIN_ITERS = 300

# Envelopes are OP_FALSE OP_IF ... OP_ENDIF — an unexecutable branch.
# Nothing inside is ever evaluated by the script interpreter, so an
# envelope has no monetary function; carrying data is all it can do.
# Every envelope therefore counts as non-monetary regardless of which
# protocol wrote it. The `ord` split below exists ONLY so the figure is
# comparable to trackers that count Ordinals alone — it is not a
# correctness filter, and using it alone understates the total.
ORD_PROTOCOLS = {"ord"}

def chain_size(opreturn_rows):
    """Whole-chain serialized byte total and how far it reaches.

    The OP_RETURN dataset carries block_size for every block it scanned,
    and that scan runs from genesis — so summing block_size is the true
    size of the chain over the scanned range, in serialized bytes, off
    the node. This is the scale-bar denominator.

    Returns the total, the height it reaches, and whether that height is
    close enough to a full chain for the bar to drop its coverage caveat.
    A partial genesis scan still produces a usable (smaller) denominator
    and an honest "measured through block N" label, rather than a wrong
    one that looks complete.
    """
    if not opreturn_rows:
        return None
    total = 0
    lo = hi = None
    for r in opreturn_rows:
        bs = r.get("block_size")
        if bs in (None, "", 0):
            continue
        total += int(bs)
        h = int(r["height"])
        lo = h if lo is None else min(lo, h)
        hi = h if hi is None else max(hi, h)
    if not total:
        return None
    return {
        "serialized_bytes": total,
        "scanned_from": lo,
        "scanned_to": hi,
        # The scan starts at genesis, so "from 1" plus a tip-ish "to"
        # means the denominator is genuinely whole-chain. The page uses
        # this to decide whether to show a coverage caveat.
        "from_genesis": lo is not None and lo <= 10,
    }


def month_key(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m")


def write(name, payload, meta):
    payload["_meta"] = meta
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    print(f"  wrote {path}")


def check_contiguous(rows, name):
    """Every block in range, or refuse.

    This project no longer samples. A gapped dataset still produces a
    complete-looking export — the curves are smooth, the totals are
    plausible, and every one of them is short by however many blocks were
    skipped. Worse, the UTXO series is not merely short but wrong, since
    set membership cannot be reconstructed from a subset.

    So a gap is a hard error with the range printed, rather than a
    silently scaled estimate.
    """
    if not rows:
        return
    heights = sorted(r["height"] for r in rows)
    span = heights[-1] - heights[0] + 1
    if len(heights) == span:
        return
    missing = []
    prev = heights[0]
    for h in heights[1:]:
        if h != prev + 1:
            missing.append((prev + 1, h - 1))
        prev = h
    shown = ", ".join(f"{a:,}-{b:,}" if a != b else f"{a:,}"
                      for a, b in missing[:4])
    raise SystemExit(
        f"\n{name}: {span - len(heights):,} blocks missing between "
        f"{heights[0]:,} and {heights[-1]:,}.\n"
        f"  gaps: {shown}{' ...' if len(missing) > 4 else ''}\n"
        f"  This export does not extrapolate. Re-run the builder over the "
        f"full range\n  before exporting.")


def main():
    os.makedirs(OUT, exist_ok=True)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    W_INT = ["height", "block_time", "block_size", "block_strippedsize",
             "witness_bytes", "envelope_bytes", "content_bytes",
             "overhead_bytes", "residual_bytes", "envelope_count",
             "envelope_txs", "envelope_fees_sat", "largest_content_bytes",
             "tx_count"] + UTXO_COLS
    O_INT = ["height", "block_time", "tx_count", "block_vsize", "or_txs",
             "or_outputs", "or_bytes", "or_stored_bytes", "or_max_size",
             "nonstandard_txs",
             "excess_bytes", "over_by_size_txs", "over_by_count_txs",
             "nonstandard_fees_sat",
             # Serialized block size, from the node. Present because the
             # OP_RETURN scan runs from genesis, so summing it gives an
             # honest whole-chain denominator for the scale bar — same
             # units as the pile (serialized bytes), unlike the live
             # poller's size_on_disk which counts compressed data plus
             # undo files the chain does not contain.
             "block_size"]
    T_INT = ["height", "block_time", "envelopes", "content_bytes",
             "envelope_bytes"]

    wb = read_csv("witness_blocks.csv", W_INT)
    check_contiguous(wb, "witness_blocks.csv")
    # opreturn_blocks.csv is the current name; blocks.csv is the pre-rename
    # name, still read so an older dataset exports without a rebuild.
    ob, ob_src = read_first(["opreturn_blocks.csv", "blocks.csv"], O_INT)
    ct, ct_src = read_first(
        ["witness_content_types.csv", "content_types.csv"], T_INT)

    if not wb and not ob:
        raise SystemExit("No datasets found in data/. Run the builders first.")

    w_env = {r["height"]: r["envelope_bytes"] for r in wb} if wb else {}

    datasets = {}
    if wb:
        wb.sort(key=lambda r: r["height"])
        datasets["witness"] = {
            "source": "witness_blocks.csv",
            "blocks": len(wb),

            "height_range": [wb[0]["height"], wb[-1]["height"]],
            "date_range": [month_key(wb[0]["block_time"]),
                           month_key(wb[-1]["block_time"])],
        }
    if ob:
        ob.sort(key=lambda r: r["height"])
        datasets["opreturn"] = {
            "source": ob_src,
            "blocks": len(ob),

            "height_range": [ob[0]["height"], ob[-1]["height"]],
            "date_range": [month_key(ob[0]["block_time"]),
                           month_key(ob[-1]["block_time"])],
        }

    # One measure. The policy figure that used to sit beside it — tier
    # bands over "beyond the old allowance" shares, and the last block
    # that carried nothing the pre-2023 rules would have refused — is
    # gone, along with the windows that fed it. Both graded blocks
    # against relay rules; neither measured what a node stores.
    meta = {"generated_at": generated_at, "datasets": datasets,
            "events": EVENTS,
            "measures": {
                "pile": "all non-monetary bytes a node must store: the "
                        "whole reveal transactions, the provable floor "
                        "of transfers, every OP_RETURN output at stored "
                        "size, plus the chainstate entries inscriptions "
                        "leave behind",
            }}
    write("meta.json", {}, meta)

    # ---- block tape: one entry per witness block -------------------------
    # Per-block non-monetary share on the SAME basis the live poller
    # uses: reveal transactions (less any OP_RETURN inside them) plus
    # every OP_RETURN output at stored size. Transfers are left out here
    # too, so a historical block and a live block are the same
    # quantity. The headline adds the transfer floor; this does not, and
    # the methodology says so.
    if wb:
        o_by_h = {r["height"]: r for r in ob} if ob else {}
        tape = []
        for r in wb:
            bs = r["block_size"]
            if not bs:
                tape.append([r["height"], 0, r["block_time"]])
                continue
            o = o_by_h.get(r["height"])
            or_stored = ((o.get("or_stored_bytes") or o.get("or_bytes", 0))
                         if o else 0)
            nm = (r.get("reveal_tx_bytes", 0)
                  - r.get("reveal_opreturn_bytes", 0)
                  + or_stored)
            tape.append([r["height"], round(nm / bs, 4), r["block_time"]])
        write("blocktape.json",
              {"columns": ["height", "nonmonetary_share", "block_time"],
               "rows": tape}, meta)

    # ---- monthly witness aggregates --------------------------------------
    w_monthly = defaultdict(lambda: defaultdict(int))
    for r in wb:
        m = w_monthly[month_key(r["block_time"])]
        m["blocks"] += 1
        for k in ("block_size", "envelope_bytes", "content_bytes",
                  "residual_bytes", "envelope_count", "envelope_txs",
                  "envelope_fees_sat"):
            m[k] += r[k]
        # Everything the tracker wrote, summed the same way. Standing
        # quantities are turned into running totals further down; these
        # are still per-month flows at this point.
        for k in UTXO_COLS:
            if k in r:
                m[k] += r[k]

    # Split envelope/content bytes by ord vs other protocols, per month.
    ord_monthly = defaultdict(lambda: defaultdict(int))
    for r in ct:
        m = ord_monthly[month_key(r["block_time"])]
        bucket = "ord" if r["protocol"] in ORD_PROTOCOLS else "other"
        m[f"{bucket}_content"] += r["content_bytes"]
        m[f"{bucket}_envelope"] += r["envelope_bytes"]

    if wb:

        months = sorted(w_monthly)
        write("witness_monthly.json", {
            "months": months,
            "envelope_share_pct": [
                round(w_monthly[m]["envelope_bytes"]
                      / w_monthly[m]["block_size"] * 100, 3)
                if w_monthly[m]["block_size"] else 0 for m in months],
            "content_mb_sampled": [
                round(w_monthly[m]["content_bytes"] / 1e6, 3) for m in months],
            "envelope_mb_est": [
                round(w_monthly[m]["envelope_bytes"] / 1e6, 1)
                for m in months],
            "envelopes_sampled": [
                w_monthly[m]["envelope_count"] for m in months],
            "estimated": False,
        }, meta)

    # ---- monthly OP_RETURN aggregates ------------------------------------
    o_monthly = defaultdict(lambda: defaultdict(int))
    for r in ob:
        m = o_monthly[month_key(r["block_time"])]
        m["blocks"] += 1
        for k in ("or_bytes", "or_stored_bytes", "excess_bytes",
                  "nonstandard_txs", "block_vsize",
                  "over_by_size_txs", "over_by_count_txs"):
            m[k] += r[k]

    if ob:

        months = sorted(o_monthly)
        write("opreturn_monthly.json", {
            "months": months,
            "or_kb_est": [
                round(o_monthly[m]["or_bytes"] / 1e3, 1)
                for m in months],
            "excess_kb_est": [
                round(o_monthly[m]["excess_bytes"] / 1e3, 2)
                for m in months],
            "nonstandard_txs_sampled": [
                o_monthly[m]["nonstandard_txs"] for m in months],
            "estimated": False,
        }, meta)

    # ---- the cumulative chart -------------------------------------------
    # Estimated chain totals per month, then cumulative.
    #
    # PRIMARY measure is CONTENT bytes — the payload itself, the most
    # conservative reading of "how much data was stored". ENVELOPE bytes
    # (payload plus the protocol fields and opcodes wrapping it) ship
    # alongside so the dashboard can toggle; both are non-monetary by
    # construction. Signatures, control blocks and legitimate spending
    # scripts live in overhead/residual and are excluded entirely.
    def utxo_series(months, monthly):
        """Monthly UTXO series, or None if this dataset predates the tracker.

        Two kinds of quantity, and they are not interchangeable:

        Two kinds of quantity, and they are not interchangeable:

          STANDING  how many inscription UTXOs exist at the end of that
                    month. A running total of added minus removed. It can
                    fall — a consolidation genuinely shrinks the burden,
                    unlike bytes in a block, which are permanent.

          FLOW      bytes those transactions put in blocks that month.
                    Summed, never accumulated here; the page accumulates
                    if it wants a cumulative view.

        Bogosize is Core's database-independent size metric. It is
        meaningless on its own and is converted to real bytes by the
        caller using the node's own disk_size/bogosize ratio.
        """
        # defaultdict would happily invent an empty month, so test for the
        # column across the whole range rather than on the first month —
        # which may exist only in the OP_RETURN data.
        if not months or not any("insc_added" in monthly[m] for m in months):
            return None
        out = {"insc_utxo_standing": [], "insc_bogo_standing": [],
               "reveal_utxo_standing": [],
               # The published chainstate figure: outputs of a reveal
               # small enough to be carrying the inscription rather than
               # returning change to the inscriber. No propagation, no
               # change. The two above are the wider definitions, kept
               # as the cross-check and the ceiling.
               "reveal_dust_standing": [], "reveal_dust_bogo_standing": [],
               "insc_tx_mb": [], "insc_output_mb": [],
               "transfer_txs": [], "insc_added": [], "insc_removed": []}
        standing = reveal_standing = bogo = 0
        dust = dust_bogo = 0
        for mo in months:
            d = monthly[mo]
            if "insc_added" not in d:
                d = {k: 0 for k in UTXO_COLS}
            standing += d["insc_added"] - d["insc_removed"]
            reveal_standing += d["reveal_added"] - d["reveal_removed"]
            bogo += d["insc_bogo_added"] - d["insc_bogo_removed"]
            dust += d.get("reveal_dust_added", 0) - d.get("reveal_dust_removed", 0)
            dust_bogo += (d.get("reveal_dust_bogo_added", 0)
                          - d.get("reveal_dust_bogo_removed", 0))
            out["insc_utxo_standing"].append(standing)
            out["reveal_utxo_standing"].append(reveal_standing)
            out["reveal_dust_standing"].append(dust)
            out["reveal_dust_bogo_standing"].append(dust_bogo)
            out["insc_bogo_standing"].append(bogo)
            out["insc_tx_mb"].append(
                round((d["reveal_tx_bytes"] + d["transfer_tx_bytes"]) / 1e6, 2))
            out["insc_output_mb"].append(round(d["insc_output_bytes"] / 1e6, 3))
            out["transfer_txs"].append(d["transfer_txs"])
            out["insc_added"].append(d["insc_added"])
            out["insc_removed"].append(d["insc_removed"])

        # Standing counts by value band, so the page can apply any dust
        # threshold it likes without another export.
        for b in UTXO_BANDS:
            run = 0
            col = []
            for mo in months:
                run += (monthly[mo][f"insc_{b}_created"]
                        - monthly[mo][f"insc_{b}_spent"])
                col.append(run)
            out[f"insc_standing_{b}"] = col
        return out


    def chainstate_ratio():
        """disk_size / bogosize from the node — the only way to turn the
        bogosize series into real bytes without assuming a constant.

        Optional: if the node is unreachable the series is still emitted
        and the page simply cannot render it in gigabytes.
        """
        try:
            from rpc import rpc
        except Exception as e:
            print(f"  note: chainstate ratio unavailable — {e}")
            return None

        # use_index=False, always, and not as a fallback.
        #
        # gettxoutsetinfo does not return disk_size when it answers from
        # coinstatsindex — and disk_size is the whole point here, since
        # bogosize is a fake unit and only the node knows what it costs on
        # its own disk. The index is faster and can answer at any height,
        # but it cannot answer THIS question, so the direct chainstate
        # scan is the correct call rather than a degraded one.
        #
        # It walks the whole UTXO set, so expect a minute or two.
        try:
            info = rpc("gettxoutsetinfo", ["none", None, False])
        except Exception as e:
            # Print what the node actually said. The exception TYPE alone
            # is useless — a syncing index, a bad credential and a timeout
            # all surface as RuntimeError and need different fixes.
            print(f"  note: chainstate ratio unavailable — {e}")
            print(f"        the UTXO series is still exported; the chart "
                  f"just cannot show it in gigabytes.")
            return None

        if not info.get("bogosize") or not info.get("disk_size"):
            print(f"  note: gettxoutsetinfo returned no disk_size/bogosize — "
                  f"got keys {sorted(info)}")
            return None

        return {"disk_size": info["disk_size"],
                "bogosize": info["bogosize"],
                "txouts": info["txouts"],
                "bytes_per_bogo": round(info["disk_size"] / info["bogosize"], 6),
                "height": info.get("height")}


    fam_payload = None
    # ---- media families ----------------------------------------------------
    if ct:
        fams = defaultdict(lambda: {"n": 0, "bytes": 0, "content": 0})
        FAMS = [("image/", "images"), ("video/", "video"),
                ("audio/", "audio"), ("model/", "3D models"),
                ("text/html", "HTML"), ("text/", "text"),
                ("application/json", "JSON"), ("application/", "apps/other")]

        def family(ctype):
            b = (ctype or "").split(";")[0].strip().lower()
            if not b:
                return "(untyped)"
            for p, f in FAMS:
                if b.startswith(p):
                    return f
            return "other"

        # BOTH measures, because they answer different questions and mixing
        # them produces a wrong claim. content_bytes is the ord body — the
        # file itself. envelope_bytes is the whole construct including the
        # protocol fields and chunk prefixes that a node also stores.
        #
        # The page headlines envelope + OP_RETURN, so a breakdown quoted in
        # content bytes would be shares of 35.85 GB presented next to a
        # 44.27 GB total, and a reader would multiply the two. The
        # envelope figures reconcile exactly with the headline; content is
        # kept alongside for anyone wanting "the files themselves".
        for r in ct:
            f = fams[family(r["content_type"])]
            f["n"] += r["envelopes"]
            f["bytes"] += r["envelope_bytes"]
            f["content"] += r["content_bytes"]

        total_n = sum(v["n"] for v in fams.values()) or 1
        total_b = sum(v["bytes"] for v in fams.values()) or 1
        ranked = sorted(fams.items(), key=lambda kv: -kv[1]["bytes"])
        write("families.json", {
            "source": ct_src,
            "families": [k for k, _ in ranked],
            "byte_share_pct": [round(v["bytes"] / total_b * 100, 2)
                               for _, v in ranked],
            "count_share_pct": [round(v["n"] / total_n * 100, 2)
                                for _, v in ranked],
            "avg_bytes": [round(v["bytes"] / v["n"]) if v["n"] else 0
                          for _, v in ranked],
            "content_mb": [round(v["content"] / 1e6, 2) for _, v in ranked],
            "envelope_mb": [round(v["bytes"] / 1e6, 2) for _, v in ranked],
            "envelopes": [v["n"] for _, v in ranked],
        }, meta)

        # families.json is not shipped — cumulative.json is the only export
        # the site reads — so the breakdown rides along inside it. Absolute
        # MB rather than percentages, so the page can reconcile it against
        # its own headline instead of trusting a share computed elsewhere.
        fam_payload = {
            "names": [k for k, _ in ranked],
            "envelope_mb": [round(v["bytes"] / 1e6, 2) for _, v in ranked],
            "content_mb": [round(v["content"] / 1e6, 2) for _, v in ranked],
            "envelopes": [v["n"] for _, v in ranked],
        }


    # Does the witness dataset carry the whole-transaction columns? They
    # arrived with the UTXO tracker, so a dataset built before it has
    # only envelope bytes and the page falls back to the narrow measure
    # rather than rendering a headline of zero.
    has_tx = any("reveal_tx_bytes" in w_monthly[m] for m in w_monthly)
    # The deduction column is newer still. Its absence is not fatal —
    # the overlap is small — but it means the pile is knowingly counting
    # some bytes twice, which is worth one line of noise at export time.
    has_dedupe = any("reveal_opreturn_bytes" in w_monthly[m] for m in w_monthly)
    if has_tx and not has_dedupe:
        print("  note: witness_blocks.csv predates the OP_RETURN deduction "
              "columns, so\n        OP_RETURN bytes inside inscription "
              "transactions are counted twice.\n        Rebuild to remove "
              "the overlap.")

    # THE DEDUCTION CROSSES TWO PIPELINES, so it is only valid where both
    # cover the same chain. insc_opreturn_bytes is measured by the witness
    # builder; or_bytes by the OP_RETURN builder. Subtracting one from the
    # other in a month only one of them scanned would remove bytes that
    # were never added, and the result would look perfectly reasonable.
    #
    # Two failures are checked. A month with witness coverage and no
    # OP_RETURN coverage silently loses its deduction; a month where the
    # deduction EXCEEDS the total is proof the two files were built over
    # different ranges, because a subset cannot be larger than its set.
    if has_tx and has_dedupe:
        def dedup(m):
            return (w_monthly[m].get("reveal_opreturn_bytes", 0)
                    + w_monthly[m].get("transfer_opreturn_bytes", 0))

        def or_stored(m):
            # or_stored_bytes is the newer column; fall back to the script
            # figure so an older OP_RETURN dataset still exports.
            return (o_monthly[m].get("or_stored_bytes")
                    or o_monthly[m].get("or_bytes", 0))

        gap = [m for m in sorted(set(w_monthly) | set(o_monthly))
               if dedup(m) and not or_stored(m)]
        over = [m for m in sorted(set(w_monthly) & set(o_monthly))
                if dedup(m) > or_stored(m)]
        if over:
            print(f"  WARNING: in {len(over)} month(s) the OP_RETURN "
                  f"deduction exceeds the OP_RETURN total "
                  f"({', '.join(over[:3])}). A subset cannot exceed its "
                  f"set, so the two pipelines cover different ranges. "
                  f"Rebuild both to the same height before trusting the "
                  f"headline.")
        elif gap:
            print(f"  note: {len(gap)} month(s) have witness coverage but no "
                  f"OP_RETURN coverage, so the deduction is not applied "
                  f"there.")

    all_months = sorted(set(w_monthly) | set(o_monthly))
    if all_months:
        series = {k: [] for k in (
            "witness_content_mb", "witness_envelope_mb",
            "witness_content_ord_mb", "witness_content_other_mb",
            "opreturn_mb")}
        if has_tx:
            # THE PUBLISHED INSCRIPTION MEASURE.
            #
            # Whole serialized transactions, not envelopes. A reveal
            # transaction exists for one reason — nobody builds one to
            # move money — so every byte of it, signature and skeleton
            # included, is caused by the inscription. A node stores
            # transactions, so this is what a node stores because of
            # them. Transfers are included on the same counterfactual:
            # the thing being moved would not exist to move.
            #
            # witness_envelope_mb is still exported alongside. It is the
            # payload alone, it is what the block grades use, and the
            # difference between the two series IS the wrapper — which
            # the page shows rather than buries.
            series["witness_tx_mb"] = []
            # And the two halves of it, separately, because they are not
            # the same claim. A reveal wraps a payload in signatures; a
            # transfer carries no payload at all and is attributed purely
            # on the counterfactual that the thing being moved would not
            # exist to move. Folding them together would let the page
            # label whole transfer transactions as "overhead".
            series["reveal_tx_mb"] = []
            # Transfers, twice. FLOOR is what can be proved: the tagged
            # dust input and the tagged output. CEILING is the whole
            # transaction, right for a real transfer and wrong for a
            # sweep. The published total uses the floor; the ceiling is
            # exported so the page can state the bound instead of
            # pretending there isn't one.
            series["transfer_floor_mb"] = []
            series["transfer_tx_mb"] = []
            series["witness_tx_ceiling_mb"] = []
            # NOTE the deduction is applied to reveal_tx_mb and
            # transfer_tx_mb above, NOT here. Either side could carry it
            # and the total is the same, but taking it on the inscription
            # side leaves opreturn_mb as every OP_RETURN byte on chain —
            # a figure anyone with a node can reproduce independently.
        run = defaultdict(float)
        for m in all_months:
            run["wc"] += w_monthly[m]["content_bytes"] / 1e6
            run["we"] += w_monthly[m]["envelope_bytes"] / 1e6
            run["wo"] += ord_monthly[m]["ord_content"] / 1e6
            run["wx"] += ord_monthly[m]["other_content"] / 1e6
            # Stored bytes, not script bytes: the pile is a storage
            # measure and a node keeps each output's value field and
            # length prefix too. Older datasets have only the script
            # figure, which reads ~9 bytes an output low.
            run["or"] += (o_monthly[m].get("or_stored_bytes")
                          or o_monthly[m].get("or_bytes", 0)) / 1e6
            series["witness_content_mb"].append(round(run["wc"], 1))
            series["witness_envelope_mb"].append(round(run["we"], 1))
            series["witness_content_ord_mb"].append(round(run["wo"], 1))
            series["witness_content_other_mb"].append(round(run["wx"], 1))
            series["opreturn_mb"].append(round(run["or"], 1))
            if has_tx:
                run["rv"] += (w_monthly[m]["reveal_tx_bytes"]
                              - w_monthly[m].get("reveal_opreturn_bytes", 0)) / 1e6
                run["tc"] += (w_monthly[m]["transfer_tx_bytes"]
                              - w_monthly[m].get("transfer_opreturn_bytes", 0)) / 1e6
                # The floor carries no OP_RETURN deduction: it counts
                # tagged inputs and tagged outputs, and an OP_RETURN is
                # never either of those.
                run["tf"] += (w_monthly[m].get("transfer_input_bytes", 0)
                              + w_monthly[m].get("transfer_output_bytes", 0)) / 1e6
                run["wt"] = run["rv"] + run["tf"]
                series["witness_tx_mb"].append(round(run["wt"], 1))
                series["reveal_tx_mb"].append(round(run["rv"], 1))
                series["transfer_floor_mb"].append(round(run["tf"], 1))
                series["transfer_tx_mb"].append(round(run["tc"], 1))
                series["witness_tx_ceiling_mb"].append(
                    round(run["rv"] + run["tc"], 1))


        # Reconcile: the ord/other split comes from witness_content_types.csv
        # while the totals come from witness_blocks.csv. Both are summed from
        # the same envelopes during the build, so they must agree. A gap means
        # one file is stale or was built from a different range.
        split_total = sum(ord_monthly[m]["ord_content"]
                          + ord_monthly[m]["other_content"] for m in all_months)
        block_total = sum(w_monthly[m]["content_bytes"] for m in all_months)
        if block_total:
            drift = abs(split_total - block_total) / block_total
            if drift > 0.01:
                print(f"  WARNING: ord/other split covers "
                      f"{split_total / block_total * 100:.1f}% of content bytes "
                      f"in witness_blocks.csv. The two files disagree — "
                      f"rebuild both from the same range before trusting "
                      f"the ORD ONLY view.")

        # AND the same check on ENVELOPE bytes, which matters more now.
        # The page draws the wrapper as reveal_tx_bytes minus the families
        # total, so any disagreement between the two files does not show
        # up as a missing slice — it is silently absorbed into
        # "signatures & skeleton", the largest object on that chart.
        # Tighter tolerance than the content check for exactly that
        # reason: this one has somewhere to hide.
        fam_env = sum(r["envelope_bytes"] for r in ct)
        blk_env = sum(w_monthly[m]["envelope_bytes"] for m in all_months)
        if blk_env and ct:
            d = abs(fam_env - blk_env) / blk_env
            if d > 0.002:
                print(f"  WARNING: witness_content_types.csv holds "
                      f"{fam_env / 1e9:.2f} GB of envelope bytes against "
                      f"{blk_env / 1e9:.2f} GB in witness_blocks.csv "
                      f"({d * 100:.2f}% apart). The made-of chart derives "
                      f"'signatures & skeleton' by subtracting the first "
                      f"from reveal_tx_bytes, so this gap lands there "
                      f"instead of showing as a missing family.")

        write("cumulative.json", {
            "months": all_months,
            **series,
            # Kept, and always false: every block in range was parsed.
            # The page reads this to decide between "exact" and "estimated"
            # wording, and an absent key would silently become the wrong
            # one.
            "estimated": False,
            "ci95": {},
            "coverage": {
                "witness": datasets.get("witness", {}).get("date_range"),
                "opreturn": datasets.get("opreturn", {}).get("date_range"),
            },
            # What the pile is made of. In absolute MB, not shares, so the
            # page can reconcile it against its own headline rather than
            # trusting a percentage computed against a different total.
            "families": fam_payload,
            # The UTXO burden inscriptions leave in the chainstate, and the
            # whole-transaction byte measure. Absent on datasets built
            # before the tracker; the page hides those elements rather
            # than failing.
            # all_months, NOT the witness-only list — every array in this
            # file is indexed by the same month vector, and passing a
            # different one would silently shift the series against the
            # labels it is drawn with.
            "utxo": utxo_series(all_months, w_monthly),
            "chainstate": chainstate_ratio(),
            # THE HONEST SCALE-BAR DENOMINATOR.
            #
            # Sum of every block's serialized size across whatever range
            # the OP_RETURN scan has reached (it runs from genesis). Same
            # units as the pile. The page divides the pile by this instead
            # of the live node's size_on_disk, which is compressed on-disk
            # bytes plus undo files — wrong units and not even all chain.
            #
            # scanned_to lets the page say honestly how much of the chain
            # this covers: if the genesis scan is only partway, the bar
            # states "chain measured through block N" rather than implying
            # it has the whole thing.
            "chain": chain_size(ob),
        }, meta)

    tg = sum(w_monthly[m].get("transfer_inputs_tagged", 0) for m in w_monthly)
    tt = sum(w_monthly[m].get("transfer_inputs_total", 0) for m in w_monthly)
    if tt:
        print(f"\n  transfer inputs: {tg:,} tagged of {tt:,} total "
              f"({tg / tt * 100:.1f}%)")
        print(f"  the lower that share, the more of the transfer ceiling is "
              f"sweeping\n  rather than moving inscriptions.")

    print(f"\nExport complete — {generated_at}")
    for name, d in datasets.items():
        print(f"  {name}: {d['blocks']:,} blocks, "
              f"{d['date_range'][0]} to {d['date_range'][1]}")
    print("\nView it:  cd dashboard && python -m http.server 8000")
    print("Then open http://localhost:8000")


if __name__ == "__main__":
    main()
