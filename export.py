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

# Shorter than TIER_WINDOW on purpose. The clean-block rate is DRIFTING —
# 1.55% in January 2026, 2.68% in July — so a 20,000-block window (~4.6
# months) averages across a near-doubling and publishes a figure the
# recent chain no longer matches: 1 in 45 against a trailing-10,000 rate
# of 1 in 40 and a July rate of 1 in 37.
#
# 10,000 blocks is ~10 weeks, still ~250 clean events, so the 95% interval
# is 1 in 36 to 1 in 46 — tight enough to quote and current enough to be
# true. The tier bands keep the longer window because a distribution of
# byte shares is far less sensitive to this drift than a rate of a rare
# event is.
CLEAN_WINDOW = 10_000

# Envelopes are OP_FALSE OP_IF ... OP_ENDIF — an unexecutable branch.
# Nothing inside is ever evaluated by the script interpreter, so an
# envelope has no monetary function; carrying data is all it can do.
# Every envelope therefore counts as non-monetary regardless of which
# protocol wrote it. The `ord` split below exists ONLY so the figure is
# comparable to trackers that count Ordinals alone — it is not a
# correctness filter, and using it alone understates the total.
ORD_PROTOCOLS = {"ord"}

# How many recent blocks feed the tier threshold.
TIER_WINDOW = 20_000


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
             "or_outputs", "or_bytes", "or_max_size", "nonstandard_txs",
             "excess_bytes", "over_by_size_txs", "over_by_count_txs",
             "nonstandard_fees_sat"]
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

    # ---- display tiers for the live portal ------------------------------
    # "Clean" blocks are effectively extinct: routine protocol traffic
    # (Runes, bridge memos, commitments) puts data in nearly every block.
    # A two-colour scheme therefore paints everything the same. The
    # BASELINE tier separates that routine floor from blocks genuinely
    # carrying stored content, using the 10th percentile of recent blocks
    # rather than a number picked by hand.
    #
    # FROZEN at export time on purpose. A threshold that floats per-render
    # would silently change what a colour means, breaking comparison
    # across time. It updates when you re-export, and the page states the
    # window it came from.
    tiers = None
    if ob and wb:
        wsize = {r["height"]: r["block_size"] for r in wb}
        # Walk the most recent heights that exist in BOTH datasets. Taking
        # the last N OP_RETURN rows would find nothing while the witness
        # scan trails behind — the threshold would silently vanish and the
        # BASELINE tier would never render.
        joined = [r for r in ob if r["height"] in wsize][-TIER_WINDOW:]
        # BEYOND-BASELINE share: inscription envelopes (never sanctioned)
        # plus OP_RETURN bytes past the pre-v30 allowance. Ordinary small
        # OP_RETURNs are excluded — that channel was deliberately created
        # in 2014, so counting it would measure the settlement rather than
        # the departure from it.
        shares = [
            (r["excess_bytes"] + w_env.get(r["height"], 0)) / wsize[r["height"]]
            for r in joined if wsize[r["height"]]
        ]
        if len(shares) >= 100:
            ordered = sorted(shares)

            def pct(p):
                return round(ordered[min(len(ordered) - 1,
                                         int(len(ordered) * p / 100))], 5)

            # Quartiles, not a floor. A 10th-percentile threshold put 90%
            # of blocks in one bucket, which answered "is this block
            # unusually quiet?" — the wrong question. The median pivot
            # answers "is this block better or worse than what is now
            # normal?", and makes the normal itself the finding.
            tiers = {
                "p25": pct(25), "median": pct(50),
                "p75": pct(75), "p95": pct(95),
                "baseline_share": pct(50),
                "window_blocks": len(shares),
                "derived_from": [month_key(joined[0]["block_time"]),
                                 month_key(joined[-1]["block_time"])],
            }

    # ---- last data-free block ------------------------------------------
    # A block with at least one transaction and zero non-monetary bytes.
    # Empty blocks (no txs) are excluded: they are mined before validation
    # completes and are pure by accident, not by demand.
    last_clean = None
    if ob and wb:
        wenv = {r["height"]: r["envelope_bytes"] for r in wb}
        for r in reversed(ob):
            h = r["height"]
            if h not in wenv:
                continue
            if r["excess_bytes"] == 0 and wenv[h] == 0 and r["tx_count"] > 0:
                last_clean = {"height": h, "time": r["block_time"],
                              "tx_count": r["tx_count"]}
                break
        joined_end = max((r["height"] for r in ob if r["height"] in wenv),
                         default=0)

        # Yearly rate of data-free blocks. Empty blocks are excluded on
        # both sides of the ratio, so the trend reflects demand for clean
        # blockspace rather than variation in how often pools mine empty.
        by_year = defaultdict(lambda: {"n": 0, "clean": 0})
        for r in ob:
            h = r["height"]
            if h not in wenv or r["tx_count"] == 0:
                continue
            y = datetime.fromtimestamp(r["block_time"], timezone.utc).year
            d = by_year[y]
            d["n"] += 1
            if r["excess_bytes"] == 0 and wenv[h] == 0:
                d["clean"] += 1
        years = [{"year": y,
                  "blocks": v["n"],
                  "clean": v["clean"],
                  "pct": round(v["clean"] / v["n"] * 100, 4)}
                 for y, v in sorted(by_year.items()) if v["n"] >= 500]

        # Trailing-window rate. A calendar year is the wrong unit: it
        # resets every January to a sample of a few hundred blocks, and by
        # December it averages across whatever changed in February. See
        # CLEAN_WINDOW for why this window is shorter than the tier one.
        joined_rows = sorted((r for r in ob
                              if r["height"] in wenv and r["tx_count"] > 0),
                             key=lambda r: r["height"])[-CLEAN_WINDOW:]
        recent = None
        if len(joined_rows) >= 2000:
            rc = sum(1 for r in joined_rows
                     if r["excess_bytes"] == 0 and wenv[r["height"]] == 0)
            recent = {"window_blocks": len(joined_rows),
                      "clean": rc,
                      "pct": round(rc / len(joined_rows) * 100, 4),
                      "height_range": [joined_rows[0]["height"],
                                       joined_rows[-1]["height"]],
                      "months": [month_key(joined_rows[0]["block_time"]),
                                 month_key(joined_rows[-1]["block_time"])]}

        last_clean = {"block": last_clean, "coverage_end": joined_end,
                      "by_year": years, "recent": recent,
                      "unmeasured_above": max(0, max(wenv, default=0) and
                                              ob[-1]["height"] - joined_end)}

    meta = {"generated_at": generated_at, "datasets": datasets,
            "events": EVENTS, "tiers": tiers, "last_clean": last_clean,
            "measures": {
                "pile": "all non-monetary bytes a node must store "
                        "(inscription envelopes + all OP_RETURN)",
                "beyond": "only what post-2022 policy changes enabled: "
                          "inscription envelopes + OP_RETURN beyond the "
                          "pre-v30 allowance of one output at 83 bytes",
            }}
    write("meta.json", {}, meta)

    # ---- block tape: one entry per sampled witness block ----------------
    if wb:
        tape = [[r["height"],
                 round(r["envelope_bytes"] / r["block_size"], 4)
                 if r["block_size"] else 0,
                 r["block_time"]] for r in wb]
        write("blocktape.json",
              {"columns": ["height", "envelope_share", "block_time"],
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
        for k in ("or_bytes", "excess_bytes", "nonstandard_txs",
                  "block_vsize", "over_by_size_txs", "over_by_count_txs"):
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
               "insc_tx_mb": [], "insc_output_mb": [],
               "transfer_txs": [], "insc_added": [], "insc_removed": []}
        standing = reveal_standing = bogo = 0
        for mo in months:
            d = monthly[mo]
            if "insc_added" not in d:
                d = {k: 0 for k in UTXO_COLS}
            standing += d["insc_added"] - d["insc_removed"]
            reveal_standing += d["reveal_added"] - d["reveal_removed"]
            bogo += d["insc_bogo_added"] - d["insc_bogo_removed"]
            out["insc_utxo_standing"].append(standing)
            out["reveal_utxo_standing"].append(reveal_standing)
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


    all_months = sorted(set(w_monthly) | set(o_monthly))
    if all_months:
        series = {k: [] for k in (
            "witness_content_mb", "witness_envelope_mb",
            "witness_content_ord_mb", "witness_content_other_mb",
            "opreturn_mb", "permitted_mb")}
        run = defaultdict(float)
        for m in all_months:
            run["wc"] += w_monthly[m]["content_bytes"] / 1e6
            run["we"] += w_monthly[m]["envelope_bytes"] / 1e6
            run["wo"] += ord_monthly[m]["ord_content"] / 1e6
            run["wx"] += ord_monthly[m]["other_content"] / 1e6
            run["or"] += o_monthly[m]["or_bytes"] / 1e6
            series["witness_content_mb"].append(round(run["wc"], 1))
            series["witness_envelope_mb"].append(round(run["we"], 1))
            series["witness_content_ord_mb"].append(round(run["wo"], 1))
            series["witness_content_other_mb"].append(round(run["wx"], 1))
            series["opreturn_mb"].append(round(run["or"], 1))

            # WHAT THE OLD RULES PERMITTED.
            #
            # Not a counterfactual — this page does not claim to know what
            # would have existed, because relay policy was never consensus
            # and blocked data can move to a cheaper carrier. This is a
            # subtraction: OP_RETURN minus the part that exceeded the
            # pre-v30 allowance, which is exactly the channel Bitcoin
            # deliberately opened in 2014 and nobody objected to.
            #
            # Envelopes contribute nothing to it: an inscription is not
            # OP_RETURN and was never within that allowance.
            run["pm"] += max(0, o_monthly[m]["or_bytes"]
                                - o_monthly[m]["excess_bytes"]) / 1e6
            series["permitted_mb"].append(round(run["pm"], 1))

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
        }, meta)

    print(f"\nExport complete — {generated_at}")
    for name, d in datasets.items():
        print(f"  {name}: {d['blocks']:,} blocks, "
              f"{d['date_range'][0]} to {d['date_range'][1]}")
    print("\nView it:  cd dashboard && python -m http.server 8000")
    print("Then open http://localhost:8000")


if __name__ == "__main__":
    main()
