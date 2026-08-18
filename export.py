"""
Export chart-ready JSON from the pipeline CSVs.

    python export.py

Reads  data/*.csv          (whichever pipelines have been built)
Writes dashboard/data/*.json

The JSON files are the contract between the pipelines and the frontend:
the dashboard reads ONLY these files, never the CSVs, so either side can
be rewritten independently. Every file carries generated_at and the
sampling step so the frontend can label extrapolations honestly.

All aggregation happens here, in Python. The browser gets pre-chewed
numbers and does no math beyond drawing.

EXTRAPOLATION
-------------
The datasets are sampled (typically every 100th block). Shares and
averages are sampling-invariant and exported as-is. Chain TOTALS are
estimated as (sampled sum x step) and marked "estimated": true — the
frontend must say so on any chart that uses them.
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


def sampling_step(rows):
    """Median gap between consecutive sampled heights."""
    hs = sorted(r["height"] for r in rows)
    if len(hs) < 2:
        return 1
    return int(statistics.median(b - a for a, b in zip(hs, hs[1:]))) or 1


def month_key(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m")


def write(name, payload, meta):
    payload["_meta"] = meta
    path = os.path.join(OUT, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    print(f"  wrote {path}")


def bootstrap_ci(values, step, iters=2000, conf=0.95):
    """95% CI for an extrapolated chain total from sampled blocks.

    Inscription bytes are heavy-tailed and bursty — most blocks near
    zero, a few in the hundreds of KB. That is exactly the shape where
    (sampled sum x step) is a noisy estimator, so a point estimate on
    its own is not publishable. Resampling with replacement gives the
    spread directly, without assuming a distribution.
    """
    if not values:
        return [0, 0, 0]
    n = len(values)
    point = sum(values) * step
    totals = []
    for _ in range(iters):
        totals.append(sum(random.choices(values, k=n)) * step)
    totals.sort()
    lo = totals[int((1 - conf) / 2 * iters)]
    hi = totals[int((1 - (1 - conf) / 2) * iters) - 1]
    return [point, lo, hi]


# Envelopes are OP_FALSE OP_IF ... OP_ENDIF — an unexecutable branch.
# Nothing inside is ever evaluated by the script interpreter, so an
# envelope has no monetary function; carrying data is all it can do.
# Every envelope therefore counts as non-monetary regardless of which
# protocol wrote it. The `ord` split below exists ONLY so the figure is
# comparable to trackers that count Ordinals alone — it is not a
# correctness filter, and using it alone understates the total.
ORD_PROTOCOLS = {"ord"}


def main():
    os.makedirs(OUT, exist_ok=True)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    W_INT = ["height", "block_time", "block_size", "block_strippedsize",
             "witness_bytes", "envelope_bytes", "content_bytes",
             "overhead_bytes", "residual_bytes", "envelope_count",
             "envelope_txs", "envelope_fees_sat", "largest_content_bytes",
             "tx_count"]
    O_INT = ["height", "block_time", "tx_count", "block_vsize", "or_txs",
             "or_outputs", "or_bytes", "or_max_size", "nonstandard_txs",
             "excess_bytes", "over_by_size_txs", "over_by_count_txs",
             "nonstandard_fees_sat"]
    T_INT = ["height", "block_time", "envelopes", "content_bytes",
             "envelope_bytes"]

    wb = read_csv("witness_blocks.csv", W_INT)
    # opreturn_blocks.csv is the current name; blocks.csv is the pre-rename
    # name, still read so an older dataset exports without a rebuild.
    ob, ob_src = read_first(["opreturn_blocks.csv", "blocks.csv"], O_INT)
    ct, ct_src = read_first(
        ["witness_content_types.csv", "content_types.csv"], T_INT)

    if not wb and not ob:
        raise SystemExit("No datasets found in data/. Run the builders first.")

    datasets = {}
    if wb:
        wb.sort(key=lambda r: r["height"])
        datasets["witness"] = {
            "source": "witness_blocks.csv",
            "blocks": len(wb),
            "step": sampling_step(wb),
            "height_range": [wb[0]["height"], wb[-1]["height"]],
            "date_range": [month_key(wb[0]["block_time"]),
                           month_key(wb[-1]["block_time"])],
        }
    if ob:
        ob.sort(key=lambda r: r["height"])
        datasets["opreturn"] = {
            "source": ob_src,
            "blocks": len(ob),
            "step": sampling_step(ob),
            "height_range": [ob[0]["height"], ob[-1]["height"]],
            "date_range": [month_key(ob[0]["block_time"]),
                           month_key(ob[-1]["block_time"])],
        }

    meta = {"generated_at": generated_at, "datasets": datasets,
            "events": EVENTS}
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

    # Split envelope/content bytes by ord vs other protocols, per month.
    ord_monthly = defaultdict(lambda: defaultdict(int))
    for r in ct:
        m = ord_monthly[month_key(r["block_time"])]
        bucket = "ord" if r["protocol"] in ORD_PROTOCOLS else "other"
        m[f"{bucket}_content"] += r["content_bytes"]
        m[f"{bucket}_envelope"] += r["envelope_bytes"]

    if wb:
        step = datasets["witness"]["step"]
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
                round(w_monthly[m]["envelope_bytes"] * step / 1e6, 1)
                for m in months],
            "envelopes_sampled": [
                w_monthly[m]["envelope_count"] for m in months],
            "estimated": True, "step": step,
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
        step = datasets["opreturn"]["step"]
        months = sorted(o_monthly)
        write("opreturn_monthly.json", {
            "months": months,
            "or_kb_est": [
                round(o_monthly[m]["or_bytes"] * step / 1e3, 1)
                for m in months],
            "excess_kb_est": [
                round(o_monthly[m]["excess_bytes"] * step / 1e3, 2)
                for m in months],
            "nonstandard_txs_sampled": [
                o_monthly[m]["nonstandard_txs"] for m in months],
            "estimated": True, "step": step,
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
    all_months = sorted(set(w_monthly) | set(o_monthly))
    if all_months:
        w_step = datasets.get("witness", {}).get("step", 1)
        o_step = datasets.get("opreturn", {}).get("step", 1)

        series = {k: [] for k in (
            "witness_content_mb", "witness_envelope_mb",
            "witness_content_ord_mb", "witness_content_other_mb",
            "opreturn_mb")}
        run = defaultdict(float)
        for m in all_months:
            run["wc"] += w_monthly[m]["content_bytes"] * w_step / 1e6
            run["we"] += w_monthly[m]["envelope_bytes"] * w_step / 1e6
            run["wo"] += ord_monthly[m]["ord_content"] * w_step / 1e6
            run["wx"] += ord_monthly[m]["other_content"] * w_step / 1e6
            run["or"] += o_monthly[m]["or_bytes"] * o_step / 1e6
            series["witness_content_mb"].append(round(run["wc"], 1))
            series["witness_envelope_mb"].append(round(run["we"], 1))
            series["witness_content_ord_mb"].append(round(run["wo"], 1))
            series["witness_content_other_mb"].append(round(run["wx"], 1))
            series["opreturn_mb"].append(round(run["or"], 1))

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

        ci = {}
        if wb:
            ci["witness_content_mb"] = [round(v / 1e6, 1) for v in bootstrap_ci(
                [r["content_bytes"] for r in wb], w_step)]
            ci["witness_envelope_mb"] = [round(v / 1e6, 1) for v in bootstrap_ci(
                [r["envelope_bytes"] for r in wb], w_step)]
        if ob:
            ci["opreturn_mb"] = [round(v / 1e6, 1) for v in bootstrap_ci(
                [r["or_bytes"] for r in ob], o_step)]

        write("cumulative.json", {
            "months": all_months,
            **series,
            "estimated": True,
            "ci95": ci,
            "coverage": {
                "witness": datasets.get("witness", {}).get("date_range"),
                "opreturn": datasets.get("opreturn", {}).get("date_range"),
            },
        }, meta)

    # ---- media families ----------------------------------------------------
    if ct:
        fams = defaultdict(lambda: {"n": 0, "bytes": 0})
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

        for r in ct:
            f = fams[family(r["content_type"])]
            f["n"] += r["envelopes"]
            f["bytes"] += r["content_bytes"]

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
        }, meta)

    print(f"\nExport complete — {generated_at}")
    for name, d in datasets.items():
        print(f"  {name}: {d['blocks']:,} blocks, step {d['step']}, "
              f"{d['date_range'][0]} to {d['date_range'][1]}")
    print("\nView it:  cd dashboard && python -m http.server 8000")
    print("Then open http://localhost:8000")


if __name__ == "__main__":
    main()
