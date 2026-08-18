"""
Query the witness/inscription dataset.

    python witness_explore.py summary          headline numbers
    python witness_explore.py monthly          month-by-month trend
    python witness_explore.py types            what is stored (MIME types)
    python witness_explore.py top [n]          largest inscriptions
    python witness_explore.py block <height>   one block in full
    python witness_explore.py audit            verify the accounting

Reads data/witness_*.csv.
No node required.

`audit` is the command to run FIRST after any build: it checks the
byte-accounting identity on every block and reports residual (bytes the
parser could not attribute) so you always know your coverage before
quoting a number.
"""

import csv
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

DATA = "data"

# Chart-annotation dates (see witness_classifier.py docstring)
FIRST_INSCRIPTION_DATE = datetime(2022, 12, 14, tzinfo=timezone.utc)

INT_COLS = {
    "height", "block_time", "tx_count", "block_weight", "block_vsize",
    "block_size", "block_strippedsize", "witness_serialized_bytes",
    "witness_bytes", "envelope_bytes", "content_bytes", "payload_bytes",
    "overhead_bytes", "residual_bytes", "annex_bytes",
    "envelope_txs", "envelope_count", "largest_content_bytes",
    "envelope_fees_sat", "p2tr_keypath_inputs", "p2tr_scriptpath_inputs",
    "p2wsh_inputs", "p2wpkh_inputs", "other_witness_inputs",
    "envelopes", "tx_vsize", "tx_weight", "tx_fee_sat",
    "tx_envelope_count",
}


def load(name):
    path = os.path.join(DATA, f"{name}.csv")
    if not os.path.exists(path):
        raise SystemExit(f"Missing {path}. Run witness_build_dataset.py first.")
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


def mb(n):
    return f"{n / 1e6:,.2f}MB"


# --------------------------------------------------------------------------

def cmd_audit():
    """Verify the accounting identity and report parser coverage."""
    b = load("witness_blocks")
    bad = [r for r in b
           if r["envelope_bytes"] + r["overhead_bytes"] + r["residual_bytes"]
           != r["witness_bytes"]]

    wit = sum(r["witness_bytes"] for r in b)
    env = sum(r["envelope_bytes"] for r in b)
    ovh = sum(r["overhead_bytes"] for r in b)
    res = sum(r["residual_bytes"] for r in b)
    ser = sum(r["witness_serialized_bytes"] for r in b)

    print(f"\nACCOUNTING AUDIT — {len(b):,} blocks")
    print(f"\n  identity (env + overhead + residual == witness):")
    print(f"    violations: {len(bad)}  "
          f"{'<- INVESTIGATE' if bad else '(exact on every block)'}")
    for r in bad[:5]:
        print(f"      block {r['height']:,}")

    print(f"\n  where witness bytes went:")
    print(f"    envelopes (data storage)   {mb(env):>12}  ({env / wit * 100:5.1f}%)"
          if wit else "    (no witness bytes)")
    if wit:
        print(f"    overhead (sigs, control)   {mb(ovh):>12}  ({ovh / wit * 100:5.1f}%)")
        print(f"    residual (unattributed)    {mb(res):>12}  ({res / wit * 100:5.1f}%)")

    print(f"\n  vs node-reported serialized witness (independent measure):")
    print(f"    our element bytes          {mb(wit):>12}")
    print(f"    node size - strippedsize   {mb(ser):>12}")
    if ser:
        gap = ser - wit
        print(f"    gap                        {mb(gap):>12}  ({gap / ser * 100:5.2f}%)")
        print(f"    (gap = compact-size length prefixes + segwit marker/flag;")
        print(f"     a few percent is expected. A LARGE gap means parser bug.)")

    hi = sorted(b, key=lambda r: -r["residual_bytes"])[:5]
    print(f"\n  largest residuals (novel-construct discovery queue):")
    for r in hi:
        share = (r["residual_bytes"] / r["witness_bytes"] * 100) if r["witness_bytes"] else 0
        print(f"    block {r['height']:,}  {r['residual_bytes']:>10,}B "
              f"({share:.1f}% of its witness)")
    print()


def cmd_summary():
    b = load("witness_blocks")
    b.sort(key=lambda r: r["height"])
    pre = [r for r in b if when(r["block_time"]) < FIRST_INSCRIPTION_DATE]
    post = [r for r in b if when(r["block_time"]) >= FIRST_INSCRIPTION_DATE]

    print(f"\n{len(b):,} blocks | {when(b[0]['block_time']):%Y-%m-%d} "
          f"to {when(b[-1]['block_time']):%Y-%m-%d}")
    print("Sampled, not exhaustive — scale by your step for chain totals.\n")

    for label, g in (("PRE-INSCRIPTION", pre), ("INSCRIPTION ERA", post)):
        if not g:
            continue
        blk_bytes = sum(r["block_size"] for r in g)
        print(f"--- {label}  ({len(g):,} blocks) ---")
        print(f"  block bytes                {mb(blk_bytes):>12}")
        print(f"  witness bytes              {mb(sum(r['witness_bytes'] for r in g)):>12}")
        env = sum(r["envelope_bytes"] for r in g)
        con = sum(r["content_bytes"] for r in g)
        print(f"  ENVELOPE BYTES             {mb(env):>12}"
              f"  ({env / blk_bytes * 100:.2f}% of all block bytes)")
        print(f"  CONTENT BYTES (the files)  {mb(con):>12}")
        print(f"  envelopes                  {sum(r['envelope_count'] for r in g):>12,}")
        print(f"  txs carrying envelopes     {sum(r['envelope_txs'] for r in g):>12,}")
        print(f"  fees paid by those txs     {sum(r['envelope_fees_sat'] for r in g):>12,} sat")
        print(f"  blocks w/ any envelope     "
              f"{sum(1 for r in g if r['envelope_count']):>12,}"
              f"  ({sum(1 for r in g if r['envelope_count']) / len(g) * 100:.1f}%)")
        print()

    print("CONTENT BYTES = ord-convention body (the actual stored file).")
    print("ENVELOPE BYTES = full envelope incl. protocol fields.")
    print("Run `audit` for parser coverage before quoting these.\n")


def cmd_monthly():
    b = load("witness_blocks")
    m = defaultdict(lambda: defaultdict(int))
    for r in b:
        k = month(r["block_time"])
        for f in ("block_size", "witness_bytes", "envelope_bytes",
                  "content_bytes", "residual_bytes", "envelope_count",
                  "envelope_txs", "tx_count"):
            m[k][f] += r[f]
        m[k]["blocks"] += 1
        m[k]["largest"] = max(m[k]["largest"], r["largest_content_bytes"])

    print(f"\n{'month':<9}{'blks':>5}{'envelopes':>11}{'content':>11}"
          f"{'env%blk':>9}{'resid':>10}{'largest':>10}")
    print("-" * 66)
    for k in sorted(m):
        d = m[k]
        share = d["envelope_bytes"] / d["block_size"] * 100 if d["block_size"] else 0
        print(f"{k:<9}{d['blocks']:>5}{d['envelope_count']:>11,}"
              f"{mb(d['content_bytes']):>11}{share:>8.2f}%"
              f"{mb(d['residual_bytes']):>10}"
              f"{d['largest'] / 1e3:>8,.0f}KB")
    print()


# Broad media families for the headline view. Grouping is an ANALYSIS
# decision, applied here rather than at parse time: the CSV stores the
# exact declared content type, so regrouping never requires a rescan.
MEDIA_FAMILIES = [
    ("image/", "image"),
    ("video/", "video"),
    ("audio/", "audio"),
    ("model/", "3d model"),
    ("font/", "font"),
    ("text/html", "html"),
    ("text/javascript", "javascript"),
    ("text/", "text"),
    ("application/json", "json"),
    ("application/", "application"),
]


def base_type(ctype):
    """Strip MIME parameters: 'text/plain;charset=utf-8' -> 'text/plain'."""
    return (ctype or "").split(";")[0].strip().lower()


def media_family(ctype):
    b = base_type(ctype)
    if not b:
        return "(none)"
    if b.startswith("bin:"):
        return "(non-ascii)"
    for prefix, family in MEDIA_FAMILIES:
        if b.startswith(prefix):
            return family
    return "other"


def cmd_types(mode="family"):
    """Content breakdown. mode: family | base | exact"""
    t = load("witness_content_types")

    keyer = {
        "family": lambda r: (media_family(r["content_type"]),),
        "base": lambda r: (r["protocol"], base_type(r["content_type"]) or "(none)"),
        "exact": lambda r: (r["protocol"], r["content_type"] or "(none)"),
    }.get(mode)
    if keyer is None:
        raise SystemExit("mode must be one of: family, base, exact")

    agg = defaultdict(lambda: defaultdict(int))
    for r in t:
        v = agg[keyer(r)]
        v["n"] += r["envelopes"]
        v["content"] += r["content_bytes"]
        v["envelope"] += r["envelope_bytes"]

    total_c = sum(v["content"] for v in agg.values()) or 1
    total_n = sum(v["n"] for v in agg.values()) or 1

    label = {"family": "MEDIA FAMILY", "base": "BASE TYPE",
             "exact": "EXACT DECLARED TYPE"}[mode]
    width = 20 if mode == "family" else 46
    print(f"\n{label}   ({len(agg):,} groups)\n")
    print(f"{'':<{width}}{'envelopes':>12}{'env%':>7}"
          f"{'content':>11}{'byte%':>8}{'avg size':>10}")
    print("-" * (width + 48))
    for k, v in sorted(agg.items(), key=lambda kv: -kv[1]["content"])[:30]:
        name = " ".join(str(x) for x in k)
        print(f"{name[:width - 1]:<{width}}{v['n']:>12,}"
              f"{v['n'] / total_n * 100:>6.1f}%{mb(v['content']):>11}"
              f"{v['content'] / total_c * 100:>7.1f}%"
              f"{v['content'] / v['n'] if v['n'] else 0:>9,.0f}B")
    print(f"\nTotals: {total_n:,} envelopes, {mb(total_c)} content")
    if mode == "family":
        print("Grouping is applied at query time; the CSV holds exact types.")
        print("Use `types base` or `types exact` for finer detail.\n")
    else:
        print()


def cmd_top(n=20):
    d = load("witness_inscription_details")
    d.sort(key=lambda r: -r["content_bytes"])
    print(f"\n{'height':>9}  {'date':<11}{'content':>10}{'type':<28} txid")
    print("-" * 100)
    for r in d[:int(n)]:
        print(f"{r['height']:>9,}  {when(r['block_time']):%Y-%m-%d} "
              f"{r['content_bytes'] / 1e3:>8,.1f}KB  "
              f"{(r['content_type'] or '(none)')[:27]:<28} {r['txid'][:24]}...")
    print("\nVerify any of these at https://ordinals.com/tx/<txid> or mempool.space\n")


def cmd_block(height):
    height = int(height)
    b = next((r for r in load("witness_blocks") if r["height"] == height), None)
    if not b:
        raise SystemExit(f"Block {height:,} not in dataset.")

    print(f"\nBLOCK {height:,}   {when(b['block_time']):%Y-%m-%d %H:%M:%S} UTC")
    print(f"  hash {b['block_hash']}")
    print(f"  {b['tx_count']:,} txs | size {mb(b['block_size'])} | "
          f"stripped {mb(b['block_strippedsize'])}")
    print(f"\n  WITNESS ACCOUNTING")
    print(f"    element bytes      {b['witness_bytes']:>12,}")
    print(f"    envelope           {b['envelope_bytes']:>12,}")
    print(f"    content (files)    {b['content_bytes']:>12,}")
    print(f"    overhead           {b['overhead_bytes']:>12,}")
    print(f"    residual           {b['residual_bytes']:>12,}")
    ok = (b["envelope_bytes"] + b["overhead_bytes"] + b["residual_bytes"]
          == b["witness_bytes"])
    print(f"    identity           {'exact' if ok else 'VIOLATED'}")
    print(f"\n  ACTIVITY")
    print(f"    envelopes          {b['envelope_count']:>12,}")
    print(f"    envelope txs       {b['envelope_txs']:>12,}")
    print(f"    largest content    {b['largest_content_bytes']:>12,} B")
    print(f"\n  INPUT MIX")
    for k, label in (("p2tr_keypath_inputs", "taproot key path"),
                     ("p2tr_scriptpath_inputs", "taproot script path"),
                     ("p2wsh_inputs", "p2wsh"),
                     ("p2wpkh_inputs", "p2wpkh"),
                     ("other_witness_inputs", "other")):
        print(f"    {label:<20}{b[k]:>10,}")

    ts = [r for r in load("witness_content_types") if r["height"] == height]
    if ts:
        print(f"\n  CONTENT TYPES")
        for r in sorted(ts, key=lambda r: -r["content_bytes"])[:12]:
            print(f"    {r['protocol']:<8}{(r['content_type'] or '(none)')[:34]:<36}"
                  f"{r['envelopes']:>6,}  {mb(r['content_bytes'])}")
    print()


COMMANDS = {
    "audit": cmd_audit, "summary": cmd_summary, "monthly": cmd_monthly,
    "types": cmd_types, "top": cmd_top, "block": cmd_block,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(__doc__)
        raise SystemExit(1)
    COMMANDS[sys.argv[1]](*sys.argv[2:])
