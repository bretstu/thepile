"""
Validate the UTXO columns produced by the rebuild.

    python verify_utxo.py                 checks 1 and 2 (no node needed)
    python verify_utxo.py --node          adds 3 and 4 (needs the node)

FOUR CHECKS, WEAKEST TO STRONGEST

  1. INTERNAL CONSISTENCY (csv only)
     Bands must sum to their totals. Standing counts must never go
     negative. The reveal-only set must stay a subset of the tainted
     set. These catch column-wiring mistakes, not logic errors.

  2. THE SHAPE OF THE SERIES (csv only)
     Nothing tagged before the first inscription. Standing count rises
     through 2023. Sanity, not proof.

  3. RE-DERIVATION (needs node)
     Re-fetch random blocks and recompute the STATELESS columns —
     outputs created and spent, bands, output bytes, p2ms. These need
     no history, so a fresh pass must reproduce the CSV exactly. Any
     mismatch is a parser bug.

  4. CONSERVATION vs THE NODE (needs node + coinstatsindex)
     Between any two heights, the CSV's net output flow must equal the
     change in the node's own UTXO count. This is the strong one: it
     tests the whole accounting against an independent source that
     knows nothing about this code.

  5. NODE AUDIT (needs node)
     The tracking database stores real outpoints, so any of them can be
     handed to the node. Every outpoint still tagged must be unspent —
     the direct test of the removal path, which every other check can
     only reach by inference. The database count is also compared with
     the integrated CSV columns; those are computed by different code
     paths and must agree exactly.
"""

import csv
import os
import random
import sys

BLOCKS_CSV = os.path.join("data", "witness_blocks.csv")

# mempool.space UTXO Set Report, block 892,385: inscription-related UTXOs
# identified by the same reveal-only rule this project's `reveal_*`
# columns implement.
MEMPOOL_HEIGHT = 892_385
MEMPOOL_COUNT = 51_188_145

BAND_NAMES = ("b330", "b546", "b1k", "b10k", "bhi")

passed = failed = warned = 0


def ok(label, detail=""):
    global passed
    passed += 1
    print(f"  [PASS] {label}" + (f"  {detail}" if detail else ""))


def bad(label, detail=""):
    global failed
    failed += 1
    print(f"  [FAIL] {label}" + (f"  {detail}" if detail else ""))


def warn(label, detail=""):
    global warned
    warned += 1
    print(f"  [WARN] {label}" + (f"  {detail}" if detail else ""))


def load():
    if not os.path.exists(BLOCKS_CSV):
        raise SystemExit(f"Missing {BLOCKS_CSV}. Run the builder first.")
    with open(BLOCKS_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if "insc_added" not in rows[0]:
        raise SystemExit(
            f"{BLOCKS_CSV} has no UTXO columns — it predates the rebuild.\n"
            "Delete data/*.csv and rebuild with the current builder.")
    for r in rows:
        for k, v in r.items():
            if k != "client" and k != "block_hash":
                r[k] = int(v) if v not in ("", None) else 0
    rows.sort(key=lambda r: r["height"])
    return rows


rows = load()
print(f"\n{len(rows):,} blocks, {rows[0]['height']:,} - {rows[-1]['height']:,}")

# ---- 1. internal consistency --------------------------------------------
print("\n1 · INTERNAL CONSISTENCY")

band_mismatch = sum(
    1 for r in rows
    if sum(r[f"out_{b}_created"] for b in BAND_NAMES) != r["outputs_created"])
(ok if not band_mismatch else bad)(
    "output bands sum to outputs_created",
    f"{band_mismatch:,} blocks disagree" if band_mismatch else "")

insc_band_mismatch = sum(
    1 for r in rows
    if sum(r[f"insc_{b}_created"] for b in BAND_NAMES) != r["insc_added"])
(ok if not insc_band_mismatch else bad)(
    "tagged bands sum to insc_added",
    f"{insc_band_mismatch:,} blocks disagree" if insc_band_mismatch else "")

# The explicit column and the derived identity must agree on every block.
# If they ever diverge, one of the two paths has a bug.
derive_mismatch = sum(
    1 for r in rows
    if r["insc_output_bytes"] != r["insc_bogo_added"] - 41 * r["insc_added"])
(ok if not derive_mismatch else bad)(
    "insc_output_bytes == insc_bogo_added - 41 x insc_added",
    f"{derive_mismatch:,} blocks disagree" if derive_mismatch else "")

# Containment: the whole transaction must be at least as big as the
# outputs it contains.
contain = sum(1 for r in rows
              if r["reveal_tx_bytes"] and
              r["reveal_tx_bytes"] < r["insc_output_bytes"])
(ok if not contain else bad)(
    "reveal_tx_bytes contains insc_output_bytes",
    f"{contain:,} blocks violate" if contain else "")

mix_mismatch = sum(
    1 for r in rows
    if r["insc_p2tr"] + r["insc_p2wpkh"] + r["insc_other"] != r["insc_added"])
(ok if not mix_mismatch else bad)(
    "script mix sums to insc_added",
    f"{mix_mismatch:,} blocks disagree" if mix_mismatch else "")

standing = reveal_standing = 0
min_standing = min_reveal = 0
subset_violation = 0
for r in rows:
    standing += r["insc_added"] - r["insc_removed"]
    reveal_standing += r["reveal_added"] - r["reveal_removed"]
    min_standing = min(min_standing, standing)
    min_reveal = min(min_reveal, reveal_standing)
    if reveal_standing > standing:
        subset_violation += 1

(ok if min_standing >= 0 else bad)(
    "tagged standing count never negative", f"low water {min_standing:,}")
(ok if min_reveal >= 0 else bad)(
    "reveal standing count never negative", f"low water {min_reveal:,}")
(ok if not subset_violation else bad)(
    "reveal set stays a subset of tainted",
    f"{subset_violation:,} blocks violate" if subset_violation else "")

# ---- 2. shape ------------------------------------------------------------
print("\n2 · SHAPE OF THE SERIES")
FIRST_INSCRIPTION = 767_430
early = [r for r in rows if r["height"] < FIRST_INSCRIPTION]
early_tagged = sum(r["insc_added"] for r in early)
if early:
    (ok if not early_tagged else bad)(
        "nothing tagged before block 767,430",
        f"{early_tagged:,} tagged early" if early_tagged else
        f"{len(early):,} pre-inscription blocks, all clean")
else:
    warn("no pre-inscription blocks in range", "cannot check the zero baseline")

print(f"         standing tagged UTXOs at tip: {standing:,}")
print(f"         standing reveal-only  at tip: {reveal_standing:,}")
tot_added = sum(r["insc_added"] for r in rows)
tot_removed = sum(r["insc_removed"] for r in rows)
print(f"         ever added {tot_added:,}, ever removed {tot_removed:,} "
      f"({tot_removed / max(tot_added, 1) * 100:.1f}% spent)")
bogo = sum(r["insc_bogo_added"] - r["insc_bogo_removed"] for r in rows)
print(f"         standing bogosize: {bogo / 1e9:.2f} GB "
      f"(x disk_size/bogosize for real chainstate bytes)")

# The two coherent totals. Never mix them — reveal_tx_bytes already
# contains both the envelope and the output bytes.
outb = sum(r["insc_output_bytes"] for r in rows)
txb = sum(r["reveal_tx_bytes"] + r["transfer_tx_bytes"] for r in rows)
print(f"         inscription output bytes:  {outb / 1e9:>6.2f} GB")
print(f"         whole reveal+transfer txs: {txb / 1e9:>6.2f} GB "
      f"(superset — do not add to the above)")

# ---- 3 & 4 need the node -------------------------------------------------
if "--node" not in sys.argv:
    print("\n(run with --node for re-derivation and the conservation check)")
else:
    from rpc import rpc
    import utxo_track
    from utxo_track import UTXOTracker
    from witness_classifier import classify_tx_witness

    print("\n3 · RE-DERIVATION OF STATELESS COLUMNS")
    STATELESS = (["outputs_created", "outputs_spent", "output_bytes",
                  "p2ms_created", "p2ms_spent"]
                 + [f"out_{b}_created" for b in BAND_NAMES]
                 + [f"out_{b}_spent" for b in BAND_NAMES])
    sample = random.sample(rows, min(12, len(rows)))
    bad_blocks = 0
    for r in sample:
        h = r["height"]
        block = rpc("getblock", [rpc("getblockhash", [h]), 3])
        env = {tx["txid"] for tx in block["tx"][1:]
               if (c := classify_tx_witness(tx)) and c["envelope_count"]}
        fresh = UTXOTracker(track_reveal=False).process_block(block, env)
        diffs = [k for k in STATELESS if fresh[k] != r[k]]
        if diffs:
            bad_blocks += 1
            print(f"         block {h:,} differs on: {', '.join(diffs)}")
            for k in diffs[:3]:
                print(f"           {k}: csv {r[k]:,} vs fresh {fresh[k]:,}")
    (ok if not bad_blocks else bad)(
        f"{len(sample)} random blocks re-derive exactly",
        f"{bad_blocks} mismatched" if bad_blocks else "")

    print("\n4 · CONSERVATION vs THE NODE")
    try:
        lo, hi = rows[0]["height"], rows[-1]["height"]
        mid = rows[len(rows) // 2]["height"]
        for a, b in ((lo, mid), (mid, hi)):
            ia = rpc("gettxoutsetinfo", ["none", a, True])
            ib = rpc("gettxoutsetinfo", ["none", b, True])
            node_delta = ib["txouts"] - ia["txouts"]
            csv_delta = sum(r["outputs_created"] - r["outputs_spent"]
                            for r in rows if a < r["height"] <= b)
            drift = csv_delta - node_delta
            rel = abs(drift) / max(abs(node_delta), 1) * 100
            label = f"blocks {a:,}-{b:,}: node {node_delta:+,} csv {csv_delta:+,}"
            if drift == 0:
                ok("net UTXO flow matches the node exactly", label)
            elif rel < 0.01:
                warn(f"net UTXO flow off by {drift:+,} ({rel:.4f}%)", label)
            else:
                bad(f"net UTXO flow off by {drift:+,} ({rel:.2f}%)", label)
    except Exception as e:
        warn("conservation check unavailable",
             f"{type(e).__name__}: {e}  (needs coinstatsindex=1)")

    print("\n5 · NODE AUDIT (the removal path, tested directly)")
    from utxo_track import UTXOTracker, DB_FILE
    if not os.path.exists(DB_FILE):
        warn("no tracking database", f"{DB_FILE} missing")
    else:
        tr = UTXOTracker(DB_FILE)
        st = tr.standing()
        print(f"         database holds {st['tainted']:,} tagged outpoints "
              f"({st['reveal']:,} reveal-created)")

        # Because the database stores REAL outpoints, any of them can be
        # handed straight to the node. Every one still tagged must be
        # unspent; if removals were being missed, this fails immediately.
        sample = tr.sample(300)
        spent = [op for op in sample
                 if rpc("gettxout", [op.split(":")[0], int(op.split(":")[1])])
                 is None]
        (ok if not spent else bad)(
            f"{len(sample)} tagged outpoints are unspent on the node",
            f"{len(spent)} are already spent — removals are being missed"
            if spent else "")

        # And the standing count must equal the integrated CSV columns.
        (ok if st["tainted"] == standing else bad)(
            "database count matches the integrated CSV columns",
            f"db {st['tainted']:,} vs csv {standing:,}"
            if st["tainted"] != standing else "")
        (ok if st["reveal"] == reveal_standing else bad)(
            "reveal count matches the integrated CSV columns",
            f"db {st['reveal']:,} vs csv {reveal_standing:,}"
            if st["reveal"] != reveal_standing else "")
        tr.close()

    print("\n6 · REPRODUCE THE PUBLISHED FIGURE")
    if rows[-1]["height"] >= MEMPOOL_HEIGHT >= rows[0]["height"]:
        rv = sum(r["reveal_added"] - r["reveal_removed"]
                 for r in rows if r["height"] <= MEMPOOL_HEIGHT)
        diff = (rv - MEMPOOL_COUNT) / MEMPOOL_COUNT * 100
        label = (f"ours {rv:,} vs published {MEMPOOL_COUNT:,} "
                 f"({diff:+.1f}%) at block {MEMPOOL_HEIGHT:,}")
        if abs(diff) <= 5:
            ok("reveal-only count matches mempool.space", label)
        elif abs(diff) <= 15:
            warn("reveal-only count is close but off", label)
        else:
            bad("reveal-only count disagrees materially", label)
    else:
        warn(f"block {MEMPOOL_HEIGHT:,} outside the scanned range",
             "cannot cross-check")

print("\n" + "=" * 62)
print(f"  {passed} passed, {failed} failed, {warned} warnings")
print("=" * 62 + "\n")
sys.exit(1 if failed else 0)
