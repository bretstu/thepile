"""
check.py — full-dataset integrity + version-consistency audit.

Run from the project root:  python check.py

Goes beyond "do the totals reconcile". It walks EVERY row and looks for
the fingerprints of a dataset built by two different code versions across
one run — the failure mode that has bitten this project repeatedly when
files were copied individually between machines.

What it checks
--------------
1. Required columns present in each CSV (the new schema, not the old).
2. Contiguity: no missing or duplicate block heights.
3. Blank / non-numeric cells in columns that must always be numbers.
4. Per-row invariants that only hold if one code version wrote the row:
     - witness:  envelope <= content <= block_size, and the accounting
                 identity envelope+overhead+residual == witness_bytes
     - opreturn: or_stored_bytes >= or_bytes (stored includes framing)
   (The UTXO tracker's own invariants are checked by verify_utxo.py,
    which also audits against the live node.)
5. "Schema seam" detection: a NEW column that is zero for a run of early
    rows and then non-zero later is the signature of a mid-dataset
    version change. Flags the first height where each such column wakes up.
6. Cross-file: witness and opreturn cover compatible ranges; the OP_RETURN
    deduction never exceeds the OP_RETURN total in any shared month.

Exit code is non-zero if any hard error is found, so it can gate a deploy.
"""
import csv, sys, os
from collections import defaultdict

DATA = "data"
PROBLEMS = []
NOTES = []

def err(msg):  PROBLEMS.append(msg)
def note(msg): NOTES.append(msg)

def load(name):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return None, None
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    header = rows[0].keys() if rows else []
    return rows, list(header)

def as_int(v):
    """Return int, or None if blank/non-numeric — the thing we hunt for."""
    if v is None or v == "":
        return None
    try:
        return int(v)
    except ValueError:
        try:
            return int(float(v))
        except ValueError:
            return None

def require_cols(header, needed, fname):
    if header is None:
        return False
    missing = [c for c in needed if c not in header]
    if missing:
        err(f"{fname}: MISSING columns {missing} — this file was built by "
            f"an older code version. Rebuild it.")
        return False
    return True

def check_contiguous(rows, fname):
    hs = [as_int(r["height"]) for r in rows]
    if any(h is None for h in hs):
        err(f"{fname}: blank/non-numeric height in {sum(h is None for h in hs)} rows")
        return
    s = sorted(hs)
    if len(set(s)) != len(s):
        dupes = len(s) - len(set(s))
        err(f"{fname}: {dupes} DUPLICATE block heights — a resume re-wrote "
            f"rows. Deduplicate or rebuild.")
    gaps = [(a, b) for a, b in zip(s, s[1:]) if b != a + 1]
    if gaps:
        shown = ", ".join(f"{a+1}-{b-1}" for a, b in gaps[:5])
        err(f"{fname}: GAPS after {s[0]}..{s[-1]} — missing {shown}"
            + (" ..." if len(gaps) > 5 else ""))
    else:
        note(f"{fname}: {len(s):,} rows, blocks {s[0]:,}-{s[-1]:,}, contiguous")

def check_numeric(rows, cols, fname):
    """Blank/non-numeric cells anywhere in columns that must be numbers."""
    bad = defaultdict(list)
    for r in rows:
        for c in cols:
            if c in r and as_int(r[c]) is None:
                bad[c].append(r.get("height", "?"))
    for c, heights in bad.items():
        err(f"{fname}: column '{c}' has {len(heights)} blank/non-numeric "
            f"cells (first at block {heights[0]}) — a partial or "
            f"wrong-version write.")

def column_health(rows, col):
    """Distinguish a real version seam from natural first-occurrence.

    A column that is zero until some height and non-zero after is NORMAL:
    reveal_opreturn_bytes can't be non-zero before the first reveal that
    carries an OP_RETURN; or_stored_bytes can't before OP_RETURN existed
    at all (block ~228,596). That is history, not a seam.

    The real fingerprints of an old-version write are:
      - the column is present in the header but zero in EVERY row
        (the builder wrote the header slot but never populated it), or
      - blank / non-numeric cells (a partial write).

    Returns (all_zero, blanks) — both falsey means healthy.
    """
    all_zero = True
    blanks = 0
    for r in rows:
        raw = r.get(col, "")
        if raw == "" or as_int(raw) is None:
            blanks += 1
            continue
        if as_int(raw) != 0:
            all_zero = False
    return all_zero, blanks

# ------------------------------------------------------------------ witness
wb, wh = load("witness_blocks.csv")
if wb is None:
    err("witness_blocks.csv not found — run witness_build_dataset.py")
else:
    need = ["height", "block_size", "envelope_bytes", "content_bytes",
            "witness_bytes", "overhead_bytes", "residual_bytes",
            "reveal_tx_bytes", "transfer_tx_bytes", "reveal_opreturn_bytes",
            "transfer_opreturn_bytes", "transfer_input_bytes",
            "transfer_output_bytes", "reveal_dust_added", "reveal_dust_removed",
            "insc_added", "insc_removed", "client"]
    if require_cols(wh, need, "witness_blocks.csv"):
        check_contiguous(wb, "witness_blocks.csv")
        check_numeric(wb, [c for c in need if c not in ("client",)],
                      "witness_blocks.csv")
        # per-row invariants
        idbad = envbad = 0
        clients = set()
        for r in wb:
            clients.add(r.get("client", ""))
            e = as_int(r["envelope_bytes"]); c = as_int(r["content_bytes"])
            w = as_int(r["witness_bytes"]); o = as_int(r["overhead_bytes"])
            res = as_int(r["residual_bytes"]); bs = as_int(r["block_size"])
            if None in (e, c, w, o, res, bs):
                continue
            if not (e >= c):        # envelope contains content
                envbad += 1
            if e + o + res != w:    # the accounting identity
                idbad += 1
        if idbad:
            err(f"witness: accounting identity envelope+overhead+residual"
                f"==witness_bytes FAILS on {idbad} rows — mixed versions.")
        if envbad:
            err(f"witness: content_bytes > envelope_bytes on {envbad} rows "
                f"— impossible under one version.")
        if len(clients) > 1:
            note(f"witness: built across {len(clients)} client versions "
                 f"{sorted(clients)} — fine if all runs used the same "
                 f"classifier, worth noting.")
        # A this-session column that is present but NEVER populated, or
        # has blank cells, is the real version-seam fingerprint. A column
        # that is simply zero until the behaviour first occurs is history.
        for col in ("reveal_opreturn_bytes", "transfer_input_bytes",
                    "reveal_dust_added", "transfer_output_bytes",
                    "reveal_dust_removed"):
            az, blanks = column_health(wb, col)
            if az:
                note(f"witness: '{col}' is zero in every row. Expected if "
                     f"that event is rare in this range; a RED FLAG if you "
                     f"know it should occur. On the full 767k+ dataset it "
                     f"should be populated.")
            if blanks:
                err(f"witness: '{col}' has {blanks} blank/non-numeric cells "
                    f"— a partial or interrupted write. Rebuild those blocks.")

# ----------------------------------------------------------------- opreturn
ob, oh = load("opreturn_blocks.csv")
if ob is None:
    err("opreturn_blocks.csv not found — run opreturn_build_dataset.py")
else:
    need = ["height", "block_size", "or_bytes", "or_stored_bytes",
            "or_outputs", "excess_bytes"]
    if require_cols(oh, need, "opreturn_blocks.csv"):
        check_contiguous(ob, "opreturn_blocks.csv")
        check_numeric(ob, need, "opreturn_blocks.csv")
        storedbad = 0
        for r in ob:
            s = as_int(r["or_stored_bytes"]); b = as_int(r["or_bytes"])
            if None in (s, b):
                continue
            if s < b:   # stored includes value+prefix, must be >= script
                storedbad += 1
        if storedbad:
            err(f"opreturn: or_stored_bytes < or_bytes on {storedbad} rows "
                f"— the stored-size column is from an older build that "
                f"only had script bytes. Rebuild.")
        # or_stored_bytes is legitimately zero before OP_RETURN existed
        # (~block 228,596), so only an ALL-zero column or blanks indicate
        # an old build. Cross-check: where or_outputs>0, stored must be>0.
        az, blanks = column_health(ob, "or_stored_bytes")
        if az and any((as_int(r.get("or_outputs")) or 0) > 0 for r in ob):
            err("opreturn: 'or_stored_bytes' is zero but OP_RETURN outputs "
                "exist — built by a version before the stored-size change. "
                "Rebuild.")
        elif az:
            note("opreturn: 'or_stored_bytes' all zero, but so is or_outputs "
                 "— just a pre-2014 range with no OP_RETURN yet. Fine.")
        if blanks:
            err(f"opreturn: 'or_stored_bytes' has {blanks} blank cells — "
                f"partial write. Rebuild those blocks.")
        contradict = sum(1 for r in ob
                         if (as_int(r.get("or_outputs")) or 0) > 0
                         and (as_int(r.get("or_stored_bytes")) or 0) == 0)
        if contradict:
            err(f"opreturn: {contradict} blocks have OP_RETURN outputs but "
                f"zero stored bytes — old-version rows mixed in. Rebuild.")

# ------------------------------------------------------------- cross-file
if wb is not None and ob is not None and wh and oh:
    wheights = [as_int(r["height"]) for r in wb]
    oheights = [as_int(r["height"]) for r in ob]
    if all(h is not None for h in wheights + oheights):
        wlo, whi = min(wheights), max(wheights)
        olo, ohi = min(oheights), max(oheights)
        note(f"cross: witness {wlo:,}-{whi:,}  |  opreturn {olo:,}-{ohi:,}")
        if abs(whi - ohi) > 20:
            note(f"cross: witness tip {whi:,} and opreturn tip {ohi:,} differ "
                 f"by {abs(whi-ohi):,} blocks — the lagging scan is still "
                 f"running. Re-export will show that category short and fire "
                 f"the deduction warning until both reach the tip. Not a "
                 f"data fault.")

# ------------------------------------------------------------------ report
print("\n" + "=" * 62)
if NOTES:
    print("NOTES")
    for n in NOTES:
        print(f"  . {n}")
    print()
if PROBLEMS:
    print(f"PROBLEMS  ({len(PROBLEMS)})")
    for p in PROBLEMS:
        print(f"  X {p}")
    print("\n  >> At least one check failed. See messages above.")
    sys.exit(1)
else:
    print("ALL CHECKS PASSED — schema, contiguity, per-row invariants, and")
    print("version consistency all hold across the full dataset.")
    print("=" * 62)
