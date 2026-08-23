"""
Tests for utxo_track.py — the traps that would silently corrupt the
standing UTXO count. No node required.

    python test_utxo_track.py
"""

import os
import sys

import tempfile
from utxo_track import (UTXOTracker, band_index, outpoint,
                        BAND_NAMES, BOGO_OVERHEAD)


def fresh():
    """A tracker on a throwaway database."""
    return UTXOTracker(os.path.join(tempfile.mkdtemp(), "t.db"))

passed = failed = 0


def check(label, got, want):
    global passed, failed
    if got == want:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL  {label}\n        got {got!r}\n        want {want!r}")


# ---- helpers to build fake blocks ----------------------------------------
P2TR = "5120" + "11" * 32          # OP_1 <32 bytes>   -> 34 bytes
P2WPKH = "0014" + "22" * 20        # OP_0 <20 bytes>   -> 22 bytes
NULLDATA = "6a" + "33" * 40


def out(sats, hexs=P2TR, typ="witness_v1_taproot"):
    return {"value": sats / 1e8, "scriptPubKey": {"hex": hexs, "type": typ}}


def vin(txid, vout, sats, hexs=P2TR, typ="witness_v1_taproot"):
    return {"txid": txid, "vout": vout,
            "prevout": {"value": sats / 1e8,
                        "scriptPubKey": {"hex": hexs, "type": typ}}}


def tx(txid, vins=(), vouts=()):
    return {"txid": txid, "vin": list(vins), "vout": list(vouts)}


def block(txs):
    # index 0 is always the coinbase
    return {"tx": [tx("cb" + "0" * 62, [{"coinbase": "00"}], [out(625_000_000)])] + txs}


print("\nBANDS")
check("330 is in the first band", band_index(330), 0)
check("331 moves to the next", band_index(331), 1)
check("546 boundary", band_index(546), 1)
check("1000 boundary", band_index(1000), 2)
check("10k boundary", band_index(10_000), 3)
check("above 10k", band_index(10_001), 4)

print("\nOUTPOINTS")
a = outpoint("ab" * 32, 0)
b = outpoint("ab" * 32, 1)
check("vout changes the outpoint", a == b, False)
check("outpoint is 36 bytes", len(a), 36)
check("txid round-trips", a[:32].hex(), "ab" * 32)
check("vout round-trips", int.from_bytes(a[32:], "big"), 0)
check("no hashing, so no collisions are possible",
      outpoint("ab" * 32, 7) == outpoint("ab" * 32, 7), True)

print("\nOP_RETURN IS NOT A UTXO")
t = fresh()
r = t.process_block(block([
    tx("aa" * 32, [vin("99" * 32, 0, 50_000)],
       [out(546), out(0, NULLDATA, "nulldata")])
]), envelope_txids=set())
check("nulldata excluded from created", r["outputs_created"], 2)   # coinbase + the 546
check("its bytes are still counted", r["output_bytes"] > 0, True)

print("\nCOINBASE")
t = fresh()
r = t.process_block(block([]), envelope_txids=set())
check("coinbase output counts", r["outputs_created"], 1)
check("coinbase input is not a spend", r["outputs_spent"], 0)

print("\nA REVEAL TAGS ITS OUTPUTS")
t = fresh()
rev = "bb" * 32
r = t.process_block(block([
    tx(rev, [vin("88" * 32, 0, 100_000)], [out(546), out(90_000)])
]), envelope_txids={rev})
check("both outputs tagged", r["insc_added"], 2)
check("sats recorded", r["insc_added_sats"], 546 + 90_000)
check("reveal set tracked separately", r["reveal_added"], 2)
check("bogosize per output", r["insc_bogo_added"], 2 * (BOGO_OVERHEAD + 34))
check("standing count", t.standing()["tainted"], 2)

print("\nSPENDING A TAGGED OUTPUT REMOVES IT")
r = t.process_block(block([
    tx("cc" * 32, [vin(rev, 0, 546)], [out(400)])
]), envelope_txids=set())
check("removal counted", r["insc_removed"], 1)
check("removal sats", r["insc_removed_sats"], 546)
# the transfer's own dust output inherits the tag
check("transfer propagates to dust", r["insc_added"], 1)
check("standing unchanged by a transfer", t.standing()["tainted"], 2)

print("\nTRANSFERS DO NOT TAINT REAL MONEY")
t2 = fresh()
rev2 = "dd" * 32
t2.process_block(block([
    tx(rev2, [vin("77" * 32, 0, 10_000)], [out(546)])
]), envelope_txids={rev2})
r = t2.process_block(block([
    # consolidates the dust into a 5,000,000 sat output
    tx("ee" * 32, [vin(rev2, 0, 546)], [out(5_000_000)])
]), envelope_txids=set())
check("dust removed", r["insc_removed"], 1)
check("large output NOT tagged", r["insc_added"], 0)
check("standing falls to zero", t2.standing()["tainted"], 0)

print("\nSAME-BLOCK CREATE THEN SPEND")
t3 = fresh()
rev3 = "f1" * 32
r = t3.process_block(block([
    tx(rev3, [vin("66" * 32, 0, 10_000)], [out(546)]),
    tx("f2" * 32, [vin(rev3, 0, 546)], [out(300)]),      # spends it same block
]), envelope_txids={rev3})
check("created and removed in one block", (r["insc_added"], r["insc_removed"]),
      (2, 1))       # the reveal's output, plus the transfer's dust
check("standing is 1", t3.standing()["tainted"], 1)

print("\nREVEAL-ONLY SET IGNORES TRANSFERS")
t4 = fresh()
rev4 = "a1" * 32
t4.process_block(block([tx(rev4, [vin("55" * 32, 0, 9_000)], [out(546)])]),
                 envelope_txids={rev4})
t4.process_block(block([tx("a2" * 32, [vin(rev4, 0, 546)], [out(500)])]),
                 envelope_txids=set())
s = t4.standing()
check("tainted keeps the transferred dust", s["tainted"], 1)
check("reveal-only decays to zero", s["reveal"], 0)

print("\nSCRIPT MIX AND P2MS")
t5 = fresh()
rev5 = "b1" * 32
r = t5.process_block(block([
    tx(rev5, [vin("44" * 32, 0, 9_000)],
       [out(330), out(294, P2WPKH, "witness_v0_keyhash"),
        out(600, "51" + "21" * 33 + "51ae", "multisig")])
]), envelope_txids={rev5})
check("p2tr counted", r["insc_p2tr"], 1)
check("p2wpkh counted", r["insc_p2wpkh"], 1)
check("other counted", r["insc_other"], 1)
check("p2ms created", r["p2ms_created"], 1)

print("\nBANDS ON CREATE AND SPEND")
t6 = fresh()
rev6 = "c1" * 32
r = t6.process_block(block([
    tx(rev6, [vin("33" * 32, 0, 900_000)],
       [out(330), out(500), out(900), out(5_000), out(800_000)])
]), envelope_txids={rev6})
check("b330", r["insc_b330_created"], 1)
check("b546", r["insc_b546_created"], 1)
check("b1k", r["insc_b1k_created"], 1)
check("b10k", r["insc_b10k_created"], 1)
check("bhi", r["insc_bhi_created"], 1)
check("all outputs banded too",
      sum(r[f"out_{b}_created"] for b in BAND_NAMES),
      r["outputs_created"])

print("\nSTATE SURVIVES A RESTART")
path = os.path.join(tempfile.mkdtemp(), "resume.db")
t7 = UTXOTracker(path)
rev7 = "d1" * 32
t7.process_block(block([tx(rev7, [vin("22" * 32, 0, 9_000)],
                          [out(546), out(600)])]), envelope_txids={rev7})
t7.commit(900_000)
before = t7.standing()
t7.close()

t8 = UTXOTracker(path)                     # reopen, as a resumed build would
check("height restored", t8.height, 900_000)
check("tagged set restored", t8.standing(), before)
r = t8.process_block(block([tx("d2" * 32, [vin(rev7, 0, 546)], [out(200)])]),
                     envelope_txids=set())
check("removes an outpoint from before the restart", r["insc_removed"], 1)

print("\nSAMPLING FOR THE NODE AUDIT")
t9 = fresh()
rv = "e1" * 32
t9.process_block(block([tx(rv, [vin("11" * 32, 0, 9_000)],
                          [out(546), out(700)])]), envelope_txids={rv})
sam = t9.sample(10)
check("sample returns txid:vout strings", len(sam), 2)
check("sample is parseable", all(":" in x and len(x.split(":")[0]) == 64
                                 for x in sam), True)
check("sample matches what is tagged", sorted(x.split(":")[1] for x in sam),
      ["0", "1"])

print("\nCOST COLUMNS AND THEIR CONTAINMENT")
t10 = fresh()
rv = "f9" * 32
P2TR_LEN = 34
blk = block([tx(rv, [vin("88" * 32, 0, 60_000)], [out(546), out(50_000)])])
blk["tx"][1]["size"] = 6829            # the node reports this
r = t10.process_block(blk, envelope_txids={rv})
check("output bytes recorded", r["insc_output_bytes"], 2 * (8 + 1 + P2TR_LEN))
check("output bytes == bogo - 41n",
      r["insc_output_bytes"], r["insc_bogo_added"] - 41 * r["insc_added"])
check("reveal tx bytes from the node's size field", r["reveal_tx_bytes"], 6829)
check("transfer bytes untouched by a reveal", r["transfer_tx_bytes"], 0)
check("whole tx contains the outputs",
      r["reveal_tx_bytes"] > r["insc_output_bytes"], True)

# a transfer: counted as a transfer, not a reveal
blk2 = block([tx("fa" * 32, [vin(rv, 0, 546)], [out(500)])])
blk2["tx"][1]["size"] = 200
r2 = t10.process_block(blk2, envelope_txids=set())
check("transfer bytes recorded", r2["transfer_tx_bytes"], 200)
check("not counted as a reveal", r2["reveal_tx_bytes"], 0)

# a transaction that both reveals and spends tagged dust counts ONCE
t11 = fresh()
a = "ab" * 32
b1 = block([tx(a, [vin("77" * 32, 0, 9_000)], [out(546)])])
b1["tx"][1]["size"] = 500
t11.process_block(b1, envelope_txids={a})
both = "ac" * 32
b2 = block([tx(both, [vin(a, 0, 546)], [out(546)])])
b2["tx"][1]["size"] = 700
r3 = t11.process_block(b2, envelope_txids={both})
check("reveal takes precedence over transfer", r3["reveal_tx_bytes"], 700)
check("not double counted", r3["transfer_tx_bytes"], 0)

print("\nOP_RETURN INSIDE A CHARGED TRANSACTION")
# The overlap the whole-transaction measure creates and the envelope
# measure could not: a reveal that also carries an OP_RETURN — a Runes
# etching — has those script bytes inside its own size AND counted by the
# OP_RETURN pipeline. This column is the deduction.
NULLDATA_LEN = len(NULLDATA) // 2      # 1 + 40 = 41 bytes of script
# Stored size adds the value field and the length prefix, matching
# or_stored_bytes in the OP_RETURN pipeline.
NULLDATA_STORED = 8 + 1 + NULLDATA_LEN
t12 = fresh()
et = "bb" * 32
b3 = block([tx(et, [vin("66" * 32, 0, 20_000)],
               [out(546), out(0, NULLDATA, "nulldata")])])
b3["tx"][1]["size"] = 900
r4 = t12.process_block(b3, envelope_txids={et})
check("OP_RETURN bytes inside a reveal are recorded",
      r4["reveal_opreturn_bytes"], NULLDATA_STORED)
check("and not on the transfer column", r4["transfer_opreturn_bytes"], 0)
check("the OP_RETURN output is not a UTXO", r4["insc_added"], 1)
check("nor counted in the output bytes",
      r4["insc_output_bytes"], 8 + 1 + P2TR_LEN)
check("the deduction is inside the charged size",
      r4["reveal_opreturn_bytes"] < r4["reveal_tx_bytes"], True)

# Same output in a transfer: also already charged, so also deducted.
b4 = block([tx("bc" * 32, [vin(et, 0, 546)],
               [out(500), out(0, NULLDATA, "nulldata")])])
b4["tx"][1]["size"] = 300
r5 = t12.process_block(b4, envelope_txids=set())
check("OP_RETURN bytes inside a transfer are recorded",
      r5["transfer_opreturn_bytes"], NULLDATA_STORED)
check("and not on the reveal column", r5["reveal_opreturn_bytes"], 0)

# An ordinary payment carrying an OP_RETURN is charged to nobody here —
# the OP_RETURN pipeline counts it in full and there is nothing to
# subtract.
t13 = fresh()
b5 = block([tx("bd" * 32, [vin("55" * 32, 0, 100_000)],
               [out(90_000), out(0, NULLDATA, "nulldata")])])
b5["tx"][1]["size"] = 250
r6 = t13.process_block(b5, envelope_txids=set())
check("untagged OP_RETURN is not deducted",
      r6["reveal_opreturn_bytes"] + r6["transfer_opreturn_bytes"], 0)

# The deduction must use the SAME convention as the OP_RETURN pipeline,
# or the subtraction is wrong by nine bytes an output.
from opreturn_classifier import classify_tx as _oc
_pipeline = _oc({"txid": "x"*64, "vout": [{"scriptPubKey": {"hex": NULLDATA}}]})
check("deduction matches or_stored_bytes exactly",
      r5["transfer_opreturn_bytes"], _pipeline["stored_bytes"])


print("\nTHE PROVABLE FLOOR, AND WHAT FALLS OUTSIDE IT")
# A reveal tags every output it makes, change included — that is how the
# mempool.space cross-check is defined. The dust columns are the subset
# that can be proved to be carrying the inscription.
t14 = fresh()
rv2 = "d1" * 32
b = block([tx(rv2, [vin("d0" * 32, 0, 250_000)], [out(546), out(200_000)])])
b["tx"][1]["size"] = 600
r = t14.process_block(b, envelope_txids={rv2})
check("reveal tags change too (cross-check definition)", r["reveal_added"], 2)
check("but only the dust is provable", r["reveal_dust_added"], 1)
check("dust bogosize is the dust output only",
      r["reveal_dust_bogo_added"], 50 + P2TR_LEN)

# Spending that change is ordinary spending. It trips the ceiling,
# because the outpoint is tagged, but proves nothing.
b2 = block([tx("d2" * 32, [vin(rv2, 1, 200_000)], [out(190_000)])])
b2["tx"][1]["size"] = 250
r2 = t14.process_block(b2, envelope_txids=set())
check("spending reveal change hits the ceiling", r2["transfer_tx_bytes"], 250)
check("and contributes nothing to the floor", r2["transfer_input_bytes"], 0)
check("nor to the provable chainstate", r2["reveal_dust_removed"], 0)

# A real transfer: the tagged dust input and the tagged output are the floor.
t15 = fresh()
rv3 = "e1" * 32
b3 = block([tx(rv3, [vin("e0" * 32, 0, 9_000)], [out(546)])])
b3["tx"][1]["size"] = 500
t15.process_block(b3, envelope_txids={rv3})
mv = tx("e2" * 32, [vin(rv3, 0, 546), vin("e9" * 32, 0, 40_000)], [out(546), out(30_000)])
mv["size"] = 400
mv["vin"][0]["txinwitness"] = ["aa" * 64]          # 64-byte sig
r3 = t15.process_block(block([mv]), envelope_txids=set())
check("ceiling is the whole transaction", r3["transfer_tx_bytes"], 400)
check("floor counts one tagged input of two", r3["transfer_inputs_tagged"], 1)
check("and knows the total", r3["transfer_inputs_total"], 2)
check("floor input bytes: 36+1+0+4 + witness(1+1+64)",
      r3["transfer_input_bytes"], 36 + 1 + 4 + 1 + 1 + 64)
check("floor output bytes: the new dust only",
      r3["transfer_output_bytes"], 8 + 1 + P2TR_LEN)
check("floor is below the ceiling",
      r3["transfer_input_bytes"] + r3["transfer_output_bytes"]
      < r3["transfer_tx_bytes"], True)

# A sweep: one tagged dust among many, consolidated above the bound.
t16 = fresh()
rv4 = "f5" * 32
b4 = block([tx(rv4, [vin("f4" * 32, 0, 9_000)], [out(546)])])
b4["tx"][1]["size"] = 500
t16.process_block(b4, envelope_txids={rv4})
sweep = tx("f6" * 32,
           [vin(rv4, 0, 546)] + [vin(bytes([i]).hex() * 32, 0, 700)
                                 for i in range(1, 60)],
           [out(30_000)])
sweep["size"] = 9_000
r4 = t16.process_block(block([sweep]), envelope_txids=set())
check("sweep ceiling charges everything", r4["transfer_tx_bytes"], 9_000)
check("sweep floor charges one input", r4["transfer_inputs_tagged"], 1)
check("out of sixty", r4["transfer_inputs_total"], 60)
check("sweep floor is a tiny fraction of the ceiling",
      r4["transfer_input_bytes"] + r4["transfer_output_bytes"] < 100, True)
check("and the taint stops at the >1,000-sat output", r4["insc_added"], 0)

print(f"\n{passed} passed, {failed} failed\n")
sys.exit(1 if failed else 0)
