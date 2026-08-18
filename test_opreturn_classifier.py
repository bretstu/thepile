"""
Tests for classifier.py. No node required.

Run:  python test_opreturn_classifier.py

These matter more than they look. The classifier is the piece that turns
raw blocks into claims, so it's the piece a skeptical reader will want to
check. A passing suite in the repo is the difference between "I wrote a
script" and "I validated my methodology."
"""

from opreturn_classifier import (
    classify_tx, protocol_tag, payload_prefix, parse_opreturn, first_push,
    script_bytes, is_opreturn, ascii_preview, legacy_allowance,
)

PASS = FAIL = 0


def check(label, got, want):
    global PASS, FAIL
    ok = got == want
    PASS, FAIL = PASS + ok, FAIL + (not ok)
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not ok:
        print(f"         got:  {got!r}")
        print(f"         want: {want!r}")


def op_return(payload: bytes, marker: int = None) -> str:
    """Build a valid OP_RETURN scriptPubKey hex."""
    out = bytes([0x6A])
    if marker is not None:
        out += bytes([0x50 + marker])
    n = len(payload)
    if n <= 0x4B:
        out += bytes([n])
    elif n <= 0xFF:
        out += bytes([0x4C, n])
    elif n <= 0xFFFF:
        out += bytes([0x4D]) + n.to_bytes(2, "little")
    else:
        out += bytes([0x4E]) + n.to_bytes(4, "little")
    return (out + payload).hex()


def p2wpkh():
    return "0014" + "ab" * 20


def tx(*scripts, txid="test", vsize=200, fee=None):
    t = {"txid": txid, "vsize": vsize, "weight": vsize * 4,
         "vout": [{"scriptPubKey": {"hex": s}} for s in scripts]}
    if fee is not None:
        t["fee"] = fee
    return t


print("\nSCRIPT PARSING")
check("is_opreturn on OP_RETURN", is_opreturn(op_return(b"hi")), True)
check("is_opreturn on p2wpkh", is_opreturn(p2wpkh()), False)
check("is_opreturn on empty", is_opreturn(""), False)
check("direct push roundtrip", first_push(op_return(b"hello")), b"hello")
check("PUSHDATA1 roundtrip", first_push(op_return(b"x" * 100)), b"x" * 100)
check("PUSHDATA2 roundtrip", first_push(op_return(b"y" * 5593)), b"y" * 5593)
check("malformed hex is safe", first_push("zzzz"), b"")
check("truncated script is safe", first_push("6a4c"), b"")

print("\nMARKER OPCODES (OP_1..OP_16 used as protocol markers)")
check("OP_13 marker parsed", parse_opreturn(op_return(b"data", marker=13)), (13, b"data"))
check("OP_8 marker parsed", parse_opreturn(op_return(b"data", marker=8)), (8, b"data"))
check("no marker on plain push", parse_opreturn(op_return(b"data"))[0], None)
check("marker with no payload", parse_opreturn("6a5d"), (13, b""))

print("\nSCRIPT SIZE (the 83-byte limit applies to this)")
check("80B payload = 83B script", script_bytes(op_return(b"z" * 80)), 83)
check("75B payload = 77B script", script_bytes(op_return(b"z" * 75)), 77)
check("5593B payload = 5597B script", script_bytes(op_return(b"z" * 5593)), 5597)

print("\nPROTOCOL TAGGING — documented protocols")
check("runes via OP_13", protocol_tag(op_return(b"\x14" + b"R" * 20, marker=13)), "runes")
check("runes bare marker", protocol_tag("6a5d"), "runes")
check("omni", protocol_tag(op_return(b"omni\x00\x00\x00\x00")), "omni")
check("counterparty", protocol_tag(op_return(b"CNTRPRTYxxxx")), "counterparty")
check("proofofexistence", protocol_tag(op_return(b"DOCPROOFabcd")), "proofofexistence")
check("thorchain", protocol_tag(op_return(b"=:BTC.BTC:bc1q")), "thorchain")

print("\nPROTOCOL TAGGING — bounded buckets, no invented names")
check("unknown marker", protocol_tag(op_return(b"\x01\x02", marker=8)), "marker-op8")
check("json payload", protocol_tag(op_return(b'{"p":"brc-20"}')), "json")
check("ascii bucket", protocol_tag(op_return(b"pwm1:s:abcdef")), "unclassified-ascii")
check("binary bucket", protocol_tag(op_return(bytes([0x00, 0x01, 0x14]))), "unclassified-binary")
check("empty payload", protocol_tag("6a00"), "empty")
check("non-opreturn", protocol_tag(p2wpkh()), "not-opreturn")

print("\nNO FRAGMENTATION — the 13,686-tag bug")
# Distinct hex payloads must NOT each become their own protocol.
hexish = [protocol_tag(op_return(f"0x{i:014x}".encode())) for i in range(50)]
check("50 distinct hex payloads -> 1 tag", len(set(hexish)), 1)
check("...and that tag is a bucket", hexish[0], "unclassified-ascii")
# Distinct binary payloads likewise.
bins = [protocol_tag(op_return(bytes([0, 1, i]))) for i in range(50)]
check("50 distinct binary payloads -> 1 tag", len(set(bins)), 1)
# Graffiti must not become protocol names.
check("graffiti not a protocol", protocol_tag(op_return(b"Luke Dash Jr")), "unclassified-ascii")
check("sentence not a protocol", protocol_tag(op_return(b"WHAT HAPPENS NEXT")), "unclassified-ascii")

print("\nPAYLOAD PREFIX — high cardinality, kept separate")
check("prefix is raw hex", payload_prefix(op_return(b"\xde\xad\xbe\xef\xff")), "deadbeef")
check("prefix keyed by marker", payload_prefix(op_return(b"\x14\x52", marker=13)), "op13:1452")
check("distinct payloads -> distinct prefixes",
      len({payload_prefix(op_return(bytes([0, 1, i, 9]))) for i in range(50)}), 50)

print("\nLEGACY ALLOWANCE")
check("no outputs = 0", legacy_allowance(0), 0)
check("one output = 83", legacy_allowance(1), 83)
check("four outputs still 83", legacy_allowance(4), 83)

print("\nTRANSACTION CLASSIFICATION")
check("no OP_RETURN returns None", classify_tx(tx(p2wpkh())), None)

r = classify_tx(tx(p2wpkh(), op_return(b"z" * 20)))
check("small: standard", r["standard_pre_v30"], True)
check("small: no excess", r["excess_bytes"], 0)

r = classify_tx(tx(op_return(b"z" * 80)))
check("exactly 83B script: standard", r["standard_pre_v30"], True)
check("exactly 83B script: no excess", r["excess_bytes"], 0)

r = classify_tx(tx(op_return(b"z" * 81)))  # -> 84 byte script
check("84B script: nonstandard", r["standard_pre_v30"], False)
check("84B script: over by size", r["over_by_size"], True)
check("84B script: excess = 1", r["excess_bytes"], 1)

r = classify_tx(tx(op_return(b"a" * 10), op_return(b"b" * 10)))
check("two small outputs: nonstandard", r["standard_pre_v30"], False)
check("two small outputs: over by count", r["over_by_count"], True)
check("two small outputs: not over by size", r["over_by_size"], False)
check("two small outputs: excess = 0", r["excess_bytes"], 0)

r = classify_tx(tx(op_return(b"z" * 5593)))
check("5597B script: excess = 5514", r["excess_bytes"], 5597 - 83)
check("5597B script: max output", r["max_output_bytes"], 5597)

# The real block 960600 shape: 4 outputs, 5913 bytes total.
big = classify_tx(tx(
    op_return(b"pwm1:s:" + b"z" * 104),      # 114B script
    op_return(b"pwm1:r:" + b"z" * 64),       #  73B script
    op_return(b"pwm1:m:" + b"z" * 5586),     # 5597B script
    op_return(b"pwt1:send2:" + b"z" * 115),  # 129B script
    vsize=6210,
))
check("block 960600: count", big["opreturn_count"], 4)
check("block 960600: total bytes", big["total_bytes"], 114 + 73 + 5597 + 129)
check("block 960600: max", big["max_output_bytes"], 5597)
check("block 960600: nonstandard", big["standard_pre_v30"], False)
check("block 960600: both violations",
      (big["over_by_size"], big["over_by_count"]), (True, True))
check("block 960600: excess", big["excess_bytes"], 5913 - 83)
check("block 960600: one bucket, not four names",
      big["protocols"], ["unclassified-ascii"])

r = classify_tx(tx(op_return(b"z" * 20), fee=0.0000165))
check("fee converts to sats", r["fee_sat"], 1650)
check("missing fee is None", classify_tx(tx(op_return(b"z" * 20)))["fee_sat"], None)
check("ascii preview", ascii_preview(op_return(b"pwm1:m:\x00\x01")), "pwm1:m:..")

print(f"\n{'=' * 46}")
print(f"  {PASS} passed, {FAIL} failed")
print(f"{'=' * 46}\n")
raise SystemExit(1 if FAIL else 0)
