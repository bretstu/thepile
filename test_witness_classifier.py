"""
Tests for witness_classifier.py. No node required.

Every gotcha from the design discussion has a test here: chunking,
multiplicity, cursed position, non-ord envelopes, delegates (no body),
annex, P2WSH, key-path spends, malformed scripts, and the accounting
identity that every witness byte lands in exactly one bucket.
"""

from witness_classifier import (
    tokenize, envelope_spans, parse_envelope,
    classify_input, classify_tx_witness,
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


# --------------------------------------------------------------------------
# Builders — construct scripts the way real inscriptions are built
# --------------------------------------------------------------------------

def push(b: bytes) -> bytes:
    n = len(b)
    if n == 0:
        return b"\x00"                       # OP_0 empty push
    if n <= 0x4B:
        return bytes([n]) + b
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + b
    return b"\x4d" + n.to_bytes(2, "little") + b


def ord_envelope(content: bytes, ctype=b"image/png", proto=b"ord",
                 extra_fields=()) -> bytes:
    """Real ord layout: 00 63 <proto> 01 01 <ctype> [fields] 00 <chunks> 68.

    Tags are 1-byte DATA PUSHES (0x01 0x01), not OP_1 constants — this
    matches on-chain inscriptions.
    """
    s = b"\x00\x63" + push(proto) + push(b"\x01") + push(ctype)
    for tag, value in extra_fields:
        s += push(tag) + push(value)
    s += push(b"")                            # empty push = body separator
    for i in range(0, len(content), 520):     # 520-byte chunking
        s += push(content[i:i + 520])
    return s + b"\x68"


def sig_check() -> bytes:
    return push(b"\x02" * 32) + b"\xac"       # <pubkey> OP_CHECKSIG


SIG = ("01" * 64)                             # 64B schnorr signature
CB = ("c0" + "02" * 32)                       # 33B control block
P2TR = "5120" + "aa" * 32
P2WSH = "0020" + "bb" * 32
P2WPKH = "0014" + "cc" * 20


def p2tr_witness(script: bytes, annex_hex=None):
    w = [SIG, script.hex(), CB]
    if annex_hex:
        w.append(annex_hex)
    return w


# --------------------------------------------------------------------------

print("\nTOKENIZER")
s = push(b"abc") + b"\xac" + push(b"x" * 600)
toks = list(tokenize(s))
check("token count", len(toks), 3)
check("payload roundtrip small", toks[0][2], b"abc")
check("payload roundtrip PUSHDATA2", toks[2][2], b"x" * 600)
check("tokens cover every byte", toks[-1][3], len(s))
check("truncated push stops cleanly",
      list(tokenize(b"\x4d\xff\xff" + b"short")), [])

print("\nENVELOPE DETECTION")
env = ord_envelope(b"hello world", ctype=b"text/plain")
script = sig_check() + env
spans = envelope_spans(script)
check("one envelope found", len(spans), 1)
check("span covers full envelope",
      spans[0], (len(sig_check()), len(sig_check()) + len(env)))

# OP_1 OP_IF is a legitimate executable branch, NOT an envelope
decoy = b"\x51\x63" + push(b"real branch") + b"\x68"
check("OP_1 IF decoy not detected", envelope_spans(decoy), [])

# Nested IF inside an envelope must not terminate it early
nested = b"\x00\x63" + push(b"ord") + b"\x63" + push(b"inner") + b"\x68" + \
         push(b"") + push(b"tail") + b"\x68"
sp = envelope_spans(nested)
check("nested IF: still one envelope", len(sp), 1)
check("nested IF: span reaches outer ENDIF", sp[0], (0, len(nested)))

# Unclosed envelope -> not counted (falls to residual)
check("unclosed envelope not counted",
      envelope_spans(b"\x00\x63" + push(b"ord") + push(b"data")), [])

print("\nENVELOPE PARSING — ord conventions")
content = b"\x89PNG" + b"\xff" * 5000        # 5,004B "image"
env = ord_envelope(content)
info = parse_envelope(env, (0, len(env)))
check("content bytes = the actual file", info["content_bytes"], 5004)
check("chunking invisible to totals", info["content_bytes"], len(content))
check("protocol = ord", info["protocol"], "ord")
check("content type extracted", info["content_type"], "image/png")
check("payload >= content (includes fields)",
      info["payload_bytes"] > info["content_bytes"], True)
check("envelope bytes = span size", info["envelope_bytes"], len(env))

# Delegate-style envelope: fields only, no body separator, no content
delegate = b"\x00\x63" + push(b"ord") + push(b"\x0b") + push(b"\xab" * 36) + b"\x68"
info = parse_envelope(delegate, (0, len(delegate)))
check("delegate: zero content bytes", info["content_bytes"], 0)
check("delegate: payload still counted", info["payload_bytes"], 3 + 1 + 36)

# Non-ord envelope that ignores the field convention entirely
alien = b"\x00\x63" + push(b"xyz") + push(b"\xde\xad" * 100) + b"\x68"
info = parse_envelope(alien, (0, len(alien)))
check("non-ord: payload counted", info["payload_bytes"], 3 + 200)
check("non-ord: content zero (no separator)", info["content_bytes"], 0)
check("non-ord: protocol tagged", info["protocol"], "xyz")

# Binary protocol tag -> bounded bin: bucket, no fragmentation
binp = b"\x00\x63" + push(b"\x00\x01\x02") + b"\x68"
check("binary proto -> bin bucket",
      parse_envelope(binp, (0, len(binp)))["protocol"].startswith("bin:"), True)

print("\nINPUT ACCOUNTING — every byte in exactly one bucket")


def balanced(acct):
    return acct["envelope"] + acct["overhead"] + acct["residual"] == acct["total"]


# P2TR key path: pure signature, no script
a = classify_input([SIG], P2TR)
check("keypath: kind", a["kind"], "p2tr-keypath")
check("keypath: all overhead", (a["overhead"], a["envelope"]), (64, 0))
check("keypath: balanced", balanced(a), True)

# P2TR script path with one inscription
script = sig_check() + ord_envelope(b"z" * 3000)
a = classify_input(p2tr_witness(script), P2TR)
check("scriptpath: kind", a["kind"], "p2tr-scriptpath")
check("scriptpath: one envelope", len(a["envelopes"]), 1)
check("scriptpath: sig+cb in overhead", a["overhead"], 64 + 33)
check("scriptpath: sig-check is residual", a["residual"], len(sig_check()))
check("scriptpath: balanced", balanced(a), True)

# Batch reveal: three envelopes in one input (multiplicity)
script = sig_check() + ord_envelope(b"a" * 600) + \
         ord_envelope(b"b" * 600, ctype=b"text/plain") + \
         ord_envelope(b"c" * 600, proto=b"other")
a = classify_input(p2tr_witness(script), P2TR)
check("batch: three envelopes", len(a["envelopes"]), 3)
check("batch: content summed",
      sum(e["content_bytes"] for e in a["envelopes"]), 1800)
check("batch: balanced", balanced(a), True)

# Cursed position: envelope AFTER other script content — still found
script = sig_check() + push(b"junk") + b"\x75" + ord_envelope(b"q" * 100)
a = classify_input(p2tr_witness(script), P2TR)
check("cursed position: found", len(a["envelopes"]), 1)
check("cursed position: balanced", balanced(a), True)

# Annex present: stripped per BIP-341, lands in residual
script = sig_check() + ord_envelope(b"q" * 400)
a = classify_input(p2tr_witness(script, annex_hex="50" + "ee" * 99), P2TR)
check("annex: measured", a["annex"], 100)
check("annex: in residual", a["residual"] >= 100, True)
check("annex: balanced", balanced(a), True)

# P2WSH envelope — pre-taproot data path, must not be missed
script = sig_check() + ord_envelope(b"w" * 200)
a = classify_input([SIG, script.hex()], P2WSH)
check("p2wsh: kind", a["kind"], "p2wsh")
check("p2wsh: envelope found", len(a["envelopes"]), 1)
check("p2wsh: balanced", balanced(a), True)

# P2WPKH: ordinary spend, nothing to attribute
a = classify_input([SIG, ("02" + "ab" * 32)], P2WPKH)
check("p2wpkh: no envelopes", len(a["envelopes"]), 0)
check("p2wpkh: balanced", balanced(a), True)

# Legit taproot multisig script path — envelope-free, zero false positive
script = push(b"\x02" * 32) + b"\xac" + push(b"\x03" * 32) + b"\xba"
a = classify_input(p2tr_witness(script), P2TR)
check("multisig script: no false positive", a["envelope"], 0)
check("multisig script: balanced", balanced(a), True)

# Malformed: truncated PUSHDATA2 inside the script
script = sig_check() + b"\x00\x63" + b"\x4d\xff\xff" + b"short"
a = classify_input(p2tr_witness(script), P2TR)
check("malformed: no envelope claimed", a["envelope"], 0)
check("malformed: bytes preserved in residual", balanced(a), True)

print("\nTRANSACTION ACCOUNTING")
tx = {
    "txid": "t1", "vsize": 500, "weight": 2000, "fee": 0.0000165,
    "vin": [
        {"txinwitness": p2tr_witness(sig_check() + ord_envelope(b"x" * 1000)),
         "prevout": {"scriptPubKey": {"hex": P2TR}}},
        {"txinwitness": [SIG, ("02" + "ab" * 32)],
         "prevout": {"scriptPubKey": {"hex": P2WPKH}}},
        {},  # legacy input, no witness
    ],
}
r = classify_tx_witness(tx)
check("tx: envelope count", r["envelope_count"], 1)
check("tx: content bytes", r["content_bytes"], 1000)
check("tx: input kinds", (r["p2tr_scriptpath"], r["p2wpkh"], r["other_witness"]), (1, 1, 0))
check("tx: identity holds",
      r["envelope_bytes"] + r["overhead_bytes"] + r["residual_bytes"],
      r["witness_bytes"])
check("tx: fee in sats", r["fee_sat"], 1650)
check("tx with no witness -> None",
      classify_tx_witness({"vin": [{}], "txid": "x"}), None)


print("\nCONTENT TYPE — exact, no truncation, deterministic")
from witness_classifier import _content_type_text

long_ct = b"text/plain;charset=utf-8"
env = ord_envelope(b"x", ctype=long_ct)
check("long type not truncated",
      parse_envelope(env, (0, len(env)))["content_type"], "text/plain;charset=utf-8")
env = ord_envelope(b"x", ctype=b"model/gltf-binary")
check("gltf-binary intact",
      parse_envelope(env, (0, len(env)))["content_type"], "model/gltf-binary")
env = ord_envelope(b"x", ctype=b"application/octet-stream")
check("octet-stream intact",
      parse_envelope(env, (0, len(env)))["content_type"], "application/octet-stream")
env = ord_envelope(b"x", ctype=b"image/svg+xml;charset=utf-8")
check("svg with charset intact",
      parse_envelope(env, (0, len(env)))["content_type"], "image/svg+xml;charset=utf-8")

check("empty type -> empty string", _content_type_text(b""), "")
check("non-ascii -> bin marker, never partial",
      _content_type_text(b"text/pl\xff\xfe"), "bin:746578")
check("oversized -> bin marker",
      _content_type_text(b"a" * 300), "bin:616161")
check("255 bytes still accepted", len(_content_type_text(b"a" * 255)), 255)
check("deterministic: same in, same out",
      _content_type_text(long_ct) == _content_type_text(long_ct), True)
check("no partial strings ever",
      _content_type_text(b"text/plain\x00more").startswith("bin:"), True)

print(f"\n{'=' * 46}")
print(f"  {PASS} passed, {FAIL} failed")
print(f"{'=' * 46}\n")
raise SystemExit(1 if FAIL else 0)
