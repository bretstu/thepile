"""
Tests for graffiti_classifier.py. No node required.

Run:  python test_graffiti_classifier.py
"""

from graffiti_classifier import (
    classify_text, opreturn_text, inscribed_texts, decode_text,
    looks_human, miner_from_coinbase, coinbase_ascii,
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


def op_return(payload: bytes) -> str:
    n = len(payload)
    if n <= 0x4B:
        push = bytes([n])
    elif n <= 0xFF:
        push = bytes([0x4C, n])
    else:
        push = bytes([0x4D]) + n.to_bytes(2, "little")
    return (bytes([0x6A]) + push + payload).hex()


def push(b: bytes) -> bytes:
    n = len(b)
    if n == 0:
        return b"\x00"
    if n <= 0x4B:
        return bytes([n]) + b
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + b
    return b"\x4d" + n.to_bytes(2, "little") + b


def envelope(ct: bytes, body: bytes) -> bytes:
    s = b"\x00\x63" + push(b"ord") + push(b"\x01") + push(ct) + push(b"")
    for i in range(0, len(body), 520):
        s += push(body[i:i + 520])
    return s + b"\x68"


def tx_env(ct, body):
    script = push(b"\x02" * 32) + b"\xac" + envelope(ct, body)
    return {"vin": [{"txinwitness": ["01" * 64, script.hex(), "c0" + "02" * 32]}],
            "vout": []}


print("\nCATEGORIES")
check("human sentence", classify_text(b"I love you Mom, forever on the chain")[0], "human")
check("bridge memo (evm addr)",
      classify_text(b"from:1.044ETH:0x3e3EeB4bd4aFE315fcc2Ac17a421B94b12A7a2Ec")[0], "bridge")
check("bridge memo (tron addr)",
      classify_text(b"to:USDT(TRON):TKyTJafVCVZKRSJP9Ciwg7Ju43r3qMznKE")[0], "bridge")
check("json mint", classify_text(b'{"p":"brc-20","op":"mint","tick":"ordi"}')[0], "json")
check("protocol tag", classify_text(b"MTLD_255531 extra")[0], "tag")
check("lifi junk is tag not human", classify_text(b"=|lifim junk4 x")[0], "tag")
check("thorchain prefix dropped", classify_text(b"=:ETH.ETH:0xabc:min")[0], None)
check("binary undecodable", classify_text(b"\xff\xfe\x00garbage\x00")[0], None)
check("too short", classify_text(b"gm")[0], None)
check("slur dropped entirely", classify_text(b"you are a nigger and more words")[0], None)

print("\nSAFETY AT STORAGE TIME")
cat, text = classify_text(b"read this https://example.com/bad now please")
check("url redacted before disk", "[link]" in text and "example.com" not in text, True)
check("truncated to cap", len(classify_text(b"word " * 100)[1]) <= 200, True)

print("\nOP_RETURN EXTRACTION")
check("plain text extracted", opreturn_text(op_return(b"hello from portland maine"))[0], "human")
check("runes skipped", opreturn_text("6a5d0714e1a01f02c803"), (None, None))
check("non-opreturn skipped", opreturn_text("0014" + "ab" * 20), (None, None))
check("large payload decodes",
      opreturn_text(op_return(b"a message " * 30))[0] is not None, True)

print("\nINSCRIPTION EXTRACTION")
got = inscribed_texts(tx_env(b"text/plain;charset=utf-8", b"remember me when the mempool clears"))
check("text/plain body extracted", len(got), 1)
check("...as human", got[0][1], "human")
check("...content type kept", got[0][0], "text/plain;charset=utf-8")
check("json body categorized json",
      inscribed_texts(tx_env(b"text/plain", b'{"p":"brc-20","op":"mint","tick":"x"}'))[0][1],
      "json")
check("image body never touched", inscribed_texts(tx_env(b"image/png", b"\x89PNG" + b"x" * 50)), [])
check("oversized body skipped", inscribed_texts(tx_env(b"text/plain", b"word " * 400)), [])
check("no witness -> nothing", inscribed_texts({"vin": [{}], "vout": []}), [])

print("\nMINER ATTRIBUTION")
def blk(tag: bytes):
    return {"tx": [{"vin": [{"coinbase": (bytes([3, 1, 2, 3]) + tag).hex()}]}]}
check("foundry", miner_from_coinbase(blk(b"/Foundry USA Pool/")), "Foundry USA")
check("antpool", miner_from_coinbase(blk(b"Mined by AntPool")), "AntPool")
check("unknown", miner_from_coinbase(blk(b"\x07\x99solo")), "Unknown")
check("coinbase ascii preserved",
      "/Foundry USA Pool/" in coinbase_ascii(blk(b"/Foundry USA Pool/")), True)
check("malformed coinbase safe", miner_from_coinbase({"tx": []}), "Unknown")

print(f"\n{'=' * 46}")
print(f"  {PASS} passed, {FAIL} failed")
print(f"{'=' * 46}\n")
raise SystemExit(1 if FAIL else 0)
