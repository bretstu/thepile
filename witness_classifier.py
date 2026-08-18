"""
Witness-data classification: inscription envelopes and byte accounting.

Pure functions only — no network, no file I/O. Testable without a node
(see test_witness_classifier.py).

WHAT THIS MEASURES
------------------
Inscriptions (and related protocols) store data inside "envelopes":
    OP_FALSE OP_IF <pushes...> OP_ENDIF
placed in tapscript (P2TR script-path) or P2WSH witness scripts. The
envelope is a no-op — it never executes — so it exists purely as data.

For every input that carries witness data, this module produces an EXACT
byte accounting. Each witness byte lands in exactly one bucket:

    envelope_bytes   bytes inside OP_FALSE OP_IF ... OP_ENDIF spans
    overhead_bytes   signatures, control blocks, non-script elements
    residual_bytes   script bytes outside envelopes, plus the annex

    envelope + overhead + residual == total witness element bytes  (always)

The residual is the self-audit: it is the measured size of whatever this
parser could NOT attribute. A novel data-embedding trick shows up as a
residual spike rather than silently vanishing. Publish it alongside the
headline numbers.

Within an envelope, two content measures (both deterministic):

    payload_bytes    sum of ALL data-push payloads inside the envelope.
                     Convention-independent — counts data regardless of
                     how a protocol structures its fields.
    content_bytes    the ord-convention BODY: pushes after the first
                     empty-push separator. For a 5KB image inscription
                     this is ~5,000 — "the actual file". Zero for
                     envelopes that don't follow the ord field layout
                     (payload_bytes still counts their data).

MEASUREMENT NOTE
----------------
"Total witness bytes" here = sum of witness element (stack item) byte
lengths. The serialized witness on disk is slightly larger (compact-size
length prefixes, the segwit marker/flag). Block-level `size -
strippedsize` from the node measures the serialized form; the builder
stores both so the gap is visible rather than hidden.

ENABLING-EVENT TIMELINE (for chart annotations)
-----------------------------------------------
    2017-08-24  SegWit activates (block 481,824) — witness discount exists
    2021-11-14  Taproot activates (block 709,632) — large tapscripts practical
    2022-12-14  First ord inscription (block 767,430)
    2023-01-21  ord 0.4.0 public release — inscription volume begins
"""

OP_0 = 0x00
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1 = 0x51
OP_16 = 0x60
OP_IF = 0x63
OP_NOTIF = 0x64
OP_ENDIF = 0x68

TAPROOT_ACTIVATION = 709_632
FIRST_INSCRIPTION = 767_430


# --------------------------------------------------------------------------
# Script tokenizer
# --------------------------------------------------------------------------

def tokenize(script):
    """Yield (start, opcode, payload, end) for each script token.

    Bitcoin script is a fully specified grammar, so this walk is complete
    rather than heuristic: every byte belongs to exactly one token. A
    truncated push (declared length exceeds remaining bytes) ends the
    walk; the unparsed remainder becomes residual in the caller.
    """
    i, n = 0, len(script)
    while i < n:
        start, op = i, script[i]
        i += 1
        payload = b""
        if 0x01 <= op <= 0x4B:
            if i + op > n:
                return
            payload, i = script[i:i + op], i + op
        elif op == OP_PUSHDATA1:
            if i + 1 > n:
                return
            ln = script[i]
            i += 1
            if i + ln > n:
                return
            payload, i = script[i:i + ln], i + ln
        elif op == OP_PUSHDATA2:
            if i + 2 > n:
                return
            ln = int.from_bytes(script[i:i + 2], "little")
            i += 2
            if i + ln > n:
                return
            payload, i = script[i:i + ln], i + ln
        elif op == OP_PUSHDATA4:
            if i + 4 > n:
                return
            ln = int.from_bytes(script[i:i + 4], "little")
            i += 4
            if i + ln > n:
                return
            payload, i = script[i:i + ln], i + ln
        yield start, op, payload, i


def _is_push(op):
    """Data-push opcodes (including empty OP_0 and OP_1..OP_16 constants)."""
    return op == OP_0 or 0x01 <= op <= OP_PUSHDATA4 or OP_1 <= op <= OP_16


def _push_value(op, payload):
    """The bytes a push token puts on the stack."""
    if OP_1 <= op <= OP_16:
        return bytes([op - 0x50])
    return payload


# --------------------------------------------------------------------------
# Envelope detection
# --------------------------------------------------------------------------

def envelope_spans(script):
    """Exact byte ranges [(start, end), ...] of every top-level envelope.

    An envelope is OP_FALSE(=OP_0) OP_IF ... matching OP_ENDIF. Matching
    is depth-counted so nested conditionals inside the envelope don't
    terminate it early. Spans nested inside other spans are dropped —
    their bytes are already counted by the outer span. Unclosed
    envelopes (no matching OP_ENDIF) are NOT counted; their bytes fall
    to residual, which is the honest treatment of malformed data.
    """
    toks = list(tokenize(script))
    spans = []
    for idx in range(len(toks) - 1):
        if toks[idx][1] != OP_0 or toks[idx][2] != b"":
            continue
        if toks[idx + 1][1] != OP_IF:
            continue
        depth = 0
        for j in range(idx + 1, len(toks)):
            op = toks[j][1]
            if op in (OP_IF, OP_NOTIF):
                depth += 1
            elif op == OP_ENDIF:
                depth -= 1
                if depth == 0:
                    spans.append((toks[idx][0], toks[j][3]))
                    break
    outer = []
    for s in spans:
        if not any(o[0] <= s[0] and s[1] <= o[1] and o != s for o in outer):
            outer.append(s)
    return outer


def parse_envelope(script, span):
    """Parse one envelope span into protocol / content-type / byte counts.

    Field layout follows the ord convention:
        <protocol push> then (tag, value) pairs, then an EMPTY push,
        then body pushes (the content, chunked at 520 bytes).
    Real inscriptions use 1-byte data pushes as tags (e.g. 0x01 0x01 for
    content-type); OP_1..OP_16 constants are accepted as equivalent tags
    for robustness.

    Envelopes that don't follow the convention still get payload_bytes
    (all push payloads) — only content_bytes/content_type need the
    convention.
    """
    inner = script[span[0] + 2:span[1] - 1]  # strip OP_0 OP_IF ... OP_ENDIF
    toks = list(tokenize(inner))

    payload_bytes = sum(len(t[2]) for t in toks)

    protocol = ""
    if toks:
        head = _push_value(toks[0][1], toks[0][2])
        protocol = _tag_text(head)

    content_type = ""
    content_bytes = 0
    k = 1
    while k < len(toks):
        op, payload = toks[k][1], toks[k][2]
        if not _is_push(op):
            k += 1
            continue
        tag = _push_value(op, payload)
        if tag == b"":  # body separator — everything after is content
            content_bytes = sum(len(t[2]) for t in toks[k + 1:])
            break
        if k + 1 < len(toks):  # (tag, value) pair
            if tag == b"\x01":
                content_type = _content_type_text(toks[k + 1][2])
            k += 2
        else:
            k += 1

    return {
        "envelope_bytes": span[1] - span[0],
        "payload_bytes": payload_bytes,
        "content_bytes": content_bytes,
        "protocol": protocol or "empty",
        "content_type": content_type,
    }


# Longest plausible MIME type is well under this; the cap only exists so a
# hostile multi-KB "content type" can't bloat a CSV cell.
MAX_CONTENT_TYPE_BYTES = 255


def _content_type_text(raw):
    """Exact declared content type, or bin:<hex> if it isn't printable ASCII.

    Strict on purpose, and deliberately different from _tag_text: content
    type is a value we report verbatim, not an identifier we bucket. The
    rule is all-or-nothing — either every byte is printable ASCII and we
    return the complete string, or we return a bin: marker. We never
    return a partial string, because a truncated MIME type is
    indistinguishable from a genuinely different one ("text/plain" vs
    "text/plain;charset=utf-8" are distinct declared values on chain).

    Deterministic: same bytes in, same string out, no length-dependent
    behaviour, no normalisation. Grouping (e.g. collapsing charset
    parameters) is an analysis decision and belongs in the explore layer.
    """
    if not raw:
        return ""
    if len(raw) > MAX_CONTENT_TYPE_BYTES:
        return "bin:" + raw[:3].hex()
    if all(32 <= b < 127 for b in raw):
        return raw.decode("ascii")
    return "bin:" + raw[:3].hex()


def _tag_text(raw, limit=16):
    """Printable-ASCII rendering of a small identifier, else bin:<hex>.

    Same bounded-vocabulary philosophy as the OP_RETURN classifier:
    under-label rather than mislabel.
    """
    head = raw[:limit]
    if head and all(32 <= b < 127 for b in head):
        return head.decode("ascii")
    return "bin:" + head[:3].hex() if head else ""


# --------------------------------------------------------------------------
# Input-level accounting
# --------------------------------------------------------------------------

def classify_input(witness_hex_list, prevout_spk_hex):
    """Exact byte accounting for one input's witness data.

    Returns a dict where envelope + overhead + residual == total, always.
    The script element is located structurally per BIP-141/BIP-341 —
    P2TR script path: [.., script, control_block] (annex stripped first);
    P2WSH: [.., witnessScript] — not guessed from content.
    """
    elems = [bytes.fromhex(w) for w in (witness_hex_list or [])]
    total = sum(len(e) for e in elems)
    out = {
        "kind": "none", "total": total,
        "envelope": 0, "overhead": 0, "residual": 0, "annex": 0,
        "envelopes": [],
    }
    if not elems:
        return out

    spk = (prevout_spk_hex or "").lower()

    # BIP-341: with >=2 witness elements, a last element starting 0x50
    # is the annex. Consensus-valid, meaning-free, unattributable → residual.
    annex = 0
    if spk.startswith("5120") and len(elems) >= 2 and elems[-1][:1] == b"\x50":
        annex = len(elems[-1])
        elems = elems[:-1]
    out["annex"] = annex

    script = None
    if spk.startswith("5120"):  # P2TR
        if len(elems) >= 2:
            out["kind"] = "p2tr-scriptpath"
            script = elems[-2]
            out["overhead"] = len(elems[-1]) + sum(len(e) for e in elems[:-2])
        else:
            out["kind"] = "p2tr-keypath"
            out["overhead"] = sum(len(e) for e in elems)
    elif spk.startswith("0020"):  # P2WSH
        out["kind"] = "p2wsh"
        script = elems[-1]
        out["overhead"] = sum(len(e) for e in elems[:-1])
    elif spk.startswith("0014"):  # P2WPKH: witness is sig+pubkey only
        out["kind"] = "p2wpkh"
        out["overhead"] = sum(len(e) for e in elems)
    else:  # nested segwit, legacy with stray witness, unknown
        out["kind"] = "other"
        out["overhead"] = sum(len(e) for e in elems)

    if script is not None:
        spans = envelope_spans(script)
        env_total = 0
        for span in spans:
            info = parse_envelope(script, span)
            env_total += info["envelope_bytes"]
            out["envelopes"].append(info)
        out["envelope"] = env_total
        out["residual"] = len(script) - env_total

    out["residual"] += annex
    assert out["envelope"] + out["overhead"] + out["residual"] == total, \
        "witness accounting leak"
    return out


# --------------------------------------------------------------------------
# Transaction-level accounting
# --------------------------------------------------------------------------

def classify_tx_witness(tx):
    """Aggregate witness accounting for one transaction.

    Requires prevout data on each input — i.e. `getblock <hash> 3`
    (verbosity 3, Core/Knots 25+). Returns None for transactions with
    no witness data at all.
    """
    totals = {
        "witness_bytes": 0, "envelope_bytes": 0, "content_bytes": 0,
        "payload_bytes": 0, "overhead_bytes": 0, "residual_bytes": 0,
        "annex_bytes": 0, "envelope_count": 0,
        "p2tr_keypath": 0, "p2tr_scriptpath": 0, "p2wsh": 0,
        "p2wpkh": 0, "other_witness": 0,
    }
    envelopes = []

    for vin in tx.get("vin", []):
        wit = vin.get("txinwitness")
        if not wit:
            continue
        spk = (vin.get("prevout") or {}).get("scriptPubKey", {}).get("hex", "")
        acct = classify_input(wit, spk)

        totals["witness_bytes"] += acct["total"]
        totals["envelope_bytes"] += acct["envelope"]
        totals["overhead_bytes"] += acct["overhead"]
        totals["residual_bytes"] += acct["residual"]
        totals["annex_bytes"] += acct["annex"]
        totals["envelope_count"] += len(acct["envelopes"])

        kind_key = {
            "p2tr-keypath": "p2tr_keypath",
            "p2tr-scriptpath": "p2tr_scriptpath",
            "p2wsh": "p2wsh",
            "p2wpkh": "p2wpkh",
        }.get(acct["kind"], "other_witness")
        totals[kind_key] += 1

        for env in acct["envelopes"]:
            totals["content_bytes"] += env["content_bytes"]
            totals["payload_bytes"] += env["payload_bytes"]
            envelopes.append(env)

    if totals["witness_bytes"] == 0:
        return None

    return {
        "txid": tx.get("txid", ""),
        "vsize": tx.get("vsize", 0),
        "weight": tx.get("weight", 0),
        "fee_sat": int(round(tx["fee"] * 1e8)) if tx.get("fee") is not None else None,
        "envelopes": envelopes,
        **totals,
    }
