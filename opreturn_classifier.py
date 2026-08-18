"""
OP_RETURN classification logic.

Pure functions only — no network, no file I/O. Everything here is
deterministic given a transaction dict from `getblock <hash> 2`, which
makes it testable without a node (see test_opreturn_classifier.py).

POLICY REFERENCE
----------------
Pre-v30 default relay policy (Bitcoin Core <= v29, and Knots defaults):
  - At most ONE OP_RETURN output per transaction.
  - That output's scriptPubKey limited to 83 bytes total
    (1 byte OP_RETURN + 1-2 bytes pushdata prefix + up to 80 bytes payload).

Bitcoin Core v30 (released 2025-10-10):
  - Multiple OP_RETURN outputs permitted.
  - Aggregate limit raised to 100,000 bytes, which the 100,000 vbyte
    transaction size limit binds before in practice.

IMPORTANT CAVEAT, carried through to any published figure:
  "Bytes in excess of pre-v30 policy" is NOT the same as "bytes that
  would not exist." Two reasons:
    1. Relay policy was never a consensus rule. Miners accepting direct
       submissions could and did include non-standard transactions.
    2. Data has other carriers. Taproot witness data costs roughly a
       quarter as much per byte thanks to the witness discount, so data
       blocked from OP_RETURN may simply move rather than disappear.
  This module measures what it measures. Causal claims need more.

TAGGING PHILOSOPHY
------------------
protocol_tag() is deliberately conservative. It returns a named protocol
ONLY for signatures documented well enough to assert, and drops everything
else into a handful of structural buckets. The tag vocabulary is bounded
and small by design — an unreadable leaderboard of thousands of one-off
labels is worse than an honest "unclassified-binary".

Identification work is deferred, not abandoned. payload_prefix() returns
the raw leading bytes, stored separately, so the distinct-prefix
population can be studied later without re-scanning the chain.
"""

# Pre-v30 default: one OP_RETURN output, 83 bytes of scriptPubKey.
LEGACY_MAX_SCRIPT_BYTES = 83
LEGACY_MAX_OUTPUTS = 1

OP_RETURN = 0x6A
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1 = 0x51
OP_16 = 0x60

PREFIX_BYTES = 4  # how much raw payload head to retain for later study


# --------------------------------------------------------------------------
# Script parsing
# --------------------------------------------------------------------------

def is_opreturn(script_hex):
    """True if this scriptPubKey is a data carrier (starts with OP_RETURN)."""
    return bool(script_hex) and script_hex[:2].lower() == "6a"


def script_bytes(script_hex):
    """Total serialized size of the scriptPubKey, in bytes.

    This is the quantity the 83-byte limit applies to — not the payload.
    An 80-byte payload is an 83-byte script: 1 (OP_RETURN) + 2 (pushdata
    prefix) + 80.
    """
    return len(script_hex) // 2


def parse_opreturn(script_hex):
    """Decompose an OP_RETURN script.

    Returns (marker, payload) where:
      marker  — int 1..16 if the script uses OP_1..OP_16 as a protocol
                marker immediately after OP_RETURN, else None. This is
                the pattern Runes uses (OP_13) and at least one other
                protocol uses (OP_8).
      payload — bytes of the first data push, or b'' if absent/malformed.

    Never raises. Block data contains plenty of malformed scripts.
    """
    try:
        raw = bytes.fromhex(script_hex)
    except ValueError:
        return None, b""

    if len(raw) < 2 or raw[0] != OP_RETURN:
        return None, b""

    i = 1
    marker = None

    # An OP_1..OP_16 immediately after OP_RETURN is a protocol marker,
    # not data. Skip past it and read the real push behind it.
    if OP_1 <= raw[i] <= OP_16:
        marker = raw[i] - 0x50
        i += 1
        if i >= len(raw):
            return marker, b""

    op = raw[i]
    if 0x01 <= op <= 0x4B:
        length, i = op, i + 1
    elif op == OP_PUSHDATA1:
        if len(raw) < i + 2:
            return marker, b""
        length, i = raw[i + 1], i + 2
    elif op == OP_PUSHDATA2:
        if len(raw) < i + 3:
            return marker, b""
        length = int.from_bytes(raw[i + 1:i + 3], "little")
        i += 3
    elif op == OP_PUSHDATA4:
        if len(raw) < i + 5:
            return marker, b""
        length = int.from_bytes(raw[i + 1:i + 5], "little")
        i += 5
    else:
        return marker, b""

    return marker, raw[i:i + length]


def first_push(script_hex):
    """Payload bytes of the first data push. Convenience wrapper."""
    return parse_opreturn(script_hex)[1]


# --------------------------------------------------------------------------
# Protocol identification
# --------------------------------------------------------------------------

# Only signatures documented well enough to assert without hedging.
# Adding to this list is a claim — each entry should be defensible if
# someone asks "how do you know?". Everything unlisted stays in a
# structural bucket, which is honest rather than wrong.
#
# Format: (matcher, label). Marker matches are checked first.

KNOWN_MARKERS = {
    13: "runes",  # Runestone: OP_RETURN OP_13 <payload>
}

KNOWN_PAYLOAD_PREFIXES = [
    (b"omni", "omni"),              # Omni Layer
    (b"CNTRPRTY", "counterparty"),  # Counterparty
    (b"DOCPROOF", "proofofexistence"),
    (b"=:", "thorchain"),           # THORChain memo: =:ASSET:DEST:...
]

# Structural buckets. Bounded vocabulary, no per-payload fragmentation.
BUCKET_JSON = "json"                    # payload begins '{' — some JSON protocol
BUCKET_ASCII = "unclassified-ascii"
BUCKET_BINARY = "unclassified-binary"
BUCKET_EMPTY = "empty"


def protocol_tag(script_hex):
    """Conservative protocol label. Bounded vocabulary.

    Returns one of:
      - a documented protocol name ("runes", "omni", "thorchain", ...)
      - "marker-opN" for an unrecognised OP_1..OP_16 marker convention
      - "json" for payloads that begin with '{'
      - "unclassified-ascii" / "unclassified-binary" / "empty"

    Deliberately does NOT invent names from payload content. Group by
    payload_prefix() when you want to investigate the unclassified
    population.
    """
    if not is_opreturn(script_hex):
        return "not-opreturn"

    marker, payload = parse_opreturn(script_hex)

    if marker is not None:
        if marker in KNOWN_MARKERS:
            return KNOWN_MARKERS[marker]
        return f"marker-op{marker}"

    if not payload:
        return BUCKET_EMPTY

    for sig, name in KNOWN_PAYLOAD_PREFIXES:
        if payload.startswith(sig):
            return name

    if payload[:1] == b"{":
        return BUCKET_JSON

    head = payload[:16]
    try:
        head.decode("ascii")
    except UnicodeDecodeError:
        return BUCKET_BINARY

    if all(32 <= b < 127 for b in head):
        return BUCKET_ASCII
    return BUCKET_BINARY


def payload_prefix(script_hex):
    """Raw leading payload bytes as hex — the research key.

    High cardinality on purpose. Stored in its own table so the protocol
    field stays readable while the underlying population remains
    groupable later. Marker-based scripts are keyed on the marker so
    they don't collide with pushdata payloads.
    """
    marker, payload = parse_opreturn(script_hex)
    if marker is not None:
        return f"op{marker}:" + payload[:PREFIX_BYTES].hex()
    return payload[:PREFIX_BYTES].hex()


def ascii_preview(script_hex, limit=48):
    """Human-readable peek at the payload, for drill-down views."""
    payload = first_push(script_hex)[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in payload)


# --------------------------------------------------------------------------
# Transaction-level classification
# --------------------------------------------------------------------------

def opreturn_outputs(tx):
    """All OP_RETURN outputs in a transaction."""
    out = []
    for idx, vout in enumerate(tx.get("vout", [])):
        script_hex = vout.get("scriptPubKey", {}).get("hex", "")
        if is_opreturn(script_hex):
            out.append({
                "vout": idx,
                "size": script_bytes(script_hex),
                "protocol": protocol_tag(script_hex),
                "prefix": payload_prefix(script_hex),
                "hex": script_hex,
            })
    return out


def legacy_allowance(n_outputs):
    """Bytes of OP_RETURN scriptPubKey pre-v30 policy would have permitted.

    One output at up to 83 bytes. Zero outputs means zero allowance — a
    transaction with no data carrier isn't "allowed" 83 unused bytes.
    """
    return LEGACY_MAX_SCRIPT_BYTES if n_outputs > 0 else 0


def classify_tx(tx):
    """Full OP_RETURN classification for one transaction.

    Returns None for transactions with no OP_RETURN outputs.

    Key fields:
      total_bytes    — actual OP_RETURN scriptPubKey bytes
      legacy_bytes   — what pre-v30 policy would have permitted
      excess_bytes   — total_bytes - legacy_bytes, floored at zero.
                       THIS IS THE HEADLINE METRIC. Read the module
                       docstring caveat before publishing it.
      standard_pre_v30 — would this have relayed under pre-v30 defaults?

    over_by_size and over_by_count are tracked separately because v30
    changed two rules. A transaction with four small OP_RETURN outputs
    violates the count rule with zero excess bytes; collapsing the two
    into one flag would hide half the effect.
    """
    outs = opreturn_outputs(tx)
    if not outs:
        return None

    total_bytes = sum(o["size"] for o in outs)
    n = len(outs)
    legacy_bytes = legacy_allowance(n)

    over_size = total_bytes > LEGACY_MAX_SCRIPT_BYTES
    over_count = n > LEGACY_MAX_OUTPUTS

    return {
        "txid": tx.get("txid", ""),
        "vsize": tx.get("vsize", 0),
        "weight": tx.get("weight", 0),
        "fee_sat": int(round(tx["fee"] * 1e8)) if tx.get("fee") is not None else None,
        "opreturn_count": n,
        "total_bytes": total_bytes,
        "max_output_bytes": max(o["size"] for o in outs),
        "legacy_bytes": legacy_bytes,
        "excess_bytes": max(0, total_bytes - legacy_bytes),
        "standard_pre_v30": not (over_size or over_count),
        "over_by_size": over_size,
        "over_by_count": over_count,
        "protocols": sorted({o["protocol"] for o in outs}),
        "outputs": outs,
    }
