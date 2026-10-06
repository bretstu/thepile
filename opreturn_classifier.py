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
"""

# Pre-v30 default: one OP_RETURN output, 83 bytes of scriptPubKey.
LEGACY_MAX_SCRIPT_BYTES = 83
LEGACY_MAX_OUTPUTS = 1

OP_RETURN = 0x6A


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


def varint_len(n):
    """Bytes Bitcoin uses for a CompactSize of n.

    Matters because a post-v30 OP_RETURN can carry ~100 KB, and assuming
    a 1-byte length prefix would undercount those outputs by two bytes
    each.
    """
    if n < 253:
        return 1
    if n < 65_536:
        return 3
    if n < 4_294_967_296:
        return 5
    return 9


def output_bytes(script_hex):
    """What a node actually stores for this output, in bytes.

    An output on disk is value + script length prefix + script. The
    83-byte policy limit applies to the SCRIPT alone, so script_bytes is
    what the grades compare against — but the pile is a storage measure,
    and the value field is stored whether or not it holds anything.

    For an OP_RETURN it almost never holds anything: the output is
    provably unspendable, so any satoshis assigned to it are destroyed.
    Those eight bytes therefore do no monetary work. They exist because
    somebody attached data, which is the same test every other figure in
    this project applies.
    """
    n = script_bytes(script_hex)
    return 8 + varint_len(n) + n


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
                "stored": output_bytes(script_hex),
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
      total_bytes    — actual OP_RETURN scriptPubKey bytes. The POLICY
                       quantity: what the 83-byte limit applied to.
      stored_bytes   — what a node stores for those outputs: value and
                       length prefix included. The STORAGE quantity, and
                       the one the pile uses. Always ~9 bytes/output
                       larger than total_bytes.
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
    stored_bytes = sum(o["stored"] for o in outs)
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
        "stored_bytes": stored_bytes,
        "max_output_bytes": max(o["size"] for o in outs),
        "legacy_bytes": legacy_bytes,
        "excess_bytes": max(0, total_bytes - legacy_bytes),
        "standard_pre_v30": not (over_size or over_count),
        "over_by_size": over_size,
        "over_by_count": over_count,
        "outputs": outs,
    }
