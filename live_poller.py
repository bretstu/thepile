"""
Live block poller for the portal view.

    python live_poller.py

Polls the node every POLL_SECONDS for a new tip. When a block is mined,
classifies it with the same code as the historical pipelines
(witness_classifier + opreturn_classifier) and writes a rolling window
of recent blocks to dashboard/data/live.json.

The frontend polls that file. No server, no sockets, no inbound
anything — the node is never exposed. Writes are atomic (tmp + rename)
so the page can never read a half-written file.

Runs forever; Ctrl+C to stop. On startup it backfills the last
BACKFILL blocks so the page is never empty.
"""

import json
import os
import time

from rpc import rpc, CLIENT
from witness_classifier import (classify_tx_witness, envelope_spans,
                                parse_envelope, tokenize, _is_push,
                                _push_value)
from opreturn_classifier import classify_tx as classify_opreturn

POLL_SECONDS = 5
WINDOW = 40          # blocks in the draggable row (~7h of chain)
BACKFILL = 24        # blocks classified on first-ever startup (~a minute)
HISTORY_KEEP = 4320  # ~30 days of blocks kept in the history file
OUTFILE = os.path.join("dashboard", "data", "live.json")
HISTORY = os.path.join("dashboard", "data", "live_history.json")

# Coinbase tags of known mining pools, matched case-insensitively against
# the printable bytes of the coinbase input. Unmatched -> "Unknown".
POOL_TAGS = [
    ("foundry", "Foundry USA"), ("antpool", "AntPool"), ("f2pool", "F2Pool"),
    ("viabtc", "ViaBTC"), ("binance", "Binance Pool"), ("luxor", "Luxor"),
    ("mara", "MARA Pool"), ("braiins", "Braiins"), ("slush", "Braiins"),
    ("spiderpool", "SpiderPool"), ("ocean.xyz", "OCEAN"), ("ocean", "OCEAN"),
    ("secpool", "SECPOOL"), ("btc.com", "BTC.com"), ("poolin", "Poolin"),
    ("carbon", "Carbon Negative"), ("ultimus", "ULTIMUSPOOL"),
    ("sbi crypto", "SBI Crypto"), ("whitepool", "WhitePool"),
]


# ---- the graffiti wire -------------------------------------------------
# Human-readable OP_RETURN text, defensively filtered. Text-only by
# construction: this reads OP_RETURN pushes exclusively — image data
# lives in witness envelopes, which this code never touches.
GRAFFITI_MIN_LEN = 8          # shorter is protocol noise
GRAFFITI_MAX_LEN = 200        # truncate long rants
GRAFFITI_PER_BLOCK = 8
# messages containing any of these are dropped entirely (case-insensitive)
BLOCKLIST = ["nigger", "faggot", "kike", "spic", "chink"]
# protocol payloads that read as text but aren't human graffiti
PROTOCOL_PREFIXES = (b"=:", b"SWAP:", b"OUT:", b"REFUND:", b"omni",
                     b"CNTRPRTY", b"RSKBLOCK:", b"ion:", b"DC-L5:")
import re as _re
_URL = _re.compile(r"https?://\S+|www\.\S+", _re.I)

# Machine text detection: bridge/swap memos and commitments are ASCII but
# not human writing. The signature is crypto addresses and routing verbs —
# a long hex or base58 run, or "to:/from:TICKER" forms. Bump this version
# whenever the filters change: history blocks stamped with an older
# version get re-filtered on the next poller start.
GRAFFITI_VERSION = 4   # bumped: blocks now also carry beyond_bytes
_MACHINE = [
    _re.compile(r"0x[0-9a-fA-F]{16,}"),                  # EVM address/hash
    _re.compile(r"[1-9A-HJ-NP-Za-km-z]{26,}"),           # base58 run (BTC/TRON/etc)
    _re.compile(r"\bbc1[a-z0-9]{20,}", _re.I),          # bech32
    _re.compile(r"\b(?:to|from|refund|out|memo|migrate|swap|bridge)\s*:", _re.I),
]


def looks_machine(text):
    return any(rx.search(text) for rx in _MACHINE)


_WORD = _re.compile(r"[A-Za-z]{2,}")
_OKCHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "0123456789 .,!?'\"-:;()@#&/\n")


def human_text(payload: bytes):
    """The shared gauntlet: returns display-ready text, or None.

    v3 is structural rather than enumerative — instead of blocklisting
    every protocol tag (SYMB:, MTLD_, lifi, ...), require the *shape* of
    natural language: multiple real words, mostly letters, ordinary
    punctuation. Protocol tags fail on shape, whatever they're called.
    """
    if len(payload) < GRAFFITI_MIN_LEN:
        return None
    if payload.startswith(PROTOCOL_PREFIXES):
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
    if printable / len(text) < 0.9:
        return None
    text = " ".join(text.split())
    text = _URL.sub("[link]", text)
    if not text:
        return None
    # natural-language shape
    if " " not in text or len(_WORD.findall(text)) < 2:
        return None
    letters = sum(1 for c in text if c.isalpha())
    if letters / len(text) < 0.55:
        return None
    weird = sum(1 for c in text if c not in _OKCHARS)
    if weird / len(text) > 0.08:
        return None
    low = text.lower()
    if any(w in low for w in BLOCKLIST):
        return None
    if looks_machine(text):
        return None
    return text[:GRAFFITI_MAX_LEN]


def _script_pushes(script_hex):
    """Data pushes from an OP_RETURN script (after the 0x6a)."""
    try:
        b = bytes.fromhex(script_hex)
    except ValueError:
        return []
    if not b or b[0] != 0x6A:
        return []
    out, i = [], 1
    while i < len(b):
        op = b[i]; i += 1
        if 1 <= op <= 0x4B:
            n = op
        elif op == 0x4C and i < len(b):
            n = b[i]; i += 1
        elif op == 0x4D and i + 1 < len(b):
            n = int.from_bytes(b[i:i+2], "little"); i += 2
        elif op == 0x4E and i + 3 < len(b):
            n = int.from_bytes(b[i:i+4], "little"); i += 4
        else:
            continue  # non-push opcode (OP_13 for runes, etc.) — skip it
        out.append(b[i:i+n]); i += n
    return out


def extract_graffiti(tx):
    """Human text from a tx's OP_RETURN outputs: [{'s':'op','t':text}]."""
    found = []
    for vout in tx.get("vout", []):
        h = vout.get("scriptPubKey", {}).get("hex", "")
        if not h.startswith("6a") or h.startswith("6a5d"):   # skip runes
            continue
        text = human_text(b"".join(_script_pushes(h)))
        if text:
            found.append({"s": "op", "t": text})
            if len(found) >= GRAFFITI_PER_BLOCK:
                break
    return found


MAX_INSCRIBED_TEXT = 400   # only small text/plain inscriptions


def extract_inscribed(tx):
    """Human text from text/plain inscription envelopes:
    [{'s':'ord','t':text}]. JSON bodies (BRC-20 mints etc.) are machine
    payloads and are skipped before the shared gauntlet even runs."""
    found = []
    for vin in tx.get("vin", []):
        for el in vin.get("txinwitness") or []:
            try:
                script = bytes.fromhex(el)
            except ValueError:
                continue
            for span in envelope_spans(script):
                meta = parse_envelope(script, span)
                ct = meta["content_type"].lower().split(";")[0].strip()
                if ct != "text/plain" and ct != "text/plain;charset=utf-8":
                    if not ct.startswith("text/plain"):
                        continue
                if not (0 < meta["content_bytes"] <= MAX_INSCRIBED_TEXT):
                    continue
                # reassemble the body: pushes after the empty separator
                inner = script[span[0] + 2:span[1] - 1]
                toks = list(tokenize(inner))
                body = b""
                for k, t in enumerate(toks):
                    if _is_push(t[1]) and _push_value(t[1], t[2]) == b"":
                        body = b"".join(x[2] for x in toks[k + 1:])
                        break
                if body.lstrip()[:1] in (b"{", b"["):   # JSON = machine
                    continue
                text = human_text(body)
                if text:
                    found.append({"s": "ord", "t": text})
                    if len(found) >= GRAFFITI_PER_BLOCK:
                        return found
    return found


def miner_from_coinbase(block):
    """Decode the coinbase input's printable bytes and match a pool tag."""
    try:
        cb_hex = block["tx"][0]["vin"][0].get("coinbase", "")
        raw = bytes.fromhex(cb_hex)
        text = "".join(chr(b) if 32 <= b < 127 else " " for b in raw).lower()
        for tag, name in POOL_TAGS:
            if tag in text:
                return name
    except Exception:
        pass
    return "Unknown"


def classify_block(height):
    """One mined block -> the dict the portal page renders."""
    block_hash = rpc("getblockhash", [height])
    block = rpc("getblock", [block_hash, 3])
    txs = block["tx"][1:]  # skip coinbase

    envelope = 0
    or_bytes = 0
    or_excess = 0
    families = {}
    graffiti = []

    for tx in txs:
        if len(graffiti) < GRAFFITI_PER_BLOCK:
            room = GRAFFITI_PER_BLOCK - len(graffiti)
            graffiti.extend((extract_graffiti(tx) + extract_inscribed(tx))[:room])
        w = classify_tx_witness(tx)
        if w:
            envelope += w["envelope_bytes"]
            for env in w["envelopes"]:
                fam = (env["content_type"] or "").split(";")[0].split("/")[0]
                fam = fam or "untyped"
                families[fam] = families.get(fam, 0) + env["content_bytes"]
        o = classify_opreturn(tx)
        if o:
            or_bytes += o["total_bytes"]
            or_excess += o["excess_bytes"]

    size = block.get("size", 0)
    top_family = max(families, key=families.get) if families else ""

    # TWO MEASURES, answering two different questions.
    #
    # data_bytes — every non-monetary byte a node must store. Feeds the
    #   odometer and the cumulative pile.
    #
    # beyond_bytes — only what post-2022 policy changes ENABLED:
    #   inscription envelopes (never sanctioned at any size) plus
    #   OP_RETURN bytes past the pre-v30 allowance of one output at 83
    #   bytes. Ordinary small OP_RETURNs are excluded: that channel was
    #   deliberately created and sized in 2014, so counting it against
    #   the policy changes would be measuring the settlement, not the
    #   departure from it. Feeds the tiers and the pure-block clock.
    data_bytes = envelope + or_bytes
    beyond_bytes = envelope + or_excess

    return {
        "miner": miner_from_coinbase(block),
        "height": height,
        "hash": block_hash,
        "time": block["time"],
        "tx_count": len(txs),
        "block_size": size,
        "envelope_bytes": envelope,
        "opreturn_bytes": or_bytes,
        "opreturn_excess_bytes": or_excess,
        "data_bytes": data_bytes,
        "data_share": round(data_bytes / size, 5) if size else 0,
        "beyond_bytes": beyond_bytes,
        "beyond_share": round(beyond_bytes / size, 5) if size else 0,
        "top_family": top_family,
        "graffiti": graffiti,
        "graffiti_v": GRAFFITI_VERSION,
    }


def upgrade_history_graffiti(history):
    """History blocks written before the graffiti wire existed have no
    'graffiti' key, so the wire shows nothing until 30 days roll over.
    Backfill the most recent day's worth using verbosity-2 blocks (vout
    only — much lighter than the full classify)."""
    missing = sorted(
        (b for b in history.values()
         if b.get("graffiti_v") != GRAFFITI_VERSION
         or "beyond_bytes" not in b),
        key=lambda b: -b["height"])[:144]
    if not missing:
        return False
    print(f"(Re)filtering graffiti for {len(missing)} blocks "
          f"(filter v{GRAFFITI_VERSION})...")
    for b in missing:
        try:
            if "beyond_bytes" not in b:
                # needs the full witness accounting, not just vouts
                history[b["height"]] = classify_block(b["height"])
                continue
            blk = rpc("getblock", [b["hash"], 2])
            g = []
            for tx in blk["tx"][1:]:
                if len(g) >= GRAFFITI_PER_BLOCK:
                    break
                room = GRAFFITI_PER_BLOCK - len(g)
                g.extend((extract_graffiti(tx) + extract_inscribed(tx))[:room])
            b["graffiti"] = g
            b["graffiti_v"] = GRAFFITI_VERSION
            if g:
                print(f"  {b['height']:,}: {len(g)} message(s)")
        except Exception as e:
            print(f"  {b['height']:,}: skipped ({e})")
            b["graffiti"] = []
            b["graffiti_v"] = GRAFFITI_VERSION
    return True


def load_history():
    """height -> classified block dict. Survives poller restarts, which is
    what makes a true 24h window possible without re-classifying 144
    blocks on every startup."""
    if not os.path.exists(HISTORY):
        return {}
    try:
        with open(HISTORY, encoding="utf-8") as f:
            return {b["height"]: b for b in json.load(f)}
    except Exception:
        return {}


def save_history(history):
    """Returns True if the file was written. History accumulates, so a
    failed write is retried by the caller until it lands — unlike
    live.json, where the next heartbeat carries everything anyway."""
    blocks = sorted(history.values(), key=lambda b: -b["height"])[:HISTORY_KEEP]
    return write_atomic(blocks, HISTORY)


def pure_stats(history):
    """How many blocks in history carried zero non-monetary bytes, and
    when the last one was. In 2026 the answer is usually 'none' — which
    is the finding, not a bug."""
    if not history:
        return None
    blocks = sorted(history.values(), key=lambda b: -b["height"])
    pure = [b for b in blocks if b.get("beyond_bytes", b["data_bytes"]) == 0]
    return {
        "scanned": len(blocks),
        "pure_count": len(pure),
        "last_pure_height": pure[0]["height"] if pure else None,
        "last_pure_time": pure[0]["time"] if pure else None,
    }


def day_stats(history):
    """Accumulation over the trailing 24h — or over however much history
    exists so far, with the true span reported so the page can label it
    honestly while the window grows toward a full day."""
    cutoff = time.time() - 86400
    recent = [b for b in history.values() if b["time"] >= cutoff]
    if len(recent) < 2:
        return None
    oldest = min(b["time"] for b in recent)
    return {
        "blocks": len(recent),
        "data_bytes": sum(b["data_bytes"] for b in recent),
        "hours": round(min(24.0, (time.time() - oldest) / 3600), 1),
    }


def write_atomic(payload, path=None):
    """Write via temp file + rename so readers never see a partial file.

    On Windows the rename fails with PermissionError if anything else has
    the destination open — python's http.server serving the file, a
    browser fetching it, or antivirus mid-scan. These locks last
    milliseconds, so retry briefly rather than crashing a poller that is
    meant to run for weeks.
    """
    path = path or OUTFILE
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    for attempt in range(8):
        try:
            os.replace(tmp, path)
            return True
        except PermissionError:
            if attempt == 7:
                print(f"  note: {os.path.basename(path)} locked by another "
                      f"process; will retry on the next cycle")
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                return False
            time.sleep(0.25 * (attempt + 1))
    return False


def chain_bytes():
    """On-disk size of the node's block store — the denominator for
    'what fraction of the chain is non-monetary'."""
    try:
        return rpc("getblockchaininfo").get("size_on_disk", 0)
    except Exception:
        return 0


def mempool_snapshot():
    """One cheap RPC — no per-transaction work. Drives portal pressure."""
    try:
        info = rpc("getmempoolinfo")
        return {
            "txs": info.get("size", 0),
            "vbytes": info.get("bytes", 0),
            "total_fee_btc": info.get("total_fee", 0),
        }
    except Exception:
        return None


def emit(history, tip, mempool=None):
    blocks = sorted(history.values(), key=lambda b: -b["height"])
    write_atomic({
        "updated_at": int(time.time()),
        "tip": tip,
        "client": CLIENT,
        "mempool": mempool,
        "chain_bytes": chain_bytes(),
        "day": day_stats(history),
        "pure": pure_stats(history),
        "blocks": blocks[:WINDOW],
    })


def main():
    os.makedirs(os.path.dirname(OUTFILE), exist_ok=True)
    tip = rpc("getblockcount")
    history = load_history()
    print(f"Poller up. Client {CLIENT}, tip {tip:,}. "
          f"History: {len(history):,} blocks.")

    if upgrade_history_graffiti(history):
        save_history(history)

    need = [h for h in range(tip - BACKFILL + 1, tip + 1) if h not in history]
    if need:
        print(f"Classifying {len(need)} missing blocks...")
        for h in need:
            history[h] = classify_block(h)
            print(f"  {h:,}  data_share={history[h]['data_share'] * 100:.2f}%  "
                  f"{history[h]['miner']}")
        save_history(history)
    emit(history, tip, mempool_snapshot())
    history_dirty = False
    print(f"Watching for new blocks every {POLL_SECONDS}s. Ctrl+C to stop.\n")

    while True:
        time.sleep(POLL_SECONDS)
        try:
            new_tip = rpc("getblockcount")
        except Exception as e:
            print(f"  node unreachable ({e}); retrying")
            continue

        if new_tip > tip:
            for h in range(tip + 1, new_tip + 1):
                b = classify_block(h)
                history[h] = b
                print(f"NEW BLOCK {h:,}  {b['miner']}  "
                      f"{b['tx_count']:,} txs  "
                      f"data {b['data_bytes']:,}B "
                      f"beyond {b['beyond_bytes']:,}B "
                      f"({b['beyond_share'] * 100:.2f}%)"
                      f"{'  <- PURE' if b['beyond_bytes'] == 0 else ''}")
            tip = new_tip
            history_dirty = True

        # A history write that lost a lock race stays pending rather than
        # being dropped: the in-memory copy is authoritative and gets
        # flushed on a later cycle.
        if history_dirty and save_history(history):
            history_dirty = False
        # heartbeat every cycle so the page can detect a dead poller;
        # mempool snapshot rides along and drives the portal's agitation
        emit(history, tip, mempool_snapshot())


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
