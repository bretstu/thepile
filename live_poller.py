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

import r2
from rpc import rpc, CLIENT
from witness_classifier import classify_tx_witness
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


# This poller deliberately does NOT extract or store on-chain text. It
# measures data; it does not republish it. Every string in live.json is
# either computed here or drawn from POOL_TAGS below. Anything that
# reintroduces free text from the chain reintroduces the liability of
# publishing whatever a stranger paid to put there.


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

    for tx in txs:
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
        "miner": miner_from_coinbase(block),   # from POOL_TAGS, never raw
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
    }


# THE PUBLISHED CONTRACT.
#
# Every field that may appear in live.json or live_history.json, and
# nothing else. Both writers project through this, so the published files
# cannot carry a field that is not listed here — no matter what a block
# dict picks up in memory, what an older file already contained, or what a
# future contributor adds while debugging.
#
# Adding a name to this tuple is the moment to ask: is this a number this
# code computed, or a label from a bounded list in this repo? If it is
# neither — if it is a string that came off the chain — it does not belong
# in a public file. That is the project's one hard line; this tuple is
# where it is enforced rather than described.
PUBLISHED_FIELDS = (
    "height", "hash", "time", "miner",
    "tx_count", "block_size",
    "envelope_bytes", "opreturn_bytes", "opreturn_excess_bytes",
    "data_bytes", "data_share",
    "beyond_bytes", "beyond_share",
    "top_family",
)


def published(block):
    """One block, reduced to the published contract."""
    return {k: block[k] for k in PUBLISHED_FIELDS if k in block}


def upgrade_history(history):
    """Backfill beyond_bytes into rows written before it existed.

    Needs the full witness accounting, so it costs a reclassify per row
    and is capped at a day's worth per startup.
    """
    missing = sorted((b for b in history.values() if "beyond_bytes" not in b),
                     key=lambda b: -b["height"])[:144]
    if not missing:
        return False
    print(f"Backfilling beyond_bytes for {len(missing)} blocks...")
    for b in missing:
        try:
            history[b["height"]] = classify_block(b["height"])
        except Exception as e:
            print(f"  {b['height']:,}: skipped ({e})")
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
    return write_atomic([published(b) for b in blocks], HISTORY)


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
    blocks = [published(b)
              for b in sorted(history.values(), key=lambda b: -b["height"])]
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

    if upgrade_history(history):
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
    print(r2.describe())
    r2.publish(OUTFILE, HISTORY, force=True)
    history_dirty = False
    print(f"Watching for new blocks every {POLL_SECONDS}s. Ctrl+C to stop.\n")

    while True:
        time.sleep(POLL_SECONDS)
        try:
            new_tip = rpc("getblockcount")
        except Exception as e:
            print(f"  node unreachable ({e}); retrying")
            continue

        new_block = new_tip > tip
        if new_block:
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

        # Publishing is throttled internally: a new block goes out at
        # once, and the intervening heartbeats are batched, because
        # between blocks the only thing that changes is the timestamp
        # proving the poller is alive.
        r2.publish(OUTFILE, HISTORY, force=new_block)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
