"""
Text classification for the graffiti archive.

Pure functions, no network. Shared by both builders (and eventually the
live poller) so OP_RETURN text and inscribed text pass through ONE set
of rules — divergent filters in different pipelines would make the
archive incoherent.

STORAGE PHILOSOPHY
------------------
The builders STORE everything decodable, labeled by category. Display
layers decide what to show (human-only wire, full garbage feed, both).
Storage never gatekeeps, because re-scanning the chain costs days and
a display filter costs nothing.

Categories (bounded vocabulary, same philosophy as the classifiers):
    human    natural-language shape: multiple words, mostly letters
    bridge   machine routing text: crypto addresses, to:/from: verbs
    json     payload begins { or [ — BRC-20 mints and friends
    tag      decodable but not language: protocol tags, IDs, hex-ish

SAFETY, APPLIED AT STORAGE TIME
-------------------------------
    - URLs are redacted to [link] before the text ever touches disk
    - blocklisted slurs cause the whole message to be dropped
    - text truncated to MAX_TEXT chars
Display layers must still render via textContent (never innerHTML) and
apply their own review posture before anything goes public.
"""

import re

from witness_classifier import (envelope_spans, parse_envelope, tokenize,
                                _is_push, _push_value)

MIN_LEN = 8          # shorter is protocol noise
MAX_TEXT = 200       # truncation cap for stored text
MAX_INSCRIBED_BODY = 1000   # only consider small text/plain bodies

# Messages containing any of these are dropped entirely (case-insensitive).
BLOCKLIST = ["nigger", "faggot", "kike", "spic", "chink"]

# Known machine prefixes that would otherwise decode as text.
PROTOCOL_PREFIXES = (b"=:", b"SWAP:", b"OUT:", b"REFUND:", b"omni",
                     b"CNTRPRTY", b"RSKBLOCK:", b"ion:", b"DC-L5:")

_URL = re.compile(r"https?://\S+|www\.\S+", re.I)
_MACHINE = [
    re.compile(r"0x[0-9a-fA-F]{16,}"),           # EVM address/hash
    re.compile(r"[1-9A-HJ-NP-Za-km-z]{26,}"),    # base58 run (BTC/TRON/...)
    re.compile(r"\bbc1[a-z0-9]{20,}", re.I),     # bech32
    re.compile(r"\b(?:to|from|refund|out|memo|migrate|swap|bridge)\s*:",
               re.I),
]
_WORD = re.compile(r"[A-Za-z]{2,}")
_OKCHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
               "0123456789 .,!?'\"-:;()@#&/\n")


def decode_text(payload: bytes):
    """UTF-8 decode with printability gate; whitespace collapsed, URLs
    redacted, truncated. None if this isn't text at all."""
    if len(payload) < MIN_LEN:
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
    if not text or printable / len(text) < 0.9:
        return None
    text = " ".join(text.split())
    text = _URL.sub("[link]", text)
    if not text:
        return None
    low = text.lower()
    if any(w in low for w in BLOCKLIST):
        return None
    return text[:MAX_TEXT]


def looks_human(text: str) -> bool:
    """Natural-language shape: several real words, mostly letters,
    ordinary punctuation. Structural, not enumerative — protocol tags
    fail on shape no matter what they're named next month."""
    if " " not in text or len(_WORD.findall(text)) < 2:
        return False
    letters = sum(1 for c in text if c.isalpha())
    if letters / len(text) < 0.55:
        return False
    weird = sum(1 for c in text if c not in _OKCHARS)
    return weird / len(text) <= 0.08


def classify_text(payload: bytes):
    """(category, text) or (None, None) for undecodable payloads."""
    if payload.startswith(PROTOCOL_PREFIXES):
        return None, None
    text = decode_text(payload)
    if text is None:
        return None, None
    if text.lstrip()[:1] in ("{", "["):
        return "json", text
    if any(rx.search(text) for rx in _MACHINE):
        return "bridge", text
    if looks_human(text):
        return "human", text
    return "tag", text


# --------------------------------------------------------------------------
# Extraction: OP_RETURN scripts
# --------------------------------------------------------------------------

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
            n = int.from_bytes(b[i:i + 2], "little"); i += 2
        elif op == 0x4E and i + 3 < len(b):
            n = int.from_bytes(b[i:i + 4], "little"); i += 4
        else:
            continue  # non-push opcode (OP_13 for runes, etc.)
        out.append(b[i:i + n]); i += n
    return out


def opreturn_text(script_hex):
    """(category, text) for one OP_RETURN scriptPubKey, or (None, None).
    Runes (6a5d...) skipped — binary payload, never text."""
    if not script_hex.startswith("6a") or script_hex.startswith("6a5d"):
        return None, None
    return classify_text(b"".join(_script_pushes(script_hex)))


# --------------------------------------------------------------------------
# Extraction: inscription envelopes (text/plain bodies only)
# --------------------------------------------------------------------------

def inscribed_texts(tx):
    """[(content_type, category, text), ...] from small text/plain
    envelope bodies in this tx's witness data. Never touches non-text
    content types, so images are structurally unreachable."""
    found = []
    for vin in tx.get("vin", []):
        for el in vin.get("txinwitness") or []:
            try:
                script = bytes.fromhex(el)
            except ValueError:
                continue
            for span in envelope_spans(script):
                meta = parse_envelope(script, span)
                ct = meta["content_type"]
                if not ct.lower().split(";")[0].strip() == "text/plain":
                    continue
                if not (0 < meta["content_bytes"] <= MAX_INSCRIBED_BODY):
                    continue
                inner = script[span[0] + 2:span[1] - 1]
                toks = list(tokenize(inner))
                body = b""
                for k, t in enumerate(toks):
                    if _is_push(t[1]) and _push_value(t[1], t[2]) == b"":
                        body = b"".join(x[2] for x in toks[k + 1:])
                        break
                cat, text = classify_text(body)
                if cat:
                    found.append((ct, cat, text))
    return found


# --------------------------------------------------------------------------
# Miner attribution from the coinbase
# --------------------------------------------------------------------------

POOL_TAGS = [
    ("foundry", "Foundry USA"), ("antpool", "AntPool"), ("f2pool", "F2Pool"),
    ("viabtc", "ViaBTC"), ("binance", "Binance Pool"), ("luxor", "Luxor"),
    ("mara", "MARA Pool"), ("braiins", "Braiins"), ("slush", "Braiins"),
    ("spiderpool", "SpiderPool"), ("ocean.xyz", "OCEAN"), ("ocean", "OCEAN"),
    ("secpool", "SECPOOL"), ("btc.com", "BTC.com"), ("poolin", "Poolin"),
    ("carbon", "Carbon Negative"), ("ultimus", "ULTIMUSPOOL"),
    ("sbi crypto", "SBI Crypto"), ("whitepool", "WhitePool"),
]


def coinbase_ascii(block, limit=100):
    """Printable bytes of the coinbase input — stored raw so pool
    attribution can be re-derived later without a rescan."""
    try:
        cb_hex = block["tx"][0]["vin"][0].get("coinbase", "")
        raw = bytes.fromhex(cb_hex)
        return "".join(chr(b) if 32 <= b < 127 else "." for b in raw)[:limit]
    except Exception:
        return ""


def miner_from_coinbase(block):
    text = coinbase_ascii(block, 200).lower()
    for tag, name in POOL_TAGS:
        if tag in text:
            return name
    return "Unknown"
