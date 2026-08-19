"""
Track the UTXO burden left behind by inscriptions.

WHAT THIS MEASURES

An inscription writes bytes into a witness, and those bytes are counted
elsewhere in this project. But the reveal transaction also creates an
OUTPUT, and that output sits in every node's chainstate until somebody
spends it. At a few hundred sats each, spending costs more than the
output holds, so in practice they never move.

This module walks the chain in order and maintains the set of outpoints
attributable to inscriptions, so each block can report how many entered
the UTXO set and how many left. Integrating those two columns gives the
standing burden at any height.

WHY THE STARTING POINT IS EXACT

The first inscription is in block 767,430. Start the scan at or before
767,400 and the tagged set is genuinely empty — there is nothing to
inherit and nothing to estimate. Every later value is observed.

TWO DEFINITIONS, TRACKED SEPARATELY

  reveal   Outputs of transactions carrying an inscription envelope.
           This matches the mempool.space UTXO Set Report, whose figure
           (51,188,145 at block 892,385) is the external check on this
           implementation.

  tainted  The same, plus propagation through transfers. An ordinal
           transfer spends the inscribed output with an ordinary keypath
           spend and creates a fresh dust output — no envelope anywhere
           in it. Under the reveal-only definition that looks like a
           removal with no matching addition, so the count decays while
           the burden has not moved. mempool.space names this as
           unsolved future work.

           Propagation is deliberately bounded: only outputs at or below
           TAINT_MAX_SATS inherit the tag. Without that bound, one
           consolidation into a real wallet would mark ordinary money as
           inscription-related forever.

WHY SQLITE AND NOT A PYTHON SET

The tagged set peaks near 60 million entries and every input in the
chain — about 1.4 billion of them — is tested against it. Held in
memory as Python objects that is roughly 8 GB, which rules out ever
running an incremental refresh on a Raspberry Pi, and it forces a
space-saving compromise: storing a hash of each outpoint rather than
the outpoint itself. Hashes cannot collide often, but they can collide,
and they cannot be handed to the node to check.

On disk the same set is ~2.3 GB, the RAM cost is whatever page cache is
configured, and there is no reason not to store the real 36-byte
outpoint. That removes the collision question completely rather than
making it small, and it means any tagged outpoint can be looked up with
gettxout to confirm the bookkeeping.

Measured on this workload: ~158k lookups/sec, adding roughly 2.5 hours
to a full rebuild. The database is also the resume state, so there is
no separate checkpoint file that could fall out of step with the CSV.

WHAT IS NOT COUNTED

  OP_RETURN outputs. They are provably unspendable and Bitcoin Core
  never puts them in the chainstate. Counting them here would inflate
  every figure in this file.

  Coinbase inputs. They spend nothing. Coinbase OUTPUTS are counted,
  because they do enter the set.

BOGOSIZE

Chainstate bytes are not knowable from block data — LevelDB compresses.
So this records Core's own database-independent metric instead:

    bogosize = 50 + len(scriptPubKey)

Report the tagged bogosize as a share of the node's total bogosize from
gettxoutsetinfo, multiply by its disk_size, and every term in the
conversion came off the node. Verify the constant against coinstats.cpp
if it ever looks wrong; what matters is using the SAME formula the node
uses, since the figure is only consumed as a ratio.
"""

import os
import sqlite3

BOGO_OVERHEAD = 50

# WHAT ADDS UP AND WHAT DOES NOT
#
# A reveal transaction puts several distinct things on disk, and two of
# the columns here are supersets of others. Adding them all would double
# count badly — for an average image inscription, 13,506 bytes instead of
# the true ~6,900.
#
#   reveal_tx_bytes   ⊃  envelope_bytes  (witness payload)
#   reveal_tx_bytes   ⊃  insc_output_bytes
#   insc_bogo_*       ∩  everything above  =  nothing
#                        chainstate is a separate database, so it is
#                        always additive
#
# Two coherent totals, and only two:
#
#   narrow  envelope + insc_output_bytes + chainstate
#           = the data, its vessel, and the permanent index entry
#
#   full    reveal_tx_bytes + transfer_tx_bytes + chainstate
#           = every byte those transactions caused, including the
#             signatures and skeleton any transaction would need
#
# Pick one at display time. Never mix them.

# Value bands, in sats. Stored as counts so the dust threshold stays a
# DISPLAY decision — "dust" moves with the fee market, and baking one
# number in here would mean another full rebuild to change your mind.
# 330 and 546 are the P2TR and legacy dust limits; 1000 matches the
# mempool report's headline bin.
BANDS = (330, 546, 1_000, 10_000)
BAND_NAMES = ("b330", "b546", "b1k", "b10k", "bhi")

# Transfers only propagate the tag to outputs this small.
TAINT_MAX_SATS = 1_000

# Heights at or below this are before the first inscription (767,430), so
# a scan starting here begins from a true empty set.
ANCHOR_HEIGHT = 767_400

DB_FILE = os.path.join("data", "utxo_track.db")

# Page cache. 256 MB is ample for the working set and leaves a Pi room to
# breathe; raise it on a desktop if the build feels I/O bound.
CACHE_MB = 256

FIELDS = [
    # whole-chain UTXO flow
    "outputs_created", "outputs_spent", "output_bytes",
    # tagged flow (reveal + transfers)
    "insc_added", "insc_removed",
    "insc_added_sats", "insc_removed_sats",
    "insc_bogo_added", "insc_bogo_removed",
    # reveal-only, for the mempool.space cross-check
    "reveal_added", "reveal_removed",
    # activity, and the block-side cost of the transactions themselves
    "transfer_txs",
    # Block bytes of the tagged OUTPUTS only. Derivable as
    # insc_bogo_added - 41*insc_added, but stored explicitly so the
    # relationship does not have to be rediscovered downstream — and so
    # the two can be cross-checked against each other.
    "insc_output_bytes",
    # Whole serialized size of the transactions, from the node's own
    # "size" field. CONTAINS the envelope and output bytes, so these must
    # never be added to those — see the note above FIELDS.
    "reveal_tx_bytes", "transfer_tx_bytes",
    # script mix of tagged additions
    "insc_p2tr", "insc_p2wpkh", "insc_other",
    # data-in-multisig, for later work on Stamps/Counterparty
    "p2ms_created", "p2ms_spent",
    # anomaly counter: must be zero on every block. A non-zero value
    # means an input arrived without prevout data, so a spend went
    # unseen and every later standing count is too high.
    "missing_prevout",
]
FIELDS += [f"out_{b}_created" for b in BAND_NAMES]
FIELDS += [f"out_{b}_spent" for b in BAND_NAMES]
FIELDS += [f"insc_{b}_created" for b in BAND_NAMES]
FIELDS += [f"insc_{b}_spent" for b in BAND_NAMES]

ZERO_ROW = {k: 0 for k in FIELDS}


def band_index(sats):
    """Which value band an output falls in. Returns 0..4."""
    for i, edge in enumerate(BANDS):
        if sats <= edge:
            return i
    return len(BANDS)


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


def outpoint(txid, vout):
    """The real thing: 32 raw txid bytes plus the output index.

    Not a hash. Stored in full so a tagged entry can be handed straight
    to gettxout, and so no collision argument is needed anywhere.
    """
    return bytes.fromhex(txid) + vout.to_bytes(4, "big")


def _sats(vout_obj):
    """BTC float -> integer sats. Exact: every sat value is well inside
    the 53 bits a double represents without loss."""
    return int(round(vout_obj.get("value", 0) * 1e8))


class UTXOTracker:
    """Walks blocks in order, maintaining the tagged outpoints on disk.

    ORDER MATTERS. Within a block a transaction may spend an output
    created by an earlier transaction in the same block, so transactions
    are processed in order and, within each, inputs before outputs.
    Batching all creations and then all spends would give the right net
    counts but corrupt set membership.

    DURABILITY. One SQLite transaction per block, committed by the
    caller via commit(height) once that block's CSV rows are flushed.
    The table therefore never runs ahead of the data, and resuming is
    just "read the height back".
    """

    def __init__(self, path=DB_FILE, track_reveal=True):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.con = sqlite3.connect(path)
        self.track_reveal = track_reveal
        self.con.executescript(f"""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA cache_size=-{CACHE_MB * 1024};
            PRAGMA temp_store=MEMORY;
            CREATE TABLE IF NOT EXISTS tagged (
                op   BLOB PRIMARY KEY,     -- 36-byte outpoint
                rev  INTEGER NOT NULL      -- 1 if created by a reveal
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS meta (
                k TEXT PRIMARY KEY, v INTEGER
            );
        """)
        self.cur = self.con.cursor()

    # ---- resume ---------------------------------------------------------
    @property
    def height(self):
        r = self.cur.execute("SELECT v FROM meta WHERE k='height'").fetchone()
        return r[0] if r else None

    def commit(self, height):
        """Persist this block. Call AFTER the CSV rows are flushed, so the
        recorded height can never be ahead of the data on disk."""
        self.cur.execute(
            "INSERT INTO meta VALUES ('height', ?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (height,))
        self.con.commit()

    def close(self):
        self.con.commit()
        self.con.close()

    # ---- the per-block pass ---------------------------------------------
    def process_block(self, block, envelope_txids):
        """Fold one block in. Returns a dict of the FIELDS counters.

        envelope_txids: txids in this block whose witnesses carry an
        inscription envelope, as already determined by the classifier —
        this module does not re-parse witnesses.
        """
        row = dict(ZERO_ROW)
        cur = self.cur
        track_rev = self.track_reveal

        # Batched per block: one executemany beats thousands of round
        # trips through the SQLite bindings.
        to_add, to_del = [], []

        for tx_i, tx in enumerate(block.get("tx", [])):
            is_coinbase = tx_i == 0
            spent_tagged = False

            # --- inputs first -------------------------------------------
            if not is_coinbase:
                for vin in tx.get("vin", []):
                    prev = vin.get("prevout")
                    if prev is None:
                        # Never expected at verbosity 3. Counted rather
                        # than skipped silently, because a missed spend
                        # inflates every later standing count.
                        row["missing_prevout"] += 1
                        continue
                    sats = _sats(prev)
                    spk = prev.get("scriptPubKey", {})
                    row["outputs_spent"] += 1
                    row[f"out_{BAND_NAMES[band_index(sats)]}_spent"] += 1
                    if spk.get("type") == "multisig":
                        row["p2ms_spent"] += 1

                    op = outpoint(vin["txid"], vin["vout"])
                    hit = cur.execute(
                        "SELECT rev FROM tagged WHERE op=?", (op,)).fetchone()
                    if hit is not None:
                        to_del.append((op,))
                        spent_tagged = True
                        row["insc_removed"] += 1
                        row["insc_removed_sats"] += sats
                        row["insc_bogo_removed"] += (
                            BOGO_OVERHEAD + len(spk.get("hex", "")) // 2)
                        row[f"insc_{BAND_NAMES[band_index(sats)]}_spent"] += 1
                        if hit[0]:
                            row["reveal_removed"] += 1

            if spent_tagged:
                row["transfer_txs"] += 1

            # --- does this transaction tag what it creates? --------------
            is_reveal = tx.get("txid") in envelope_txids

            # Whole-transaction cost, from the node's own size field.
            # Reveal takes precedence so a transaction that both reveals
            # and moves tagged dust is counted once, not twice.
            if is_reveal:
                row["reveal_tx_bytes"] += tx.get("size", 0)
            elif spent_tagged:
                row["transfer_tx_bytes"] += tx.get("size", 0)
            # A reveal tags everything it makes; a transfer tags only the
            # dust it makes, so consolidating into real money does not
            # mark that money as inscription-related.
            tag_all = is_reveal
            tag_dust = is_reveal or spent_tagged

            # --- then outputs -------------------------------------------
            for n, vout in enumerate(tx.get("vout", [])):
                spk = vout.get("scriptPubKey", {})
                script_len = len(spk.get("hex", "")) // 2
                row["output_bytes"] += 8 + varint_len(script_len) + script_len

                # OP_RETURN outputs never enter the chainstate.
                if spk.get("type") == "nulldata":
                    continue

                sats = _sats(vout)
                band = BAND_NAMES[band_index(sats)]
                row["outputs_created"] += 1
                row[f"out_{band}_created"] += 1
                if spk.get("type") == "multisig":
                    row["p2ms_created"] += 1

                if not (tag_all or (tag_dust and sats <= TAINT_MAX_SATS)):
                    continue

                to_add.append((outpoint(tx["txid"], n),
                               1 if (is_reveal and track_rev) else 0))
                row["insc_added"] += 1
                row["insc_added_sats"] += sats
                row["insc_bogo_added"] += BOGO_OVERHEAD + script_len
                row["insc_output_bytes"] += 8 + varint_len(script_len) + script_len
                row[f"insc_{band}_created"] += 1
                if is_reveal and track_rev:
                    row["reveal_added"] += 1

                t = spk.get("type", "")
                if t == "witness_v1_taproot":
                    row["insc_p2tr"] += 1
                elif t == "witness_v0_keyhash":
                    row["insc_p2wpkh"] += 1
                else:
                    row["insc_other"] += 1

            # A transaction can spend an output an EARLIER transaction in
            # this same block created, so pending writes are flushed at
            # the transaction boundary rather than at the end of the
            # block. Otherwise that spend would not find its target.
            if to_del:
                cur.executemany("DELETE FROM tagged WHERE op=?", to_del)
                to_del.clear()
            if to_add:
                cur.executemany(
                    "INSERT INTO tagged VALUES (?,?) "
                    "ON CONFLICT(op) DO NOTHING", to_add)
                to_add.clear()

        return row

    # ---- reporting -------------------------------------------------------
    def standing(self):
        n = self.cur.execute("SELECT COUNT(*) FROM tagged").fetchone()[0]
        r = self.cur.execute(
            "SELECT COUNT(*) FROM tagged WHERE rev=1").fetchone()[0]
        return {"tainted": n, "reveal": r}

    def sample(self, n=200, reveal_only=False):
        """Random tagged outpoints as 'txid:vout', for auditing against
        the node. Every one returned must still be unspent."""
        q = ("SELECT op FROM tagged " + ("WHERE rev=1 " if reveal_only else "")
             + "ORDER BY RANDOM() LIMIT ?")
        return [f"{r[0][:32].hex()}:{int.from_bytes(r[0][32:], 'big')}"
                for r in self.cur.execute(q, (n,))]
