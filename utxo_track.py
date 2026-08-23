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
  never puts them in the chainstate. Counting them as UTXOs here would
  inflate every figure in this file. Their SIZE is still recorded, in
  reveal_opreturn_bytes / transfer_opreturn_bytes, but only for
  transactions whose whole size was charged — see the note above FIELDS.
  Those columns are deductions, not additions.

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
#   reveal_tx_bytes   ⊃  reveal_opreturn_bytes
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
#
# THE FULL MEASURE IS THE PUBLISHED ONE, and it brings an overlap the
# narrow measure could not have. An envelope lives in a witness and an
# OP_RETURN lives in an output, so under the narrow measure the two
# pipelines could never touch the same byte. Under the full measure they
# can: a reveal that also carries an OP_RETURN — a Runes etching is
# exactly this shape — has those script bytes inside its own size AND
# counted again by the OP_RETURN builder.
#
# The intersection is measured here and DEDUCTED FROM THE INSCRIPTION
# SIDE. Either side could carry the deduction — the total is identical —
# but taking it here leaves the OP_RETURN figure as "every OP_RETURN byte
# on chain", which anyone with a node can reproduce. The alternative left
# it as "every OP_RETURN except the ones inside inscription
# transactions", a quantity nobody else computes and nobody can check.
#
# The published pile is therefore
#
#   (reveal_tx_bytes    - reveal_opreturn_bytes)
# + (transfer_tx_bytes  - transfer_opreturn_bytes)
# + all OP_RETURN stored bytes
# + chainstate

# Value bands, in sats. Stored as counts so the dust threshold stays a
# DISPLAY decision — "dust" moves with the fee market, and baking one
# number in here would mean another full rebuild to change your mind.
# 330 and 546 are the P2TR and legacy dust limits; 1000 matches the
# mempool report's headline bin.
BANDS = (330, 546, 1_000, 10_000)
BAND_NAMES = ("b330", "b546", "b1k", "b10k", "bhi")

# Transfers only propagate the tag to outputs this small. It is also the
# project's single definition of "dust": the value at or below which an
# output is treated as carrying an inscription rather than money. Used by
# the propagation bound AND by the provable-floor columns, so the two can
# never drift apart.
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
    # reveal-only, for the mempool.space cross-check. Counts EVERY
    # output of a reveal, change included, because that is how the
    # published figure it is checked against is defined.
    "reveal_added", "reveal_removed",
    # reveal-only AND dust. The provable chainstate burden: outputs of a
    # reveal small enough to be carrying the inscription rather than
    # returning money to the inscriber. Excludes change, excludes
    # everything propagation added. This is the published figure.
    "reveal_dust_added", "reveal_dust_removed",
    "reveal_dust_bogo_added", "reveal_dust_bogo_removed",
    # activity, and the block-side cost of the transactions themselves
    "transfer_txs",
    # THE PROVABLE FLOOR FOR TRANSFERS.
    #
    # transfer_tx_bytes below is the CEILING: the whole transaction,
    # correct when the transaction exists only to move an inscription
    # and wrong when an inscription rides along with other business —
    # a sweep of 200 dust outputs, three of them tagged, is charged in
    # full. Nothing in the protocol says which of those a transaction
    # is, so neither figure is published alone.
    #
    # These two are what can be proved. The tagged dust input exists
    # because the inscription exists; the tagged output is where it
    # lands. The fee input, the change and the skeleton might belong to
    # the transfer or to something else, so they are outside the floor.
    # Only inputs at or below TAINT_MAX_SATS count: spending a reveal's
    # large change output is ordinary spending, not a transfer.
    "transfer_input_bytes", "transfer_output_bytes",
    # How much of the gap between floor and ceiling is sweeping. A real
    # transfer is 1 tagged input of 2 or 3; a sweep is 3 of 200.
    "transfer_inputs_tagged", "transfer_inputs_total",
    # Block bytes of the tagged OUTPUTS only. Derivable as
    # insc_bogo_added - 41*insc_added, but stored explicitly so the
    # relationship does not have to be rediscovered downstream — and so
    # the two can be cross-checked against each other.
    "insc_output_bytes",
    # Whole serialized size of the transactions, from the node's own
    # "size" field. CONTAINS the envelope and output bytes, so these must
    # never be added to those — see the note above FIELDS.
    "reveal_tx_bytes", "transfer_tx_bytes",
    # OP_RETURN bytes sitting INSIDE those transactions, split the same
    # way the transaction bytes are. The deduction that keeps the two
    # pipelines from charging the same bytes twice — subtracted HERE,
    # from the inscription side, so the OP_RETURN figure stays "every
    # OP_RETURN byte on chain" and anyone with a node can reproduce it.
    #
    # Stored size, not script size: value field and length prefix
    # included, matching or_stored_bytes in the OP_RETURN pipeline. The
    # two must use the same convention or the subtraction is wrong by
    # nine bytes an output.
    "reveal_opreturn_bytes", "transfer_opreturn_bytes",
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


def input_bytes(vin):
    """Serialized bytes of one input, witness included.

    36 (outpoint) + length-prefixed scriptSig + 4 (sequence), plus the
    input's witness stack, which lives elsewhere in the serialization but
    is stored on the same disk for the same reason. Every term comes off
    the node's own decoded transaction.
    """
    ss = (vin.get("scriptSig") or {}).get("hex", "")
    n = len(ss) // 2
    total = 36 + varint_len(n) + n + 4
    wit = vin.get("txinwitness") or []
    if wit:
        total += varint_len(len(wit))
        for item in wit:
            ln = len(item) // 2
            total += varint_len(ln) + ln
    return total


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
            # Per-transaction, because whether these land on the transfer
            # columns depends on is_reveal, which is not known until the
            # inputs have already been walked.
            tagged_in_bytes = tagged_in_n = tx_in_n = 0

            # --- inputs first -------------------------------------------
            if not is_coinbase:
                for vin in tx.get("vin", []):
                    tx_in_n += 1
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
                        bogo = BOGO_OVERHEAD + len(spk.get("hex", "")) // 2
                        row["insc_bogo_removed"] += bogo
                        row[f"insc_{BAND_NAMES[band_index(sats)]}_spent"] += 1
                        if hit[0]:
                            row["reveal_removed"] += 1
                            if sats <= TAINT_MAX_SATS:
                                row["reveal_dust_removed"] += 1
                                row["reveal_dust_bogo_removed"] += bogo
                        # The floor counts only tagged DUST. Spending a
                        # reveal's large change output is the inscriber
                        # spending money, not moving an inscription —
                        # the transaction still trips the ceiling, but
                        # it proves nothing and is left out here.
                        if sats <= TAINT_MAX_SATS:
                            tagged_in_n += 1
                            tagged_in_bytes += input_bytes(vin)

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
                row["transfer_input_bytes"] += tagged_in_bytes
                row["transfer_inputs_tagged"] += tagged_in_n
                row["transfer_inputs_total"] += tx_in_n
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

                # OP_RETURN outputs never enter the chainstate, so they
                # take no further part in the UTXO accounting. They are
                # measured here first: if this transaction's whole size
                # was charged above, these script bytes are inside that
                # charge and the OP_RETURN pipeline is about to count
                # them a second time.
                if spk.get("type") == "nulldata":
                    if is_reveal:
                        row["reveal_opreturn_bytes"] += (
                            8 + varint_len(script_len) + script_len)
                    elif spent_tagged:
                        row["transfer_opreturn_bytes"] += (
                            8 + varint_len(script_len) + script_len)
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
                stored = 8 + varint_len(script_len) + script_len
                row["insc_output_bytes"] += stored
                if not is_reveal:
                    # Tagged by propagation from a transfer, so it is
                    # where the inscription landed — part of the floor.
                    row["transfer_output_bytes"] += stored
                row[f"insc_{band}_created"] += 1
                if is_reveal and track_rev:
                    row["reveal_added"] += 1
                    if sats <= TAINT_MAX_SATS:
                        row["reveal_dust_added"] += 1
                        row["reveal_dust_bogo_added"] += (
                            BOGO_OVERHEAD + script_len)

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
