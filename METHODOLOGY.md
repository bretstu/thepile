# Methodology

The long form of what the site states in one screen. Everything here is the reasoning behind the ledger on [thepile.space](https://thepile.space) — the history of how non-monetary data got onto the chain, how each kind is read off a full node, and the bounds on every published figure. The code and tests in this repository are the authoritative version of all of it.

## Part one — how it got there

### Inscriptions — an accident, then a market

An inscription is a file — an image, a line of text, a token ticket — hidden inside the part of a transaction that normally holds signatures. It rides in a script branch that opens on a condition that is always false, so the interpreter skips the whole branch without ever reading it. It cannot affect whether the payment is valid, which leaves those bytes exactly one purpose: being stored.

```
OP_FALSE OP_IF <data> OP_ENDIF
```

None of this was designed. SegWit in 2017 moved signatures into a separate witness area and priced those bytes at roughly a quarter of the normal rate — a fix for transaction malleability, with cheap storage as a side effect. Taproot in 2021 then removed the limit on how large a single script could be, so that complex spending conditions would fit — and, unintended, so would a script the size of an entire block. Two upgrades, each reasonable alone, combined into a large discounted slot guarded only by the rule that a branch which never runs is never examined.

In December 2022 a developer demonstrated the gap by using it; the first inscription sits in block 767,430. Within weeks the technique shipped as a public tool with a convention that assigns each inscription to an individual satoshi, giving the data an owner — NFTs on Bitcoin. Text-token mints followed in 2023 and came to dominate by count. It was raised with Bitcoin Core as a gap in the data limits; the maintainers declined to filter it, on the reasoning that a relay filter does not bind miners and would mostly push the traffic out of view.

**The point that matters for measurement:** inscriptions are not a feature that was switched on. They are a seam between two upgrades — found, then productised. There was never a rule against them to relax.

### OP_RETURN — the deliberate one

OP_RETURN is the opposite story: a data channel added on purpose. By 2014 people were already embedding data in fake addresses, which forces every node to carry those unspendable "coins" in its working memory forever. Bitcoin Core 0.9 offered a lesser evil — an output type that is provably unspendable, so a node stores it once in block history and never adds it to the list of live coins. It launched at 40 bytes of payload, settled at 80, and stayed there for a decade.

In October 2025 Bitcoin Core v30 removed that default cap: multiple OP_RETURN outputs per transaction, up to roughly 100 KB. That is the Core v30 marker on the site's chart.

Every node still downloads, verifies and stores every byte of it, exactly like inscription data. What it avoids is the second, permanent cost — it never enters the chainstate. That difference is the entire reason the third category exists.

### Chainstate — the permanent residue

The chainstate is the database of every coin that currently exists, which every node keeps on hand to check whether the next transaction is spending something real. Inscription dust enters it and stays: spending a few hundred satoshis costs more in fees than it recovers, so tens of millions of these outputs now sit in every node's working set.

This is data doing precisely what OP_RETURN was invented in 2014 to prevent.

It is also different in kind from everything above. Blocks are history: a pruned node deletes them and carries on validating. The chainstate is **state** — no setting removes an entry while the coin exists. So the smallest number on the site is the only permanent one, and it is the one that decides whether modest hardware can still run a node in ten years.

## Part two — how the node is read

### Reading the witness

Each witness script is walked token by token — Bitcoin Script is a fully specified grammar, so every byte belongs to exactly one token — and `OP_FALSE OP_IF` is matched to its `OP_ENDIF` by depth, so a conditional nested inside an envelope cannot close it early. An envelope with no matching `OP_ENDIF` is not counted at all.

Detection is structural, not a list of protocols. The shape of the script is the whole test, so the same rule that caught the first inscription in 2022 catches whatever is invented next, with no code change and no guess at intent.

Every witness byte then lands in exactly one bucket, and the sum is asserted on every single input:

```
envelope + overhead + residual = total witness bytes
```

The **residual** is everything the parser could not attribute, published alongside the headline so a novel embedding trick appears as a spike rather than vanishing. Each block's totals are also checked against `size − strippedsize`, a figure the node reports independently and the parser never touches.

### Reading the outputs

Every output in every block is examined. An OP_RETURN announces itself in its first byte, so finding them needs no heuristics and no protocol list — the script either starts that way or it does not.

Each one is counted at its **stored** size — what a node keeps on disk — and that is the figure every number on the site uses. The script size alone, which the pre-v30 relay rule capped at 83 bytes, is still written to the dataset for anyone studying the policy history, but no figure here is derived from it. Mixing the two would compare a storage figure against a limit that never governed storage.

### Tracking the chainstate

The tracker walks the chain strictly in order, starting thirty blocks before the first inscription — so the tagged set begins **genuinely empty**, with nothing inherited and nothing estimated. Outputs are tagged as they are created and untagged the moment the chain spends them. Order matters within a block too: a transaction can spend an output an earlier transaction in the same block created.

Each entry is stored as the real outpoint rather than a hash, so any of them can be handed straight back to the node and confirmed unspent — the bookkeeping is auditable line by line, and no collision argument is needed anywhere.

Size uses the node's own database-independent metric (`bogosize = 50 + script length`), converted to real bytes with the node's own `disk_size / bogosize` ratio, so every term in the conversion came off the node. As an outside check, counting every reveal output reproduces the figure mempool.space published in its UTXO Set Report — 51,188,145 at block 892,385 — from entirely separate code.

## Part three — where the numbers differ, and what they miss

### One measure, everywhere

Every figure on the site — the total, the chart, the share on each live block — is the same quantity: bytes a node stores because non-monetary data exists. Whole inscription transactions, every OP_RETURN output at its stored size, and the chainstate entries left behind.

The live blocks are not graded or colour-coded. A block's percentage and its bar are the measurement; whether it is high or low is for the reader, against the chain-wide figure at the top. An earlier version of the site ranked blocks against a "typical" band and counted blocks that carried nothing the pre-2023 relay rules would have refused. Both were judgments about rules rather than measurements of storage, and both are gone.

One difference remains between a live block and the total: transfers. Identifying a transfer needs the tagged outpoint set the historical tracker builds, which the live poller does not carry, so the per-block share counts reveal transactions and OP_RETURN only. It reads a little under the chain-wide rate, and in the conservative direction.

### The bounds, stated

Two figures on the site are ranges rather than points, and both are published at the low end.

**Transfers.** Only the provable parts are counted, which undercounts a genuine transfer and refuses to overcount a sweep. The whole-transaction figure is measured as an upper bound, so the answer to "how much is this missing?" is a number rather than a shrug.

**Chainstate.** The published count excludes change and excludes everything the tag reached by propagation. Counting every reveal output gives the cross-check; counting everything tagged gives the ceiling.

### What this does not measure

**"Would have blocked" is softer than it sounds.** The OP_RETURN cap was a relay default, and miners taking transactions directly could always ignore it. Inscriptions were never refused by Bitcoin Core at all. Neither would have been impossible — both would have been harder or dearer.

**Data can move.** Witness bytes are cheaper than output bytes, so data blocked from one route may take another rather than disappear.

**Some carriers are not detected.** Protocols that hide data in fake public keys are counted here as ordinary spending — and their outputs sit in the chainstate too. A pipeline for them is planned.

**The total is a floor.** Commit transactions are missing, fake-key carriers are missing, transfers and chainstate are both published at their low bound, and blocks between the last full scan and the live feed are not counted yet. Every gap points the same way.

---

Every block since the first inscription is parsed on a full node — no indexers, no third-party data, no sampling. A gap in the block range is an error rather than a mode. The classifiers are covered by tests that run without a node, every witness byte is bound by a per-input accounting identity, and every block is checked against a measure the node reports independently. Source, tests and the full method: [github.com/bretstu/thepile](https://github.com/bretstu/thepile).
