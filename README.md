# The Pile

**An exact byte accounting of non-monetary data on the Bitcoin blockchain.**

Inscription envelopes in witness space and OP_RETURN data carriers, parsed
from raw blocks on a self-hosted full node, verified by a per-block
accounting identity, with unattributed bytes reported rather than hidden.

This is a measurement instrument, not an argument. It reports what is
there and states its own uncertainty. What you conclude from the numbers
is your business.

---

## What it measures

Every witness byte lands in exactly one bucket, and the buckets must sum:

```
envelope + overhead + residual == total witness bytes    (asserted, every block)
```

- **envelope** — bytes inside `OP_FALSE OP_IF … OP_ENDIF`. This branch never
  executes, so it has no monetary function; carrying data is all it can do.
- **overhead** — signatures, control blocks. Monetary: they prove ownership.
- **residual** — everything the parser could not attribute. Published
  alongside the headline numbers, because an honest instrument reports its
  own coverage. A novel data-embedding technique shows up as a residual
  spike instead of silently vanishing.

**The published inscription figure is the whole transaction**, not the
envelope. A reveal transaction exists only to publish its payload, so its
signature, skeleton and outputs are all caused by the inscription — and a
node stores serialized transactions, not envelopes. Transfers are charged
on the same counterfactual. The envelope figure is still exported
alongside: it is the payload alone, it is what the per-block grades use,
and the difference between the two is the wrapper.

For OP_RETURN, every byte is counted: an OP_RETURN output is provably
unspendable, so it is a data carrier at any size. The pre-v30 83-byte
limit is tracked separately as a *policy* metric ("excess bytes"), not as
the monetary boundary. OP_RETURN bytes that sit *inside* an inscription
transaction are deducted (`insc_opreturn_bytes`), since the whole-
transaction measure already charged them — an envelope and an OP_RETURN
could never overlap before, and now they can.

### What it does not measure

- Data hidden in taproot keys, amounts, or nSequence fields —
  steganographic embedding is undetectable by construction.
- Fake-key outputs (bare multisig, fake P2WSH) that occupy the UTXO set.
  Planned as a third pipeline; currently absent.
- Commit transactions. An inscription takes a commit *and* a reveal; the
  commit carries no envelope, so nothing tags it. Its bytes are counted
  nowhere, which makes every total a floor.
- Pre-2014 and pre-inscription history outside the scanned range.

---

## Architecture

One direction, no loops:

```
Bitcoin node ──> builders ──> data/*.csv ──> export.py ──> cumulative.json ──> R2 ──> static page
                 (refresh.py, every 6h, to tip−6)                                 ▲
                 live_poller.py (always on, the tip) ──> live.json ──────────────┘
```

The page reads three JSON files from R2 and nothing else: `cumulative.json`
from the refresh, `live.json` and `live_history.json` from the poller.
Code goes through git and deploys as a static page; data goes through
R2 and never touches the repo. All aggregation happens in Python; the
browser does no math beyond drawing.

Two services keep it current, and they do different jobs:

- **The poller** classifies each block as it lands — reveals and
  OP_RETURN — and publishes within seconds. It follows the tip.
- **The refresh** resumes the full builders every six hours to six blocks
  below the tip, runs the chainstate tracker (transfers and the UTXO
  burden need state walked in order), audits the result with `check.py`,
  exports, and uploads. It never follows the tip, because the tracker's
  committed state cannot be rewound through a reorg.

The page stitches them at the export's last height: the historical total
through that block, plus the poller's blocks above it.

The dashboard is static files. There is no server, no database, and no
inbound network surface — the node is never exposed.

### Layout

| Path | Purpose |
|---|---|
| `witness_classifier.py` | Envelope detection and witness byte accounting. Pure functions. |
| `opreturn_classifier.py` | OP_RETURN output sizing. Pure functions. |
| `utxo_track.py` | The chainstate tracker: tagged outpoints, provable floors, transfer accounting. |
| `*_build_dataset.py` | Walk the chain, write the CSVs. Resumable; refuse to append across a schema change. |
| `export.py` | CSVs → `cumulative.json`. |
| `live_poller.py` | Watches the tip, classifies new blocks, publishes `live.json` to R2. |
| `refresh.py` | Resumes the builders to tip−6, audits, exports, uploads `cumulative.json`. Scheduled. |
| `deploy/` | systemd units for the poller, the refresh timer and a monthly tracker audit. |
| `check.py` | Full-dataset integrity and version-consistency audit. No node needed. |
| `verify_utxo.py` | Audits the tracker against the live node. |
| `verify_block.py` | One block, re-derived and cross-checked against the CSVs. |
| `check_theme.py` | Structural guard for the page's two-theme stylesheet. |
| `dashboard/index.html` | The dashboard: headline, chart, live blocks, composition, and the accounting ledger. |
| `test_*.py` | Tests for the classifiers and the tracker. No node required. |

---

## Running it

Requires Python 3.10+ and a Bitcoin full node (Core or Knots 25+) with
`txindex=1` and `getblock` verbosity 3.

```bash
cp .env.example .env          # then fill in your node's RPC details
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
```

Verify the classifiers and the tracker before trusting any number:

```bash
python test_witness_classifier.py
python test_opreturn_classifier.py
python test_utxo_track.py
```

Build the datasets the first time (hours to a day, resumable):

```bash
python opreturn_build_dataset.py 1 <tip-6>           # from genesis: OP_RETURN
                                                     # history and the chain-size
                                                     # denominator
python witness_build_dataset.py 767400 <tip-6> 3     # from just before the
                                                     # first inscription
python check.py                                      # integrity + version audit
python verify_utxo.py --node                         # tracker vs the live node
python export.py
```

After that, nothing is run by hand. Install the services:

```bash
./deploy/install.sh
```

That starts the poller, a refresh timer (every 6 hours; `refresh.py`
resumes both builders, audits, exports, uploads) and a monthly tracker
audit. To refresh immediately: `sudo systemctl start thepile-refresh`.
To watch one: `journalctl -u thepile-refresh -n 40 --no-pager`.

The only manual steps left are pushing code, and rebuilding `data/`
from scratch when a CSV schema changes.

Then serve the dashboard:

```bash
cd dashboard && python -m http.server 8000
```

Arguments are `start end workers`. Every block in the range is scanned;
`workers` overlaps RPC fetches with classification (3 is safe on 8-10 GB
of RAM for the witness scan, which holds decoded verbosity-3 blocks).
Start the witness scan at or below 767,400 so the UTXO tracker begins
from a genuinely empty set — it refuses to run otherwise rather than
inherit an unknown state.

Both builders refuse to append to a CSV written with a different set of
columns. If you are upgrading across a schema change, move `data/` aside
and rebuild.

---

## Methodology notes

The full write-up — how each kind of non-monetary data got onto the
chain, how it is read off a full node, and the bounds on every published
figure — is in [METHODOLOGY.md](METHODOLOGY.md). The site itself states
only the accounting rules; this is the long form behind them.

**No sampling.** Every block in range is parsed, so every total is a
count rather than an estimate. Sampling was supported once and was
removed: scaling a sum by the step is defensible, but a standing UTXO
count cannot be scaled at all — set membership is not a sum, and an
output added in a scanned block and spent in a skipped one would never
be removed. A gap in the height sequence is an error, not a mode; the
export refuses and names the missing range.

**Perceptual encoding, disclosed.** On the live dashboard the data-share
aura is scaled non-linearly so a 1% block is visible. The printed
percentage is always exact. The number is honest; the glow is legible.

**Conservative tagging.** Protocol labels are only asserted for
signatures documented well enough to defend. Everything else lands in a
small set of structural buckets. Raw payload prefixes are stored
separately so the unclassified population can be studied later without
re-scanning the chain.

---

## Contributing

Issues and pull requests welcome. Things that would help most:

- **Verification.** Run the scans against your own node and compare
  totals. Independent reproduction is the point.
- **The fake-key pipeline.** Bare multisig and fake-P2WSH data storage —
  the only category that occupies the UTXO set permanently.
- **Residual analysis.** Anything currently unattributed that should be.

Please keep classifiers pure (no network, no file I/O) and add tests for
new detection logic. The test suites are the reason anyone should believe
the numbers.

## Security

Do not commit `.env`. The `data/` directory is gitignored: it is large
and regenerable from the builders.

## License

MIT. See `LICENSE`.
