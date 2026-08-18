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

For OP_RETURN, every byte is counted: an OP_RETURN output is provably
unspendable, so it is a data carrier at any size. The pre-v30 83-byte
limit is tracked separately as a *policy* metric ("excess bytes"), not as
the monetary boundary.

### What it does not measure

- Data hidden in taproot keys, amounts, or nSequence fields —
  steganographic embedding is undetectable by construction.
- Fake-key outputs (bare multisig, fake P2WSH) that occupy the UTXO set.
  Planned as a third pipeline; currently absent.
- Pre-2014 and pre-inscription history outside the scanned range.

---

## Architecture

One direction, no loops:

```
Bitcoin node ──> builders ──> data/*.csv ──> export.py ──> dashboard/data/*.json ──> static page
                                                                    ▲
                             live_poller.py ─────────────────────────┘
```

The page reads only JSON. The JSON files are a versioned contract, so
either side can be rewritten independently. All aggregation happens in
Python; the browser does no math beyond drawing.

The dashboard is static files. There is no server, no database, and no
inbound network surface — the node is never exposed.

### Layout

| Path | Purpose |
|---|---|
| `witness_classifier.py` | Envelope detection and witness byte accounting. Pure functions. |
| `opreturn_classifier.py` | OP_RETURN parsing and conservative protocol tagging. Pure functions. |
| `graffiti_classifier.py` | Shared text classification (human / bridge / json / tag). |
| `*_build_dataset.py` | Walk the chain, write CSVs. Resumable. |
| `*_explore.py` | Query the CSVs from the command line. `audit` first. |
| `export.py` | CSVs → chart-ready JSON. |
| `live_poller.py` | Watches the tip, classifies new blocks, writes `live.json`. |
| `dashboard/portal.html` | Live dashboard. |
| `dashboard/index.html` | Methodology and deep-dive charts. |
| `test_*.py` | 154 tests, no node required. |

---

## Running it

Requires Python 3.10+ and a Bitcoin full node (Core or Knots 25+) with
`txindex=1` and `getblock` verbosity 3.

```bash
cp .env.example .env          # then fill in your node's RPC details
python -m venv venv && source venv/bin/activate     # Windows: venv\Scripts\activate
```

Verify the classifiers before trusting any number:

```bash
python test_witness_classifier.py      # 64 tests
python test_opreturn_classifier.py     # 62 tests
python test_graffiti_classifier.py     # 28 tests
```

Build a quick sample (every 100th block — minutes, not hours):

```bash
python witness_build_dataset.py 767400 962000 100
python opreturn_build_dataset.py 767400 962000 100
python witness_explore.py audit        # ALWAYS check coverage first
python export.py
```

Then serve the dashboard:

```bash
cd dashboard && python -m http.server 8000
```

Arguments are `start end step workers`. Use `step 1` for a full scan
(hours) and `workers 3` to overlap RPC fetches with classification.

---

## Methodology notes

**Sampling.** A sampled dataset extrapolates chain totals as
`sampled sum × step`. Inscription bytes are heavy-tailed, so those totals
ship with bootstrap confidence intervals and are labeled `estimated`.
A full scan sets the step to 1 and the label flips to exact
automatically. Sampling steps are derived **per month**, so a
partially-completed full scan exports correctly rather than mis-scaling
the sampled remainder.

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
- **Protocol identification.** `opreturn_explore.py unknown` ranks
  unidentified payload prefixes by volume. Confident identifications can
  be promoted into `KNOWN_PAYLOAD_PREFIXES`.
- **Residual analysis.** Anything currently unattributed that should be.

Please keep classifiers pure (no network, no file I/O) and add tests for
new detection logic. The test suites are the reason anyone should believe
the numbers.

## Security

Do not commit `.env`. The `data/` directory is gitignored: it is large,
regenerable, and the graffiti tables contain arbitrary text pulled off
the blockchain — republishing that is a separate decision from publishing
code.

## License

MIT. See `LICENSE`.
