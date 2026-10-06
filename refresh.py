"""
Advance the historical dataset to the tip and publish it. Runs unattended.

    python refresh.py            # the scheduled entry point
    python refresh.py --dry-run  # everything except the upload

WHAT IT DOES, IN ORDER

  1. Ask the node for the tip and aim six blocks below it. The builders
     commit per block and the UTXO tracker's state is not rewindable, so
     they must never follow the tip into a reorg. Six blocks of lag is
     the price of that; the live poller covers the gap.
  2. Resume both builders to that height. Each skips what it already has,
     so a run touches ~36 blocks and finishes in a minute or two.
  3. Run check.py. If anything is inconsistent, STOP. The numbers already
     published stay live and the journal says why.
  4. Run export.py, then upload cumulative.json to R2 beside live.json.
     Data never passes through git.

WHY A SEPARATE SERVICE FROM THE POLLER

  The poller classifies a block in isolation: reveals and OP_RETURN. The
  builders also run the chainstate tracker, which is what gives transfers
  and the UTXO burden — state that must be walked in order from a known
  height. Different fidelity, different reorg tolerance. The poller owns
  the last hour; this owns everything older. The page stitches the two at
  the export's last height.

FAILURE IS FINE

  Every step is resumable or gated. A crash mid-build leaves the CSVs
  one block ahead at worst and the next run resumes. A failed check
  publishes nothing. systemd does not start a second instance while one
  is running, and the lock below covers a manual run on top of that.
"""

import fcntl
import os
import subprocess
import sys
import time

from rpc import rpc

REORG_BUFFER = 6
WITNESS_START = 767_400      # 30 blocks before the first inscription
OPRETURN_START = 1           # genesis: OP_RETURN history and the chain size
WITNESS_WORKERS = 3          # verbosity-3 blocks are heavy; 3 fits in 10 GB
OPRETURN_WORKERS = 5

PY = sys.executable
LOCK = os.path.join("data", ".refresh.lock")
CUMULATIVE = os.path.join("dashboard", "data", "cumulative.json")


def log(msg):
    print(f"[refresh] {msg}", flush=True)


def run(label, *args):
    """Run a pipeline step. Returns True on exit 0.

    The builders draw a progress bar with carriage returns, which is
    noise in a journal, so output is captured and only the tail is shown
    — all of it on failure, the last few lines on success.
    """
    t0 = time.time()
    p = subprocess.run([PY, "-u", *args], capture_output=True, text=True)
    out = (p.stdout + p.stderr).replace("\r", "\n")
    lines = [l for l in out.splitlines() if l.strip()]
    secs = time.time() - t0
    if p.returncode == 0:
        log(f"{label}: ok in {secs:.0f}s")
        for l in lines[-3:]:
            log(f"    {l[:160]}")
        return True
    log(f"{label}: FAILED (exit {p.returncode}) after {secs:.0f}s")
    for l in lines[-25:]:
        log(f"    {l[:200]}")
    return False


def main(dry_run=False):
    os.makedirs("data", exist_ok=True)
    lock = open(LOCK, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log("another refresh is running; leaving it alone")
        return 0

    tip = rpc("getblockcount")
    target = tip - REORG_BUFFER
    log(f"tip {tip:,}, building to {target:,}")

    if not run("opreturn builder", "opreturn_build_dataset.py",
               str(OPRETURN_START), str(target), str(OPRETURN_WORKERS)):
        return 1
    if not run("witness builder", "witness_build_dataset.py",
               str(WITNESS_START), str(target), str(WITNESS_WORKERS)):
        return 1

    # The gate. A dataset that fails its own audit is not published, and
    # the previous export stays live. Nothing here is a warning — check.py
    # exits non-zero only on hard errors.
    if not run("check", "check.py"):
        log("check failed — NOT exporting; previous numbers stay published")
        return 1

    if not run("export", "export.py"):
        return 1

    if dry_run:
        log("dry run: cumulative.json written locally, not uploaded")
        return 0

    import r2
    if not r2.ENABLED:
        log("R2 not configured; cumulative.json written locally only")
        return 0
    if r2.put(CUMULATIVE):
        log(f"published cumulative.json through block {target:,}")
        return 0
    log("upload failed; will retry on the next run")
    return 1


if __name__ == "__main__":
    sys.exit(main(dry_run="--dry-run" in sys.argv))
