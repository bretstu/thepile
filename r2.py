"""
Publish the live JSON to Cloudflare R2.

WHY THIS EXISTS
---------------
The node and the poller live on a home network. The website does not. This
module is the only outbound path between them: a few KB of derived JSON
pushed over HTTPS to an object store. Nothing is exposed inbound, no port
is forwarded, and the node's address never leaves the house.

DESIGN RULES
------------
1. OPTIONAL. With no R2 credentials in .env this module no-ops and the
   poller behaves exactly as it always has, writing local files only. A
   contributor cloning the repo must never need a Cloudflare account to
   run the thing.

2. NEVER FATAL. A failed upload prints a line and returns. The poller is
   meant to run for weeks; a flaky home connection or an expired token is
   not a reason to stop measuring the chain. The local files stay
   authoritative and the next successful upload carries everything.

3. RATE-AWARE. R2 bills writes (Class A operations). live.json changes on
   every heartbeat, but nothing a visitor sees changes faster than the
   block clock, so uploads are throttled: immediately on a new block,
   otherwise at most once per MIN_UPLOAD_SECONDS.

SETUP
-----
    pip install boto3

    .env:
        R2_ACCOUNT_ID=...
        R2_ACCESS_KEY_ID=...
        R2_SECRET_ACCESS_KEY=...
        R2_BUCKET=thepile-live
"""

import os
import time

from dotenv import load_dotenv

load_dotenv()

ACCOUNT_ID = os.getenv("R2_ACCOUNT_ID", "")
ACCESS_KEY = os.getenv("R2_ACCESS_KEY_ID", "")
SECRET_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "")
BUCKET = os.getenv("R2_BUCKET", "")

# The browser polls every 15-20s, so a 20s edge cache means a visitor sees
# data at most ~40s stale while R2 itself serves a handful of requests an
# hour regardless of how many people are watching. That gap is what keeps
# a traffic spike from becoming a bill.
CACHE_CONTROL = "public, max-age=20"

# Heartbeats are 5s apart, but only the "poller is alive" timestamp moves
# between blocks. Uploading that 12 times a minute would be 500k writes a
# month to say nothing new.
MIN_UPLOAD_SECONDS = 60

ENABLED = all((ACCOUNT_ID, ACCESS_KEY, SECRET_KEY, BUCKET))

_client = None
_last_upload = 0.0
_warned = False


def _get_client():
    """Lazy so that importing this module never costs anything, and so a
    missing boto3 is only a problem for people who actually publish."""
    global _client, _warned
    if _client is not None:
        return _client
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        if not _warned:
            print("R2: boto3 not installed — publishing disabled "
                  "(pip install boto3)")
            _warned = True
        return None
    _client = boto3.client(
        "s3",
        endpoint_url=f"https://{ACCOUNT_ID}.r2.cloudflarestorage.com",
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        region_name="auto",
        # Fail fast and stay out of the poll loop's way: a stalled upload
        # must not delay the next block's classification.
        config=Config(retries={"max_attempts": 2},
                      connect_timeout=5, read_timeout=15),
    )
    return _client


def put(local_path, key=None):
    """Upload one file. Returns True on success, False on anything else."""
    if not ENABLED:
        return False
    client = _get_client()
    if client is None:
        return False
    key = key or os.path.basename(local_path)
    try:
        with open(local_path, "rb") as f:
            client.put_object(
                Bucket=BUCKET, Key=key, Body=f.read(),
                ContentType="application/json",
                CacheControl=CACHE_CONTROL,
            )
        return True
    except Exception as e:
        # Deliberately broad: network, credentials, DNS, clock skew. None
        # of them are worth stopping a poller over.
        print(f"  R2: upload of {key} failed ({type(e).__name__}: {e})")
        return False


def publish(live_path, history_path, force=False):
    """Push the live pair, throttled unless force=True (a new block).

    Returns True if an upload round actually ran.
    """
    global _last_upload
    if not ENABLED:
        return False
    now = time.time()
    if not force and now - _last_upload < MIN_UPLOAD_SECONDS:
        return False
    _last_upload = now

    ok = put(live_path)
    if force:
        # History only changes when a block lands, so it rides the forced
        # path only. It is also the larger file by an order of magnitude.
        put(history_path)
    return ok


def describe():
    """One line for the poller's startup banner."""
    if not ENABLED:
        return "R2: not configured — writing local files only"
    return f"R2: publishing to {BUCKET} (throttle {MIN_UPLOAD_SECONDS}s)"
