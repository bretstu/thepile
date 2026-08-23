import os
import random
import sys
import time

import requests
import urllib3
from dotenv import load_dotenv

load_dotenv()

HOST = os.getenv("BITCOIN_RPC_HOST")
PORT = os.getenv("BITCOIN_RPC_PORT", "8332")
SCHEME = os.getenv("BITCOIN_RPC_SCHEME", "http")
USER = os.getenv("BITCOIN_RPC_USER")
PASSWORD = os.getenv("BITCOIN_RPC_PASSWORD")
VERIFY_TLS = os.getenv("BITCOIN_RPC_VERIFY_TLS", "true").lower() == "true"
CLIENT = os.getenv("BITCOIN_CLIENT", "unknown")
CHAIN = os.getenv("BITCOIN_CHAIN", "mainnet")

URL = f"{SCHEME}://{HOST}:{PORT}/"

# How long to keep retrying a call that fails at the TRANSPORT level.
#
# A multi-day scan will outlive at least one of: a router reboot, a node
# restart for an update, a DHCP renewal, a brief Wi-Fi drop. Without
# this, any one of them ends the run — cleanly and resumably, but it
# ends, and if nobody is at the keyboard the machine then sits idle for
# however long that is. Fifteen minutes covers every ordinary
# interruption; anything longer is a real outage worth stopping for.
RETRY_SECONDS = int(os.getenv("BITCOIN_RPC_RETRY_SECONDS", "900"))

# Transient by definition: the request never reached a working node, so
# retrying it cannot double-apply anything. getblock is a read — there is
# no such thing as a partially applied one.
_TRANSIENT = (requests.exceptions.ConnectionError,
              requests.exceptions.Timeout,
              requests.exceptions.ChunkedEncodingError)

# bitcoind answers 503 while it is still loading the block index, and a
# proxy in front of it answers 502/504 when the backend is restarting.
_TRANSIENT_STATUS = {502, 503, 504}

# StartOS uses its own Root CA, so we skip verification on the LAN.
if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def rpc(method, params=None):
    """Call a Bitcoin JSON-RPC method and return the result.

    Retries transport failures with exponential backoff for up to
    RETRY_SECONDS. An RPC-level error — a bad height, a method the node
    does not have — is NOT retried: the node answered, and the answer
    was no. Masking that behind a retry loop would turn a bug into a
    fifteen-minute pause.
    """
    payload = {
        "jsonrpc": "1.0",
        "id": "blockspace-dash",
        "method": method,
        "params": params or [],
    }

    deadline = time.monotonic() + RETRY_SECONDS
    delay = 1.0
    attempt = 0

    while True:
        attempt += 1
        try:
            response = requests.post(
                URL,
                json=payload,
                auth=(USER, PASSWORD),
                timeout=120,
                verify=VERIFY_TLS,
            )
            if response.status_code in _TRANSIENT_STATUS:
                raise requests.exceptions.ConnectionError(
                    f"HTTP {response.status_code} from the node")
            body = response.json()
            if body.get("error"):
                raise RuntimeError(f"RPC error on {method}: {body['error']}")
            if attempt > 1:
                print(f"\n  [rpc] recovered after {attempt} attempts\n",
                      file=sys.stderr, flush=True)
            return body["result"]

        except _TRANSIENT as e:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(
                    f"Node unreachable for {RETRY_SECONDS}s while calling "
                    f"{method}. Last error: {e}") from e
            # Jitter, because every prefetch worker fails at the same
            # instant when the node goes away and would otherwise
            # reconnect in lockstep.
            wait = min(delay, 60.0, remaining) * (0.5 + random.random())
            if attempt == 1:
                print(f"\n  [rpc] node unreachable ({e.__class__.__name__}); "
                      f"retrying for up to {RETRY_SECONDS // 60} min\n",
                      file=sys.stderr, flush=True)
            time.sleep(wait)
            delay = min(delay * 2, 60.0)


if __name__ == "__main__":
    print(f"Connected. Block height: {rpc('getblockcount'):,}")