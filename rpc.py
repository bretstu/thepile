import os
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

# StartOS uses its own Root CA, so we skip verification on the LAN.
if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def rpc(method, params=None):
    """Call a Bitcoin JSON-RPC method and return the result."""
    payload = {
        "jsonrpc": "1.0",
        "id": "blockspace-dash",
        "method": method,
        "params": params or [],
    }
    response = requests.post(
        URL,
        json=payload,
        auth=(USER, PASSWORD),
        timeout=120,
        verify=VERIFY_TLS,
    )
    body = response.json()
    if body.get("error"):
        raise RuntimeError(f"RPC error on {method}: {body['error']}")
    return body["result"]


if __name__ == "__main__":
    print(f"Connected. Block height: {rpc('getblockcount'):,}")