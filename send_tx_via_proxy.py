#!/usr/bin/env python3

import sys
import json
import requests

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <from_account> <to_account> <rpc_url>")
    sys.exit(1)

from_account = sys.argv[1]
to_account = sys.argv[2]
rpc_url = sys.argv[3]

headers = {"Content-Type": "application/json"}

def to_wei(amount_eth):
    return hex(int(amount_eth * 10**18))

def to_gwei(amount_gwei):
    return hex(int(amount_gwei * 10**9))

# Build the transaction dictionary matching eth_sendTransaction params
tx = {
    "from": from_account,
    "to": to_account,
    "value": to_wei(100),  # 100 ETH
    "gas": hex(21000),
    "gasPrice": to_gwei(20),  # 20 Gwei
}

payload = {
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [tx],
    "id": 1,
}

response = requests.post(rpc_url, headers=headers, data=json.dumps(payload))

if response.status_code == 200:
    resp_json = response.json()
    if "result" in resp_json:
        print(f"Transaction sent! Tx hash: {resp_json['result']}")
    else:
        print(f"Error sending transaction: {resp_json.get('error')}")
else:
    print(f"HTTP error: {response.status_code}")
