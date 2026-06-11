#low overhead + improvements

#!/usr/bin/env python3
"""
Eclipse Defense Validator (Trust + MTD) — Blue & Green Box Edition
==================================================================

This file merges:
- BLUE BOX (Local, per-node):
  • Metric Collector
  • Local Anomaly Detector (event-driven)
  • Trust Score Manager (decay/increment + evictions)
  • MTD Enforcer (fixed/random/adaptive) + 1s Connection Guard
  • Optional Port Hopping

- GREEN BOX (Global, decentralized/collaborative):
  • Gossip Reputation (EigenTrust-like hints via federated aggregation)
  • On-Chain Alerts/Evidence (JSONL "ledger" with majority flagging)
  • Federated / Shared Anomaly Model (periodic threshold tuning)

Notes
-----
- All original metrics, CSV outputs, scenarios, and analyzer remain intact.
- Global layer is lightweight and file/in-memory only (no actual chain);
  it’s designed to be replaced by real P2P/gossip or on-chain infra later.

Requirements:
  pip install paramiko requests pandas matplotlib numpy
"""

from __future__ import annotations
import os, sys, time, math, csv, random, socket, threading, argparse, json, hashlib, hmac
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

import paramiko,requests

try:
    import pandas as pd
    import matplotlib.pyplot as plt
except Exception:
    pd = None
    plt = None

try:
    import numpy as np
except Exception:
    np = None  # DP noise will be disabled if numpy not available


# ============================
# ========== CONFIG ==========
# ============================
# config.py (or whatever file defines NODES)

import json

def nodes_from_file(path):
    nodes = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            node = json.loads(line)
            nodes.append(node)
    return nodes


CONFIG = {
    "SSH_USER": "phdadmin",
    "SSH_KEY_PATH": os.path.expanduser("~/.ssh/id_ed25519"),
    "GETH_PATH": "/usr/bin/geth",
    "NETWORK_ID": 12345,
    "RESULTS_DIR": "./results",

    # Bring-up reliability
    "START_RETRIES": 3,
    "RETRY_BACKOFF_SEC": 3,
    "PORT_READY_TIMEOUT": 20,
    "RPC_READY_TIMEOUT": 30,

    # Topology
    "NODES": [],

    # Local Defense (BLUE)
    "DEFENSE": {
        # Trust
        "TRUST_INIT": 0.5,
        "TRUST_INC": 0.3,
        "TRUST_DEC": 0.15,
        "TRUST_FLOOR": 0.0,
        "TRUST_CEIL": 1.0,
        "TRUST_DROP_THRESHOLD": 0.35,
        "TRUST_EVENT_DEC": 0.10,         # PATCH: strong event-driven penalty for slow-burn attackers
        "MANAGER_INTERVAL_SEC": 10,

        # Shuffle strategy selection
        "SHUFFLE_MODE": "adaptive",      # fixed | random | adaptive

        # Fixed-time
        "SHUFFLE_INTERVAL_SEC": 120,

        # Random-time
        "SHUFFLE_MIN_SEC": 30,
        "SHUFFLE_MAX_SEC": 100,

        # MTD details
        "SHUFFLE_REPLACE_N": 2,
        "TARGET_MIN_PEERS": 4,

        "FANOUT_PER_NODE": 6,

        # Adaptive thresholds
        "ADAPTIVE_THRESHOLDS": {
            "MIN_IP_ENTROPY": 1.2,
            "MIN_TRUST_MEAN": 0.45,
            "MAX_EXPOSURE_DELTA_SEC": 6,
            "TX_TIMEOUT_RATIO": 0.35,
            "TX_WINDOW": 4,
            # PATCH: debounce & hysteresis knobs
            "RISK_CONSEC_HI": 4,          # require 2 consecutive high-risk ticks to act
            "RISK_CONSEC_LO": 2,          # require 2 consecutive low-risk ticks to clear
            "ENTROPY_HYSTERESIS": 0.1     # lower "ok" threshold for clearing
        },

        # Guards / escalation
        "MIN_HONEST_PEERS": 1,
        "GUARD_INTERVAL_SEC": 20.0,
        "BAN_COOLDOWN_SEC": 15,
        "BAN_COOLDOWN_ATTACKER_SEC": 45,  # PATCH: longer ban for attacker
        "RECOVERY_HARD_RESET": True,
        "STUCK_ECLIPSE_SEC": 8,
        "MIN_PEERCOUNT": 2,
        "MAX_ATTACKER_RATIO": 0.4,
        "MAX_TX_TIMEOUT_RATIO": 0.35,
        "TX_WINDOW": 4,

        # PATCH: per-node shuffle cooldown + token cap
        "SHUFFLE_COOLDOWN_SEC": 45,
        "MAX_REPL_PER_MIN": 1,          # token bucket limit for adaptive replace ops per node

        # PATCH: cap shuffle delay (non-real-time)
        "MAX_SHUFFLE_CAP_SEC": 180.0,

        # PATCH: non-real-time mode (skip adaptive/guard threads)
        "NON_REALTIME_MODE": False,

        # Port hopping (optional)
        "ENABLE_PORT_HOP": False,
        "PORT_HOP_INTERVAL_SEC": 180,
        "PORT_HOP_DELTA": 10,
    },

    # GLOBAL (GREEN)
    "GLOBAL": {
        "ENABLE_GOSSIP": True,
        "GOSSIP_INTERVAL_SEC": 10,
        "EIGENTRUST_ALPHA": 0.6,          # weight of direct experience vs hints
        "ENABLE_ONCHAIN_ALERTS": True,
        "ONCHAIN_FILE": "./results/onchain_alerts.jsonl",
        "ONCHAIN_MAJORITY": 0.5,          # proportion of honest nodes needed to flag
        "ENABLE_FEDERATED": True,
        "FED_INTERVAL_SEC": 15,
        # bounds for federated tuning
        "FED_MIN_IP_ENTROPY_RANGE": (0.8, 2.5),
        "FED_TX_TIMEOUT_RANGE": (0.1, 0.6),
        # PATCH: DP noise for summaries
        "FED_EPSILON": 0.02               # Laplace scale; set 0 to disable
    },
    # TX QoS / Mempool hardening (drop dust, cap queues)
    "TX_QOS": {
        "PRICELIMIT_WEI_NORMAL": 1_000_000_000,   # 1 gwei
        "PRICELIMIT_WEI_DEFCON": 5_000_000_000,   # 5 gwei under flood
        "GLOBAL_SLOTS": 1024,
        "GLOBAL_QUEUE": 1024,
        "ACCOUNT_SLOTS": 128,
        "ACCOUNT_QUEUE": 64,
        "RPC_FEE_CAP_WEI": 50_000_000_000        # 50 gwei cap
    },

    # TX propagation test (optional)
    "TX_TEST": {
        "ENABLE": True,
        "SENDER_NODE_IP": "131.170.68.137",
        "SENDER_ACCOUNT": "0xB9475142b47d0DDeA65a6b5734C3e5Da2ea65Db4",  # 0x...
        "SENDER_PASSPHRASE": "Work1234",
        "DEST_ADDR": "0x7F28C17E10fC04a63D52E4064290740253Fbb566",  # 0x...
        "VALUE_WEI": 1000000000000000000,  # 1 ETH
        "GAS": 21000,
        "GAS_PRICE_WEI": 0,
        "INTERVAL_SEC": 60,
        "TIMEOUT_SEC": 30
    },
    # Attack simulators (lab only)
    "ATTACK": {
        "ENABLE": True,
        # TX flood
        "TX_FLOOD": True,
        "TX_FLOOD_QPS": 2,
        "TX_FLOOD_DURATION_SEC": 120,
        "TX_FROM_NODE_IP": "131.170.68.139",
        "TX_FROM_ACCOUNT": "0xB9475142b47d0DDeA65a6b5734C3e5Da2ea65Db4",
        "TX_FROM_PASSPHRASE": "Work1234",
        "TX_TO_ADDR": "0x7F28C17E10fC04a63D52E4064290740253Fbb566",
        "TX_VALUE_WEI": 0,
        "TX_GAS": 21000,
        "TX_GAS_PRICE_WEI": 0,
        # Connection churn
        "CONN_CHURN": True,
        # "CHURN_TARGETS": ["131.170.68.136","131.170.68.137","131.170.68.138"],
        "CHURN_TARGETS": [],
        "CHURN_OPS_PER_SEC": 1,
        "CHURN_DURATION_SEC": 120,
        # Benign RPC pressure
        "RPC_HAMMER": False,
        "RPC_METHODS": ["net_peerCount","eth_blockNumber","admin_peers"],
        "RPC_QPS": 20,
        "RPC_DURATION_SEC": 60
    }
}
# Append extra nodes dynamically
CONFIG["NODES"] = CONFIG["NODES"] + nodes_from_file("hosts.txt")

# # --- TX_TEST normalization: support VALUE_ETHER -> VALUE_WEI ---
# try:
#     txc = CONFIG.get("TX_TEST", {})
#     if "VALUE_ETHER" in txc and (txc.get("VALUE_ETHER") is not None):
#         val_eth = txc.get("VALUE_ETHER")
#         val_eth_num = float(val_eth) if not isinstance(val_eth, (int,float)) else val_eth
#         txc["VALUE_WEI"] = int(float(val_eth_num) * (10 ** 18))
#     cfg["TX_TEST"] = txc
# except Exception as _e:
#     print("[TXTEST] normalization skipped due to error:", _e)
# ============================
# ========= UTILITIES ========
# ============================
class SSH:
    def __init__(self, host: str, user: str, key_path: str):
        self.host = host; self.user = user; self.key_path = key_path; self.client = None
    def connect(self):
        if self.client: return
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.host, username=self.user, key_filename=self.key_path)
    def exec(self, cmd: str) -> Tuple[int, str, str]:
        self.connect(); stdin, stdout, stderr = self.client.exec_command(cmd)
        rc = stdout.channel.recv_exit_status()
        return rc, stdout.read().decode("utf-8","ignore"), stderr.read().decode("utf-8","ignore")
    def close(self):
        if self.client: self.client.close(); self.client = None

def json_rpc(host: str, port: int, method: str, params: Optional[List]=None, timeout=10):
    url = f"http://{host}:{port}"
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()
    resp = r.json()
    if "error" in resp:
        raise RuntimeError(f"RPC error {resp['error']}")
    return resp.get("result")

def ip_of_remote_address(remote_addr: str) -> str:
    return remote_addr.split(":")[0] if ":" in remote_addr else remote_addr

def entropy(values: List[str]) -> float:
    if not values: return 0.0
    counts: Dict[str,int] = {}
    for v in values: counts[v] = counts.get(v,0)+1
    total = len(values)
    return -sum((c/total)*math.log((c/total)+1e-12,2) for c in counts.values())

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ============================
# ======= DATA STRUCTS =======
# ============================
@dataclass
class NodeCfg:
    ip: str; role: str; datadir: str; http_port: int; p2p_port: int; max_peers: int

@dataclass
class NodeState:
    cfg: NodeCfg; ssh: SSH
    enode: Optional[str] = None; node_id: Optional[str] = None
    known_enodes: Dict[str, str] = field(default_factory=dict)
    trust: Dict[str, float] = field(default_factory=dict)
    last_peer_set: Set[str] = field(default_factory=set)
    malicious_exposure_seconds: float = 0.0
    exposure_marker: float = 0.0


# ============================
# ========== GREEN ===========
# ===== Global Layer =========
# ============================
class GlobalCollaborativeLayer:
    """
    Lightweight 'green box' that runs centrally (this script).
    - Gossip reputation: aggregates local trust into global hints (per peer IP)
    - On-chain alerts: appends signed-like alerts to JSONL; majority -> flagged
    - Federated anomaly: tunes global thresholds and shares back to locals
    """
    def __init__(self, orch: "GethOrchestrator"):
        self.orch = orch
        self.stop_event = orch.stop_event
        self.cfg = orch.cfg["GLOBAL"]
        self.lock = threading.Lock()

        # global state
        self.hints: Dict[str, float] = {}        # peer_ip -> [0..1] trust hint
        self.alerts: List[dict] = []             # in-memory recent alerts
        self.flagged_ips: Set[str] = set()       # majority-flagged bad peers

        # rolling stats for federated tuning
        self.recent_entropy: List[float] = []
        self.recent_tx_timeout: List[float] = []

        # ensure onchain file dir exists
        if self.cfg.get("ENABLE_ONCHAIN_ALERTS", True):
            os.makedirs(os.path.dirname(self.cfg["ONCHAIN_FILE"]), exist_ok=True)

    # ----- Gossip reputation (EigenTrust-like) -----
    def gossip_loop(self):
        if not self.cfg.get("ENABLE_GOSSIP", True): return
        interval = self.cfg.get("GOSSIP_INTERVAL_SEC", 10)
        alpha = float(self.cfg.get("EIGENTRUST_ALPHA", 0.6))
        while not self.stop_event.is_set():
            try:
                # Collect local trust views: map peer_ip -> mean(local_trusts)
                views: Dict[str, List[float]] = {}
                for ip in self.orch.honest_ips:
                    st = self.orch.nodes[ip]
                    peers = self.orch.current_peers(ip)
                    for p in peers:
                        pid = p.get("id")
                        pip = ip_of_remote_address(p["network"]["remoteAddress"])
                        lt = st.trust.get(pid, self.orch.cfg["DEFENSE"]["TRUST_INIT"])
                        views.setdefault(pip, []).append(lt)

                # Aggregate and smooth with previous hints
                with self.lock:
                    for pip, arr in views.items():
                        local = sum(arr)/len(arr)
                        old = self.hints.get(pip, 0.5)
                        self.hints[pip] = alpha*local + (1.0-alpha)*old
            except Exception as e:
                print(f"[Global/Gossip] {e}")
            time.sleep(interval)

    def get_hint(self, peer_ip: str) -> float:
        with self.lock:
            # If flagged by majority, push hint aggressively low
            if peer_ip in self.flagged_ips:
                return 0.0
            return self.hints.get(peer_ip, 0.5)

    # ----- On-chain alerts / evidence (JSONL) -----
    def _valid_sig(self, entry: dict) -> bool:
        key = os.environ.get("ONCHAIN_HMAC_KEY","")
        if not key:
            return True  # accept unsigned in demo mode
        try:
            msg = entry["msg"]
            expect = hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expect, entry.get("sig",""))
        except Exception:
            return False

    def post_alert(self, kind: str, issuer_ip: str, suspect_ip: str, details: dict):
        if not self.cfg.get("ENABLE_ONCHAIN_ALERTS", True): return
        try:
            # PATCH: HMAC evidence signing (verifiable if key present)
            msg = f"{issuer_ip}|{suspect_ip}|{kind}|{json.dumps(details, sort_keys=True)}|{int(time.time())}"
            key = os.environ.get("ONCHAIN_HMAC_KEY","")
            sig = hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest() if key else sha256_hex(msg)
            entry = {
                "ts": int(time.time()),
                "type": kind,
                "issuer": issuer_ip,
                "suspect": suspect_ip,
                "details": details,
                "msg": msg,
                "sig": sig
            }
            self.alerts.append(entry)
            with open(self.cfg["ONCHAIN_FILE"], "a") as f:
                f.write(json.dumps(entry)+"\n")
        except Exception as e:
            print(f"[Global/OnChain] {e}")

    def onchain_loop(self):
        if not self.cfg.get("ENABLE_ONCHAIN_ALERTS", True): return
        # Majority flagging sweeping loop
        interval = self.cfg.get("GOSSIP_INTERVAL_SEC", 10)
        while not self.stop_event.is_set():
            try:
                # Count alerts per suspect from honest issuers (with sig verification if key set)
                counts: Dict[str,int] = {}
                issuers: Set[str] = set(self.orch.honest_ips)
                for a in self.alerts[-200:]:
                    if a.get("issuer") in issuers and self._valid_sig(a):
                        counts[a["suspect"]] = counts.get(a["suspect"],0)+1
                # majority threshold
                need = max(1, int(self.cfg.get("ONCHAIN_MAJORITY", 0.5)*len(self.orch.honest_ips)))
                new_flagged = {sus for sus,c in counts.items() if c >= need}
                if new_flagged - self.flagged_ips:
                    print(f"[Global/OnChain] Majority flagged: {new_flagged - self.flagged_ips}")
                self.flagged_ips |= new_flagged
            except Exception as e:
                print(f"[Global/OnChain] {e}")
            time.sleep(interval)

    # ----- Federated anomaly tuning -----
    def record_fed_samples(self, entropy_vals: List[float], tx_timeout_ratio: float):
        # PATCH: DP noise (Laplace)
        eps = float(self.cfg.get("FED_EPSILON", 0.0))
        def noise():
            if eps <= 0 or np is None: return 0.0
            try:
                return float(np.random.laplace(0.0, eps))
            except Exception:
                return 0.0
        with self.lock:
            self.recent_entropy.extend([e + noise() for e in entropy_vals])
            self.recent_tx_timeout.append(tx_timeout_ratio + noise())
            # keep windows bounded
            if len(self.recent_entropy) > 2000: self.recent_entropy = self.recent_entropy[-2000:]
            if len(self.recent_tx_timeout) > 200: self.recent_tx_timeout = self.recent_tx_timeout[-200:]

    def federated_loop(self):
        if not self.cfg.get("ENABLE_FEDERATED", True): return
        interval = self.cfg.get("FED_INTERVAL_SEC", 15)
        while not self.stop_event.is_set():
            try:
                with self.lock:
                    if not self.recent_entropy:
                        time.sleep(interval); continue
                    # Tune MIN_IP_ENTROPY to ~30th percentile (avoid over-sensitivity)
                    pct = 0.30
                    ent_sorted = sorted(self.recent_entropy)
                    idx = max(0, min(len(ent_sorted)-1, int(pct*len(ent_sorted))))
                    new_min_ent = ent_sorted[idx]
                    lo, hi = self.cfg["FED_MIN_IP_ENTROPY_RANGE"]
                    new_min_ent = max(lo, min(hi, new_min_ent))

                    # Tune TX_TIMEOUT_RATIO to mean+stdev/2 bounded
                    if self.recent_tx_timeout:
                        mean_t = sum(self.recent_tx_timeout)/len(self.recent_tx_timeout)
                        var_t = sum((x-mean_t)**2 for x in self.recent_tx_timeout)/max(1,len(self.recent_tx_timeout))
                        std_t = var_t**0.5
                        new_tx_ratio = mean_t + 0.5*std_t
                    else:
                        new_tx_ratio = 0.25
                    lo2, hi2 = self.cfg["FED_TX_TIMEOUT_RANGE"]
                    new_tx_ratio = max(lo2, min(hi2, new_tx_ratio))

                # publish into local thresholds
                thr = self.orch.cfg["DEFENSE"]["ADAPTIVE_THRESHOLDS"]
                old_e, old_t = thr.get("MIN_IP_ENTROPY", 1.2), thr.get("TX_TIMEOUT_RATIO")
                thr["MIN_IP_ENTROPY"] = new_min_ent
                thr["TX_TIMEOUT_RATIO"] = new_tx_ratio
                print(f"[Global/Fed] MIN_IP_ENTROPY {old_e:.2f}->{new_min_ent:.2f}, TX_TIMEOUT_RATIO {old_t:.2f}->{new_tx_ratio:.2f}")
            except Exception as e:
                print(f"[Global/Fed] {e}")
            time.sleep(interval)


# ============================
# ===== ORCHESTRATOR =========
# ============================
class GethOrchestrator:

    # --- Propagation probes (chain-first) ---
    def _rpc(self, ip, method, params=None, timeout=5):
        return json_rpc(ip, self.nodes[ip].cfg.http_port, method, params or [], timeout=timeout)

    def _probe_tx_known(self, ip, txhash):
        try:
            r = self._rpc(ip, "eth_getTransactionByHash", [txhash], timeout=5)
            if r:
                return True, r
            return False, None
        except Exception as e:
            return "rpc_error", str(e)

    def _probe_tx_receipt(self, ip, txhash):
        try:
            r = self._rpc(ip, "eth_getTransactionReceipt", [txhash], timeout=5)
            if r and isinstance(r, dict) and r.get("blockNumber"):
                return True, r
            return False, r
        except Exception as e:
            return "rpc_error", str(e)

    def _probe_tx_in_pool(self, ip, txhash):
        try:
            tp = self._rpc(ip, "txpool_content", [], timeout=5) or {}
            for sec in ("pending", "queued"):
                secobj = tp.get(sec) or {}
                for addr in secobj.values():
                    for txdata in addr.values():
                        if isinstance(txdata, list):
                            iters = txdata
                        else:
                            iters = [txdata]
                        for ent in iters:
                            if isinstance(ent, dict) and ent.get("hash", "").lower() == txhash.lower():
                                return True, sec
            return False, None
        except Exception as e:
            return "rpc_error", str(e)

    # inside class GethOrchestrator:
    def _normalize_tx_test(self):
        tx = dict(self.cfg.get("TX_TEST", {}))
        tx.setdefault("REQUIRE_ETH_CAPS", True)   # require eth/* caps for gossip
        tx.setdefault("NONCE_GAP_LIMIT", 32)      # warn/abort if gap too large
        tx.setdefault("DIAG_PUSH_RAW", True)      # best-effort raw resend to receivers
        self.cfg["TX_TEST"] = tx

    # --- helper: does the sender have an eth/* capability connection to this receiver? ---
    def _sender_has_eth_caps_to(self, src_ip: str, dest_ip: str) -> bool:
        try:
            peers = json_rpc(src_ip, self.nodes[src_ip].cfg.http_port, "admin_peers") or []
            for p in peers:
                caps = p.get("caps") or []
                ra = (p.get("network") or {}).get("remoteAddress","")
                rip = ra.split(":")[0] if ra else ""
                if rip == dest_ip and any(str(c).startswith("eth/") for c in caps):
                    return True
            return False
        except Exception as e:
            print(f"[TXTEST] caps check error {src_ip}->{dest_ip}: {e}")
            return False

    def _measure_propagation(self, txhash: str, source_ip: str, dest_ip: str, timeout_sec: int):
        import time
        start = time.time()
        status = "not_found"
        while (time.time() - start) <= timeout_sec and (not self.stop_event.is_set()):
            got, info = self._probe_tx_receipt(dest_ip, txhash)
            if got is True:
                delay_ms = int((time.time() - start) * 1000)
                status = "found_chain"
                return delay_ms, 0, status
            if got == "rpc_error":
                status = "rpc_error_receipt"

            got2, info2 = self._probe_tx_known(dest_ip, txhash)
            if got2 is True:
                delay_ms = int((time.time() - start) * 1000)
                status = "found_known"
                return delay_ms, 0, status
            if got2 == "rpc_error":
                status = "rpc_error_tx"

            got3, sec = self._probe_tx_in_pool(dest_ip, txhash)
            if got3 is True:
                delay_ms = int((time.time() - start) * 1000)
                status = f"found_pool_{sec}"
                return delay_ms, 0, status
            if got3 == "rpc_error":
                status = "rpc_error_pool"

            time.sleep(0.5)
        return -1, 1, status
    def __init__(self, config: dict):
        # Deterministic RNGs (set by main)
        self.seed: int = getattr(self, 'seed', 0)
        self.global_rng: random.Random = getattr(self, 'global_rng', random.Random(0))
        try:
            import numpy as _np
            self._np_seed = self.seed
        except Exception:
            self._np_seed = None
        # Monotonic base; set at each run_* start
        self.start_mono: float = time.monotonic()

        self.mode = "baseline"
        self.last_adaptive_action: Dict[str, float] = {}
        self.cfg = config
        
        self._normalize_tx_test()

        self.user = config["SSH_USER"]
        self.key_path = config["SSH_KEY_PATH"]
        self.geth = config["GETH_PATH"]
        self.network_id = config["NETWORK_ID"]
        self.results_root = os.path.abspath(config["RESULTS_DIR"])
        os.makedirs(self.results_root, exist_ok=True)

        self.nodes: Dict[str, NodeState] = {}
        for n in config["NODES"]:
            nc = NodeCfg(**n)
            self.nodes[nc.ip] = NodeState(cfg=nc, ssh=SSH(nc.ip, self.user, self.key_path))

        self.attacker_ip = next(n['ip'] for n in config['NODES'] if n['role'] == 'attacker')
        self.honest_ips = [n['ip'] for n in config['NODES'] if n['role'] in ('honest','boot')]
        # self.cfg.setdefault("ATTACK", {})["CHURN_TARGETS"] = self.global_rng.sample(self.honest_ips, k=min(20, len(self.honest_ips)))  # auto-churn

        # # Exclude sender from propagation targets
        # try:
        #     _sender_ip = self.cfg.get("TX_TEST", {}).get("SENDER_NODE_IP")
        #     if _sender_ip:
        #         self.honest_ips = [ip for ip in self.honest_ips if ip != _sender_ip]

        
        
        # except Exception as _e:
        #     print("[INIT] Could not filter sender from honest_ips:", _e)

        self.stop_event = threading.Event()
        self.metrics: Dict[str, List] = {}
        self.tx_recent: List[int] = []
        self.tx_delay_recent: List[float] = []   # 1=timeout, 0=ok window
        self.ban_until: Dict[str, float] = {}
        self.eclipse_since: Dict[str, float] = {}

        # TX-DEFCON state per node
        self.defcon_nodes: set = set()
        # PATCH: token-bucket state for replacement capping (adaptive)
        cap = int(self.cfg["DEFENSE"].get("MAX_REPL_PER_MIN"))
        self.tokens = {ip: {"t": time.monotonic(), "tokens": cap} for ip in self.honest_ips}

        # PATCH: per-node adaptive state (debounce/hysteresis)
        self._adp_state: Dict[str, Dict[str, float]] = {}

        # PATCH: per-peer low-trust streak counter for adaptive hysteresis.  Each key
        # is a tuple (node_ip, peer_id) and the value is the number of
        # consecutive trust-manager ticks during which the peer's trust has
        # remained below the drop threshold.  This is used to avoid
        # immediately evicting peers after a single low-trust observation.
        from collections import defaultdict
        self.low_trust_streak: Dict[Tuple[str, str], int] = defaultdict(int)

        # BLUE controllers registry
        self.controllers: Dict[str, Dict[str, object]] = {}

        # GREEN layer
        self.global_layer = GlobalCollaborativeLayer(self)

    # ---------- metrics ----------
    def _reset_metrics(self):
        self.metrics = {
            "peer_count": [],
            "ip_entropy": [],
            "trust_stats": [],
            "dsr": [],
            "replacement_events": [],
            "churn": [],
            "tx_propagation": [],
        }
        self.eclipse_since.clear()
        self.ever_eclipsed = {ip: False for ip in self.honest_ips}
        for ip in self.honest_ips:
            st = self.nodes[ip]
            st.last_peer_set = set()
            st.malicious_exposure_seconds = 0.0
            st.exposure_marker = 0.0

    
    def _rng_for(self, key: str) -> random.Random:
        # Derive a stable RNG from the global seed and a key (e.g., ip)
        h = hashlib.sha256(f"{self.seed}|{key}".encode()).hexdigest()
        return random.Random(int(h[:16], 16))
# ---------- bring-up ----------
    def _wait_for_port(self, ip: str, port: int, timeout: int):
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline and not self.stop_event.is_set():
            try:
                with socket.create_connection((ip, port), timeout=1.0):
                    return
            except Exception as e:
                last_err = e
                time.sleep(0.5)
        raise TimeoutError(f"Port {port} on {ip} not reachable: {last_err}")

    def _wait_for_rpc_ready(self, ip: str, port: int, timeout: int) -> dict:
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline and not self.stop_event.is_set():
            try:
                _ = json_rpc(ip, port, "web3_clientVersion")
                info = json_rpc(ip, port, "admin_nodeInfo")
                return info
            except Exception as e:
                last_err = e
                time.sleep(0.5)
        raise TimeoutError(f"RPC not ready on {ip}:{port}: {last_err}")

    
    def _build_txpool_flags(self, n):
        """
        Build mempool QoS flags. Switch pricelimit if node is in DEFCON.
        """
        qos = self.cfg.get("TX_QOS", {})
        if hasattr(self, "defcon_nodes") and (n.cfg.ip in self.defcon_nodes):
            limit = int(qos.get("PRICELIMIT_WEI_DEFCON", 0))
        else:
            limit = int(qos.get("PRICELIMIT_WEI_NORMAL", 0))
        globalslots = int(qos.get("GLOBAL_SLOTS", 1024))
        globalqueue = int(qos.get("GLOBAL_QUEUE", 1024))
        accountslots = int(qos.get("ACCOUNT_SLOTS", 128))
        accountqueue = int(qos.get("ACCOUNT_QUEUE", 64))
        rpc_feecap = int(qos.get("RPC_FEE_CAP_WEI", 0))
        miner_gasprice = max(1, limit // 10) if limit else 1
        return (
            f" --txpool.pricelimit {limit}"
            f" --txpool.globalslots {globalslots}"
            f" --txpool.globalqueue {globalqueue}"
            f" --txpool.accountslots {accountslots}"
            f" --txpool.accountqueue {accountqueue}"
            f" --miner.gasprice {miner_gasprice}"
            f" --rpc.txfeecap {rpc_feecap}"
        )

    def _common_flags(self, n: NodeState, http=True, discovery=True, bootnodes: Optional[str]=None) -> str:
            http_flags = ""
            if http:
                http_flags = (
                    f" --http --http.addr 0.0.0.0 --http.port {n.cfg.http_port}"
                    f" --http.api personal,admin,net,eth,web3,txpool --http.corsdomain '*' --http.vhosts '*'"
                )
            nat_flag = f" --nat extip:{n.cfg.ip}"
            discover_flag = "" if discovery else " --nodiscover"
            boot_flag = f" --bootnodes {bootnodes}" if bootnodes else ""
            unlock_flags = (
                f" --allow-insecure-unlock --unlock {self.cfg['TX_TEST']['SENDER_ACCOUNT']} --password ~/geth_project/password.txt"
                if self.cfg["TX_TEST"]["ENABLE"]
                else ""
            )
            txpool_flags = self._build_txpool_flags(n)
            # " --txpool.pricelimit 0 --miner.gasprice 1 --rpc.txfeecap 0 --txpool.accountqueue 1024 --txpool.globalqueue 10240 --txpool.globalslots 20480 " 
            fanout = int(self.cfg.get("FANOUT_PER_NODE", 6))
            safe_maxpeers = max(6, fanout) # n.cfg.max_peers
            
            return (
                f"--datadir {n.cfg.datadir} --networkid {self.network_id}"
                f" --port {n.cfg.p2p_port} --maxpeers {safe_maxpeers}{nat_flag}{discover_flag}{boot_flag}{http_flags}"
                f"{txpool_flags} {unlock_flags}"
                f" --verbosity 4 --vmodule=txpool=5,p2p=4 "
            )

    def start_node(self, ip: str, discovery=True, logfile: Optional[str]=None):
        n = self.nodes[ip]
        n.ssh.connect()
        # --- ADD THESE LINES ---
        print(f"[{ip}] Wiping old datadir state...")
        # This removes the peer database and discovery cache
        n.ssh.exec(f"rm -rf {n.cfg.datadir}/geth/nodes; rm -f {n.cfg.datadir}/geth/peers.json; mkdir -p {n.cfg.datadir}")
        # -----------------------

        # n.ssh.exec(f"mkdir -p {n.cfg.datadir}")
        logpath = logfile or f"{n.cfg.datadir}/geth_run.log"

        retries = int(self.cfg.get("START_RETRIES", 3))
        backoff = float(self.cfg.get("RETRY_BACKOFF_SEC", 3))
        port_to = int(self.cfg.get("PORT_READY_TIMEOUT", 20))
        rpc_to  = int(self.cfg.get("RPC_READY_TIMEOUT", 30))
        last_err = None

        for attempt in range(1, retries+1):
            cmd = f"nohup {self.geth} {self._common_flags(n, http=True, discovery=discovery)} > {logpath} 2>&1 & echo $!"
            rc, out, err = n.ssh.exec(cmd)
            if rc != 0:
                last_err = RuntimeError(f"start rc={rc}: {err.strip()}")
            else:
                try:
                    self._wait_for_port(ip, n.cfg.http_port, port_to)
                    info = self._wait_for_rpc_ready(ip, n.cfg.http_port, rpc_to)
                    n.enode = info.get("enode"); n.node_id = info.get("id")
                    print(f"[{ip}] started ok: {n.enode}")
                    return
                except Exception as e:
                    last_err = e
            try:
                self.stop_node(ip)
            except Exception:
                pass
            if attempt < retries:
                sleep_for = backoff * attempt
                print(f"[StartNode] {ip} attempt {attempt} failed: {last_err}. Retry in {sleep_for:.1f}s")
                time.sleep(sleep_for)
        raise RuntimeError(f"Failed to start node {ip} after {retries} attempts: {last_err}")

    def stop_node(self, ip: str):
        self.nodes[ip].ssh.exec('pkill -f "geth --datadir"')
        time.sleep(1)

    def restart_with_new_port(self, ip: str, delta: int=10, discovery=True):
        n = self.nodes[ip]
        self.stop_node(ip)
        n.cfg.p2p_port += delta
        self.start_node(ip, discovery=discovery)

    # ---------- peers ----------
    def add_peer(self, from_ip: str, peer_enode: str) -> bool:
        # cooldown ban check
        try:
            peer_ip = peer_enode.split("@")[1].split(":")[0]
            until = self.ban_until.get(peer_ip, 0)
            if until and time.time() < until:
                return False
            # PATCH: stricter green-box hint gate (avoid later churn)
            if self.global_layer.get_hint(peer_ip) <= 0.3:   # was 0.2
                return False
        except Exception:
            pass
        try:
            return bool(json_rpc(from_ip, self.nodes[from_ip].cfg.http_port, "admin_addPeer", [peer_enode]))
        except Exception:
            return False

    def _peer_remote_ip(self, peer_obj: dict) -> str:
        try:
            addr = peer_obj.get("network", {}).get("remoteAddress", "")
            if addr.startswith('['):  # IPv6 form "[::1]:30303"
                return addr.split(']')[0][1:]
            return addr.split(':')[0]
        except Exception:
            return ""

    def _peer_enode(self, peer_obj: dict) -> str:
        # geth admin.peers exposes 'enode' for each peer
        return peer_obj.get("enode") or peer_obj.get("id", "")

    def _current_honest_peer_records(self, node_ip: str):
        """Return list of (peer_ip, peer_enode) for honest peers of node_ip."""
        peers = self.current_peers(node_ip)  # wrapper around admin.peers
        recs = []
        for p in peers:
            pip = self._peer_remote_ip(p)
            if pip and (pip in self.honest_ips) and (pip != node_ip):
                recs.append((pip, self._peer_enode(p)))
        return recs

    def _get_all_peer_records(self, node_ip: str):
            """Return list of (peer_ip, peer_enode) for ALL peers of node_ip."""
            peers = self.current_peers(node_ip)  # This already has the 1s timeout
            recs = []
            for p in peers:
                pip = self._peer_remote_ip(p)
                enode = self._peer_enode(p)
                if pip and enode and (pip != node_ip): # Ensure we have both
                    recs.append((pip, enode))
            return recs

    def remove_peer_hard(self, node_ip: str, peer_ip: str) -> bool:
        """
        Robustly remove a peer from node_ip:
        1. Find the peer's enode from *all* current peers.
        2. Call admin_removePeer(enode).
        3. POLL for up to 3 seconds until the peer is actually gone.
        """
        
        # Step 1: Find the enode
        recs = self._get_all_peer_records(node_ip) 
        target_enodes = [en for pip, en in recs if pip == peer_ip]
        
        if not target_enodes:
            return True # Peer is already gone
        
        enode = target_enodes[0]
        
        # Step 2: Call admin_removePeer
        try:
            # Call the RPC but DO NOT return
            json_rpc(node_ip, self.nodes[node_ip].cfg.http_port, "admin_removePeer", [enode], timeout=2.0)
        except Exception as e:
            print(f"[RemoveHard] admin_removePeer({node_ip}, {peer_ip}) raised: {e}")
            return False # RPC call failed

        # Step 3: Wait and Verify (with polling)
        deadline = time.time() + 5.0  # Poll for up to 3 seconds
        while time.time() < deadline:
            recs2 = self._get_all_peer_records(node_ip)
            if not any(pip == peer_ip for pip, _ in recs2):
                return True # Verification SUCCESS: Peer is gone
            
            # Peer not gone, sleep and retry
            time.sleep(0.25)
            try:
                # Call the RPC but DO NOT return
                json_rpc(node_ip, self.nodes[node_ip].cfg.http_port, "admin_removePeer", [enode], timeout=3.0)
            except Exception as e:
                print(f"[RemoveHard] admin_removePeer({node_ip}, {peer_ip}) raised: {e}")
                return False # RPC call failed

            
        # If we exit the loop, we timed out
        print(f"[RemoveHard] WARNING: peer {peer_ip} still present at {node_ip} after 3s timeout.")
        return False

    def remove_peer_by_ip(self, from_ip: str, peer_ip: str) -> bool:
        return self.remove_peer_hard(from_ip, peer_ip)
        # try:
        #     peers = json_rpc(from_ip, self.nodes[from_ip].cfg.http_port, "admin_peers") or []
        # except Exception:
        #     return False
        # target_enode = None
        # for p in peers:
        #     pip = ip_of_remote_address(p['network']['remoteAddress'])
        #     if pip == peer_ip:
        #         target_enode = p.get('enode'); break
        # if not target_enode:
        #     return False
        # try:
        #     return bool(json_rpc(from_ip, self.nodes[from_ip].cfg.http_port, "admin_removePeer", [target_enode]))
        # except Exception:
        #     return False

    def current_peers(self, ip: str) -> List[dict]:
        try:
            # Add a 1-second timeout to prevent a dead node from freezing the monitor
            return json_rpc(ip, self.nodes[ip].cfg.http_port, "admin_peers", timeout=1.0) or []
        except Exception as e:
            # Optional: log the error to see which node is hanging
            print(f"[Monitor/Warn] Failed to get peers for {ip}: {e}")
            return []

    def partial_connect_honests(self):
        """Randomly connect each honest node to a fixed number of other honest nodes."""
        honest_ips = list(self.honest_ips)
        enodes = {ip: self.nodes[ip].enode for ip in self.honest_ips}
        for src in honest_ips:
            possible_peers = sorted([ip for ip in honest_ips if ip != src])
            selected = self.global_rng.sample(possible_peers, min(self.cfg.get("FANOUT_PER_NODE", 6), len(possible_peers)))
            print(f"[PartialConnect] {src} -> {selected}")
            for dst in selected:
                self.nodes[src].known_enodes[dst] = enodes[dst]
                self.add_peer(src, enodes[dst])


    def connect_honests_among_themselves(self):
        enodes = {ip: self.nodes[ip].enode for ip in self.honest_ips}
        for ip in self.honest_ips:
            for other in self.honest_ips:
                if other == ip: continue
                self.nodes[ip].known_enodes[other] = enodes[other]
                self.add_peer(ip, enodes[other])

    def connect_all_to_attacker(self):
        att_enode = self.nodes[self.attacker_ip].enode
        for ip in self.honest_ips:
            self.nodes[ip].known_enodes[self.attacker_ip] = att_enode
            self.add_peer(ip, att_enode)

    def disconnect_all(self):
        for ip in self.honest_ips:
            peers = self.current_peers(ip)
            for p in peers:
                pip = ip_of_remote_address(p['network']['remoteAddress'])
                self.remove_peer_by_ip(ip, pip)

    def disconnect_all_except_attacker(self):
        print("[Setup] Starting disconnection for all honest nodes...")
        for ip in self.honest_ips:
            try:
                peers_before = self.current_peers(ip)
                peers_to_remove = []
                for p in peers_before:
                    pip = ip_of_remote_address(p['network']['remoteAddress'])
                    if pip != self.attacker_ip and pip != ip: # Also don't try to remove self
                        peers_to_remove.append(pip)
                
                if not peers_to_remove:
                    print(f"[Setup] Node {ip} has no honest peers to remove.")
                    continue

                print(f"[Setup] Node {ip}: Attempting to remove {len(peers_to_remove)} peers: {peers_to_remove}")
                for pip in peers_to_remove:
                    self.remove_peer_by_ip(ip, pip)
                
                # --- VERIFICATION STEP ---
                print(f"[Setup] Node {ip}: Verifying disconnection...")
                time.sleep(1.0) # Give Geth a moment
                peers_after = self.current_peers(ip)
                honest_left = 0
                for p in peers_after:
                    pip_after = ip_of_remote_address(p['network']['remoteAddress'])
                    if pip_after != self.attacker_ip and pip_after != ip:
                        honest_left += 1
                
                if honest_left == 0:
                    print(f"[Setup] Node {ip}: VERIFICATION SUCCESS. 0 honest peers remain.")
                else:
                    print(f"[Setup] Node {ip}: !!! VERIFICATION FAILED. {honest_left} honest peers remain.")

            except Exception as e:
                print(f"[Setup] Node {ip}: CRITICAL ERROR during disconnect: {e}")

        print("[Setup] Disconnection phase complete.")

    # ---------- classify & guard helpers ----------
    def _classify_peers(self, ip: str):
        peers = self.current_peers(ip)
        honest_set = set(self.honest_ips)
        honest_conn, attacker_conn, others = set(), set(), set()
        for p in peers:
            pip = ip_of_remote_address(p["network"]["remoteAddress"])
            if pip == self.attacker_ip:
                attacker_conn.add(pip)
            elif pip in honest_set and pip != ip:
                honest_conn.add(pip)
            else:
                others.add(pip)
        return honest_conn, attacker_conn, others, peers

    def _ban_sweep(self, ip: str):
        peers = self.current_peers(ip)
        for p in peers:
            pip = ip_of_remote_address(p["network"]["remoteAddress"])
            until = self.ban_until.get(pip, 0)
            if until and time.time() < until:
                if self.remove_peer_by_ip(ip, pip):
                    self.metrics["replacement_events"].append([time.time(), ip, "ban_re_drop", pip])

    def _force_recovery(self, ip: str, min_add: int = 2):
        if min_add <= 0:
            return
        existing = {ip_of_remote_address(p["network"]["remoteAddress"]) for p in self.current_peers(ip)}
        boot_ip = next((i for i in self.honest_ips if self.nodes[i].cfg.role == "boot"), None)
        add_list = [x for x in self.honest_ips if x not in (ip, self.attacker_ip)]
        if boot_ip and boot_ip in add_list:
            add_list.remove(boot_ip)
            add_candidates = [boot_ip] + add_list
        else:
            add_candidates = add_list
        added = 0
        for hip in add_candidates:
            if hip in existing: continue
            enode = self.nodes[hip].enode
            if enode and self.add_peer(ip, enode):
                self.metrics["replacement_events"].append([time.time(), ip, "guard_add_honest", hip])
                existing.add(hip); added += 1
                try:
                    json_rpc(ip, self.nodes[ip].cfg.http_port, "admin_addTrustedPeer", [enode])
                except Exception:
                    pass
                if added >= min_add: break
        print(f"[ForceRecovery] {ip} added {added} honest peers for recovery.")

        _, attacker_conn, _, _ = self._classify_peers(ip)
        if attacker_conn:
            for ap in list(attacker_conn):
                if self.remove_peer_by_ip(ip, ap):
                    # PATCH: attacker gets longer ban
                    self.ban_until[ap] = time.time() + float(self.cfg["DEFENSE"].get("BAN_COOLDOWN_ATTACKER_SEC", 45))
                    self.metrics["replacement_events"].append([time.time(), ip, "guard_drop_attacker", ap])

    # ---------- tx propagation ----------
    def _txpool_has_tx(self, ip: str, tx_hash: str) -> bool:
        try:
            content = json_rpc(ip, self.nodes[ip].cfg.http_port, "txpool_content")
        except Exception:
            return False
        # print(f"[TXTEST] checking {ip} for {tx_hash}: Content: {content}")
        for bucket in ("pending","queued"):
            d = content.get(bucket, {}) or {}
            for _from, nonces in d.items():
                for _nonce, txs in nonces.items():
                    for h,_tx in txs.items():
                        if h.lower() == tx_hash.lower(): return True
        return False

    def _is_london_enabled(self, ip: str) -> bool:
        # London blocks include baseFeePerGas in the header
        try:
            blk = json_rpc(ip, self.nodes[ip].cfg.http_port, "eth_getBlockByNumber", ["latest", False])
            return "baseFeePerGas" in (blk or {})
        except Exception:
            return False

    def _send_tx(self):
        txc = self.cfg["TX_TEST"]
        if not txc.get("ENABLE"):
            return None
        # --- TX_TEST normalization: FORCE_LEGACY to bypass 1559 variability ---
        if "FORCE_LEGACY" not in txc:
            txc["FORCE_LEGACY"] = True
        self.cfg["TX_TEST"] = txc

        ip   = txc["SENDER_NODE_IP"]
        acct = txc.get("SENDER_ACCOUNT")
        to   = txc.get("DEST_ADDR")
        val  = int(txc.get("VALUE_WEI", 0))
        gas  = int(txc.get("GAS", 21000))

        # (optional) unlock
        if acct and txc.get("SENDER_PASSPHRASE") is not None:
            try:
                json_rpc(ip, self.nodes[ip].cfg.http_port, "personal_unlockAccount", [acct, txc["SENDER_PASSPHRASE"], 120])
            except Exception as e:
                print(f"[TXTEST] unlock warn: {e}")

        london = self._is_london_enabled(ip)
        MIN_TIP = 1_000_000_000  # 1 gwei
        try:
            # get suggested price (works for both legacy & london)
            gp_hex = json_rpc(ip, self.nodes[ip].cfg.http_port, "eth_gasPrice")
            gp = max(1, int(gp_hex, 16))  # never zero
            tip = max(gp, 1_000_000_000)
            fee_cap = gp + tip 
        except Exception as e:
            print("[TXTEST] Gas Price:", e)
            gp = 1
        # --- Force legacy path if configured ---
        # if self.cfg.get("TX_TEST", {}).get("FORCE_LEGACY", False):
        #     # Choose gasPrice >= max(pricelimit normal/defcon)
        #     print(f"[TXTEST] Sending LEGACY tx from {ip} (bypass 1559)")
        #     qos = self.cfg.get("TX_QOS", {})
        #     g_min = int(qos.get("PRICELIMIT_WEI_DEFCON", 5_000_000_000))
        #     g_norm = int(qos.get("PRICELIMIT_WEI_NORMAL", 1_000_000_000))
        #     gasprice = max(g_min, g_norm, 10_000_000_000)  # at least 10 gwei
        #     tx = {
        #         "from": acct, "to": to, "value": hex(val), "gas": hex(gas),
        #         "gasPrice": hex(gasprice)
        #     }
        # else:
            # existing london/legacy branch follows
        if london:
            # Get suggested priority fee for EIP-1559
            tip_hex = json_rpc(ip, self.nodes[ip].cfg.http_port, "eth_maxPriorityFeePerGas")
            suggested_tip = int(tip_hex, 16)
            tip = max(suggested_tip, 5_000_000_000)
            fee_cap = gp + tip + 2_000_000_000  # add 2 gwei extra buffer

            tx = {
                "from": acct, "to": to, "value": hex(val), "gas": hex(gas),
                "maxPriorityFeePerGas": hex(tip),
                "maxFeePerGas":         hex(fee_cap),
            }
        else:
            # LEGACY (type-0) — the only thing that matters is a non-zero gasPrice
            gasprice = max(5_000_000_000, 1_000_000_000, 10_000_000_000)  # at least 10 gwei
            tx = {
                "from": acct, "to": to, "value": hex(val), "gas": hex(gas),
                "gasPrice": hex(gasprice)
            }

        try:
            h = json_rpc(ip, self.nodes[ip].cfg.http_port, "eth_sendTransaction", [tx])
            return h, time.time()
        except Exception as e:
            # If node rejects type-2, retry once as legacy
            msg = getattr(e, "args", [None])[0] or ""
            print(f"[TXTEST] Type-2 rejected: {e} ==> {msg}")
            if "transaction underpriced" in str(msg) or "type 2 rejected" in str(msg) or "not yet in London" in str(msg):
                tip = 5_000_000_000
                tx.pop("maxPriorityFeePerGas", None)
                tx.pop("maxFeePerGas", None)
                tx["gasPrice"] = hex(tip) #tx.get("gasPrice") or hex(max(1, gp))
                try:
                    h = json_rpc(ip, self.nodes[ip].cfg.http_port, "eth_sendTransaction", [tx])
                    return h, time.time()
                except Exception as e2:
                    print(f"[TXTEST] legacy retry failed: {e2}")
                    return None
            print(f"[TXTEST] send failed: {e}")
            print(e.args[0])
            return None



    def _tx_propagation_loop(self):
        txc = self.cfg["TX_TEST"]
        interval = int(txc.get("INTERVAL_SEC", 60))
        timeout = float(txc.get("TIMEOUT_SEC", 30))
        while not self.stop_event.is_set():
            sent = self._send_tx()
            if sent is None:
                time.sleep(interval); continue
            # # after you get tx hash from the sender:
            # raw = json_rpc(src_ip, http_port_src, "eth_getRawTransactionByHash", [tx_hash])
            # for ip in [ip for ip in self.honest_ips if ip != src_ip]:
            #     try:
            #         r = json_rpc(ip, self.nodes[ip].cfg.http_port, "eth_sendRawTransaction", [raw])
            #         print(f"[TXTEST] Push to {ip}: {r}")
            #     except Exception as e:
            #         print(f"[TXTEST] Push to {ip} failed: {e}")

            tx_hash, t0 = sent
            try:
                _known, _ = self._probe_tx_known(self.cfg["TX_TEST"]["SENDER_NODE_IP"], tx_hash)
                if _known is True:
                    print(f"[TXTEST] Source node {self.cfg['TX_TEST']['SENDER_NODE_IP']} knows tx {tx_hash} immediately.")
                    
                    # --- Nonce-gap & caps preflight; and optional raw resend to receivers ---
                    try:
                        src_ip = self.cfg["TX_TEST"]["SENDER_NODE_IP"]
                        acct = self.cfg["TX_TEST"]["SENDER_ACCOUNT"]
                        # sender's pending nonce (what it'll use for next tx)
                        sent_nonce_hex = json_rpc(src_ip, self.nodes[src_ip].cfg.http_port,
                                                "eth_getTransactionCount", [acct, "pending"]) or "0x0"
                        sent_nonce = int(sent_nonce_hex, 16)
                        # receivers' view of sender's pending nonce
                        targets = [ip for ip in self.honest_ips if ip != src_ip]
                        rx_nonces = []
                        for _ip in targets:
                            try:
                                nr_hex = json_rpc(_ip, self.nodes[_ip].cfg.http_port,
                                                "eth_getTransactionCount", [acct, "pending"]) or "0x0"
                                rx_nonces.append(int(nr_hex, 16))
                            except Exception as e:
                                print(f"[TXTEST] Nonce fetch error @ {_ip}: {e}")
                        if rx_nonces:
                            min_rx = min(rx_nonces)
                            gap = sent_nonce - min_rx
                            print(f"[TXTEST] Nonce preflight: sent={sent_nonce} min_rx={min_rx} gap={gap}")
                            limit = int(self.cfg.get("TX_TEST",{}).get("NONCE_GAP_LIMIT",32))
                            if gap > limit:
                                print(f"[TXTEST] WARNING: nonce gap {gap} exceeds limit {limit}; receivers may drop as far-future.")
                        # Require eth/* caps if configured
                        if bool(self.cfg.get("TX_TEST",{}).get("REQUIRE_ETH_CAPS", True)):
                            for _ip in targets:
                                ok = self._sender_has_eth_caps_to(src_ip, _ip)
                                print(f"[TXTEST] Caps {src_ip}->{_ip}: {'eth/* OK' if ok else 'MISSING'}")
                        # Best-effort raw resend (proves validation vs. gossip)
                        if bool(self.cfg.get("TX_TEST",{}).get("DIAG_PUSH_RAW", True)):
                            raw = None
                            try:
                                raw = json_rpc(src_ip, self.nodes[src_ip].cfg.http_port,
                                            "eth_getRawTransactionByHash", [tx_hash])
                            except Exception as e:
                                print(f"[TXTEST] raw-by-hash not available on sender: {e}")
                            if raw:
                                for _ip in targets:
                                    try:
                                        r = json_rpc(_ip, self.nodes[_ip].cfg.http_port, "eth_sendRawTransaction", [raw])
                                        print(f"[TXTEST] Push raw to {_ip}: {r}")
                                    except Exception as e:
                                        print(f"[TXTEST] Push raw to {_ip} failed: {e}")
                    except Exception as e:
                        print(f"[TXTEST] diagnostics block error: {e}")

                else:
                    print(f"[TXTEST] Source node {self.cfg['TX_TEST']['SENDER_NODE_IP']} did NOT immediately report tx {tx_hash}.")
            except Exception as _e:
                print(f"[TXTEST] Source sanity check error for {tx_hash}: {_e}")


            # --- Peer summary before measuring propagation ---
            try:
                for _ip in self.honest_ips:
                    peers = json_rpc(_ip, self.nodes[_ip].cfg.http_port, "admin_peers") or []
                    peer_ips = [p.get('network',{}).get('remoteAddress','') for p in peers]
                    print(f"[Peers] {_ip}: {len(peers)} -> {peer_ips}")
            except Exception as _e:
                print(f"[Peers] summary error: {_e}")
            any_timeout = 0
            
            targets = [ip for ip in self.honest_ips if ip != self.cfg['TX_TEST']['SENDER_NODE_IP']]
            for ip in targets:
                delay_ms, timeout_flag, status = self._measure_propagation(tx_hash, self.cfg["TX_TEST"]["SENDER_NODE_IP"], ip, timeout)
                if timeout_flag == 1:
                    any_timeout = 1
                self.metrics["tx_propagation"].append([int(t0), tx_hash, self.cfg["TX_TEST"]["SENDER_NODE_IP"], ip, delay_ms, timeout_flag, status])

            self.tx_recent.append(any_timeout)
            win = max(1, self.cfg["DEFENSE"]["ADAPTIVE_THRESHOLDS"].get("TX_WINDOW", 4))

            try:
                last_batch = [row for row in self.metrics.get("tx_propagation", []) if row[-2] == 0][-len(targets):]
                if last_batch:
                    avg_delay = sum(r[3] for r in last_batch) / len(last_batch)
                    self.tx_delay_recent.append(avg_delay)
                    win_d = max(1, self.cfg["DEFENSE"]["ADAPTIVE_THRESHOLDS"].get("TX_WINDOW", 4))
                    if len(self.tx_delay_recent) > win_d:
                        self.tx_delay_recent = self.tx_delay_recent[-win_d:]
            except Exception: pass
            if len(self.tx_recent) > win: self.tx_recent = self.tx_recent[-win:]
            for _ in range(interval):
                if self.stop_event.is_set(): break
                time.sleep(1)

    # ---------- monitor & metrics ----------
    # def _record_metrics_tick(self, t: int):
    #     # Collect per-node metrics and (optionally) publish samples to global layer
    #     ent_samples = []
    #     for ip in self.honest_ips:
    #         n = self.nodes[ip]
    #         peers = self.current_peers(ip)
    #         peer_ids = set(p.get('id') for p in peers)
    #         peer_ips = [ip_of_remote_address(p['network']['remoteAddress']) for p in peers]
    #         # counts
    #         self.metrics["peer_count"].append([t, ip, len(peers)])
    #         # entropy
    #         ent = entropy(peer_ips); ent_samples.append(ent)
    #         self.metrics["ip_entropy"].append([t, ip, ent])
    #         # trust stats
    #         if n.trust:
    #             vals = list(n.trust.values()); mu = sum(vals)/len(vals)
    #             var = sum((x-mu)**2 for x in vals)/max(len(vals),1); std = math.sqrt(var)
    #         else:
    #             mu = std = 0.0
    #         self.metrics["trust_stats"].append([t, ip, mu, std])
    #         # DSR (has at least one HONEST peer)
    #         has_honest = any((pip in self.honest_ips) and (pip != ip) for pip in peer_ips)
    #         self.metrics["dsr"].append([t, ip, 1 if has_honest else 0])
    #         # exposure seconds
    #         if any(pip == self.attacker_ip for pip in peer_ips):
    #             n.malicious_exposure_seconds += 1.0
    #         # churn
    #         added = len(peer_ids - n.last_peer_set)
    #         removed = len(n.last_peer_set - peer_ids)
    #         if added or removed:
    #             self.metrics["churn"].append([t, ip, added, removed])
    #         n.last_peer_set = peer_ids

    #     # feed federated tuner
    #     if self.cfg["GLOBAL"].get("ENABLE_FEDERATED", True):
    #         # tx timeout window ratio
    #         win = max(1, int(self.cfg["DEFENSE"].get("TX_WINDOW", 4)))
            
    #         tx_timeout_ratio = 0.0
    #         if getattr(self, "tx_delay_recent", None):
    #             vals = self.tx_delay_recent[-win:] or []
    #             if vals:
    #                 vs = sorted(vals)
    #                 idx = max(0, int(math.ceil(0.95*len(vs))) - 1)
    #                 p95 = vs[idx]
    #                 thresh = max(float(conf.get("TX_P95_SPIKE_MS", 50)), p95)
    #                 tx_timeout_ratio = sum(1 for v in vals if v > thresh) / max(1, len(vals))
    #         elif self.tx_recent:
    #             tx_timeout_ratio = (sum(self.tx_recent[-win:]) / min(len(self.tx_recent), win)) if self.tx_recent else 0.0
    #         self.global_layer.record_fed_samples(ent_samples, tx_timeout_ratio)
    def _record_metrics_tick(self, t: int):
        """Collect per-node metrics and compute DSR using a sustained-eclipse rule.
        A node is considered *not defended* (0) only if it has had zero honest peers
        continuously for >= STUCK_ECLIPSE_SEC. Otherwise it's marked defended (1).
        """
        conf = self.cfg.get("DEFENSE", {})
        eclipse_win = float(conf.get("STUCK_ECLIPSE_SEC", 12))

        ent_samples = []
        now = time.monotonic()

        for ip in self.honest_ips:
            n = self.nodes[ip]
            peers = self.current_peers(ip)
            peer_ids = set(p.get('id') for p in peers)
            peer_ips = [ip_of_remote_address(p['network']['remoteAddress']) for p in peers]

            # honest counts
            honest_count = sum(1 for pip in peer_ips if (pip in self.honest_ips) and (pip != ip))
            self.metrics.setdefault("honest_counts", []).append([t, ip, honest_count])

            # counts
            self.metrics["peer_count"].append([t, ip, len(peers)])

            # entropy
            ent = entropy(peer_ips); ent_samples.append(ent)
            self.metrics["ip_entropy"].append([t, ip, ent])

            # trust stats
            if n.trust:
                vals = list(n.trust.values()); mu = sum(vals)/len(vals)
                var = sum((x-mu)**2 for x in vals)/max(len(vals),1); std = math.sqrt(var)
            else:
                mu = std = 0.0
            self.metrics["trust_stats"].append([t, ip, mu, std])

            # --- DSR sustained-eclipse logic ---
            has_honest = any((pip in self.honest_ips) and (pip != ip) for pip in peer_ips)
            if has_honest:
                # clear eclipse timer for this node
                if ip in self.eclipse_since:
                    self.eclipse_since.pop(ip, None)
            else:
                # start timer if not already started
                self.eclipse_since.setdefault(ip, now)

            stuck_for = (now - self.eclipse_since.get(ip, now)) if not has_honest else 0.0
            in_sustained_eclipse = (not has_honest) and (stuck_for >= eclipse_win)
            if in_sustained_eclipse:
                self.ever_eclipsed[ip] = True

            defended = 0 if in_sustained_eclipse else 1
            self.metrics["dsr"].append([t, ip, defended])

            # malicious exposure seconds (keep original behavior but only increment when attacker present)
            if any(pip == self.attacker_ip for pip in peer_ips):
                n.malicious_exposure_seconds += 1.0

            # churn
            added = len(peer_ids - n.last_peer_set)
            removed = len(n.last_peer_set - peer_ids)
            if added or removed:
                self.metrics["churn"].append([t, ip, added, removed])
            n.last_peer_set = peer_ids

        # feed federated tuner (unchanged)
        if self.cfg["GLOBAL"].get("ENABLE_FEDERATED", True):
            win = max(1, int(self.cfg["DEFENSE"].get("TX_WINDOW", 4)))
            tx_timeout_ratio = 0.0
            if getattr(self, "tx_delay_recent", None):
                vals = self.tx_delay_recent[-win:] or []
                if vals:
                    vs = sorted(vals)
                    idx = max(0, int(math.ceil(0.95*len(vs))) - 1)
                    p95 = vs[idx]
                    thresh = max(float(conf.get("TX_P95_SPIKE_MS", 50)), p95)
                    tx_timeout_ratio = sum(1 for v in vals if v > thresh) / max(1, len(vals))
            elif self.tx_recent:
                tx_timeout_ratio = (sum(self.tx_recent[-win:]) / min(len(self.tx_recent), win)) if self.tx_recent else 0.0
            self.global_layer.record_fed_samples(ent_samples, tx_timeout_ratio)

    # ---------- trust & shuffle ----------
    def _trust_manager_step(self, ip: str):
        # Gate: trust manager (with fill-to-target) is ADAPTIVE-ONLY.
        if self.mode != "adaptive":
            return

        n = self.nodes[ip]; conf = self.cfg["DEFENSE"]
        peers = self.current_peers(ip)

        # init trust
        for p in peers:
            pid = p.get('id')
            if pid not in n.trust: n.trust[pid] = conf["TRUST_INIT"]

        # green-box hint blending (EigenTrust-like)
        def blend(local_val: float, peer_ip: str):
            hint = self.global_layer.get_hint(peer_ip)
            a = float(self.cfg["GLOBAL"].get("EIGENTRUST_ALPHA", 0.6))
            return a*local_val + (1.0-a)*hint

        # compute tx_timeout_ratio for event-penalty logic
        a_thr = conf["ADAPTIVE_THRESHOLDS"]
        win = max(1, int(conf.get("TX_WINDOW", 4)))
        
        tx_timeout_ratio = 0.0
        if getattr(self, "tx_delay_recent", None):
            vals = self.tx_delay_recent[-win:] or []
            if vals:
                vs = sorted(vals)
                idx = max(0, int(math.ceil(0.95*len(vs))) - 1)
                p95 = vs[idx]
                thresh = max(float(conf.get("TX_P95_SPIKE_MS", 50)), p95)
                tx_timeout_ratio = sum(1 for v in vals if v > thresh) / max(1, len(vals))
        elif self.tx_recent:
            tx_timeout_ratio = (sum(self.tx_recent[-win:]) / min(len(self.tx_recent), win)) if self.tx_recent else 0.0
        event_penalty = float(conf.get("TRUST_EVENT_DEC", 0.10))

        # signals: normal increment / isolation handling
        if any(ip_of_remote_address(p['network']['remoteAddress']) == self.attacker_ip for p in peers) and len(peers) == 1:
            for p in peers:
                if ip_of_remote_address(p['network']['remoteAddress']) == self.attacker_ip:
                    pid = p.get('id')
                    newv = max(conf["TRUST_FLOOR"], n.trust.get(pid, conf["TRUST_INIT"]) - conf["TRUST_DEC"])
                    n.trust[pid] = blend(newv, self.attacker_ip)
                    # raise on-chain alert (isolation sign)
                    self.global_layer.post_alert("isolation", ip, self.attacker_ip, {"only_peer":"attacker"})
        elif len(peers) >= max(1, conf["TARGET_MIN_PEERS"] - 1):
            for p in peers:
                pid = p.get('id'); pip = ip_of_remote_address(p['network']['remoteAddress'])
                newv = min(conf["TRUST_CEIL"], n.trust.get(pid, conf["TRUST_INIT"]) + conf["TRUST_INC"])
                n.trust[pid] = blend(newv, pip)

        # PATCH: event-driven decay applies only to the attacker when isolated or when
        # the transaction timeout ratio exceeds the adaptive threshold.  This avoids
        # penalising honest peers for global failures.  Only decrease trust for
        # the attacker peer when either (a) the node is fully isolated with the
        # attacker, or (b) the timeout ratio is high.  All other peers are left
        # untouched by the event penalty.
        for p in peers:
            pid = p.get('id')
            pip = ip_of_remote_address(p['network']['remoteAddress'])
            # Only penalise the attacker peer under isolation or high timeouts
            if pip == self.attacker_ip and ((len(peers) == 1) or (tx_timeout_ratio >= a_thr.get("TX_TIMEOUT_RATIO", 0.0))):
                n.trust[pid] = max(conf["TRUST_FLOOR"], n.trust.get(pid, conf["TRUST_INIT"]) - event_penalty)

        # Hysteresis on low-trust eviction.  For each peer we maintain a
        # per-peer counter of consecutive intervals during which its trust is
        # below the drop threshold.  Only when the counter reaches
        # ``LOW_TRUST_CONSEC_EVICT`` will we attempt to drop the peer.  This
        # prevents immediate eviction due to transient trust dips.
        # Clean up streak counters for peers that are no longer connected.
        current_ids = set()
        for p in peers:
            pid = p.get('id')
            if pid is not None:
                current_ids.add((ip, pid))
        # Remove stale entries for this node
        for key in list(self.low_trust_streak.keys()):
            node_ip, pid = key
            if node_ip == ip and (node_ip, pid) not in current_ids:
                self.low_trust_streak.pop(key, None)

        # Determine how many consecutive low-trust ticks are needed before eviction.
        consec_need = int(conf.get("LOW_TRUST_CONSEC_EVICT", 3))
        to_drop: List[Tuple[str, str]] = []  # list of (peer_ip, peer_id)
        for p in peers:
            pid = p.get('id')
            pip = ip_of_remote_address(p['network']['remoteAddress'])
            # skip missing ids
            if pid is None:
                continue
            # compute current trust value
            trv = n.trust.get(pid, conf["TRUST_INIT"])
            key = (ip, pid)
            if trv <= conf["TRUST_DROP_THRESHOLD"]:
                # increment streak
                self.low_trust_streak[key] += 1
                # mark for drop if streak threshold reached
                if self.low_trust_streak[key] >= consec_need:
                    to_drop.append((pip, pid))
            else:
                # reset streak if trust recovered
                self.low_trust_streak[key] = 0

        # Drop marked peers.  In adaptive mode we respect the token bucket
        # replacement cap when evicting low-trust peers to avoid excessive
        # churn.  Each drop is treated as a single replacement operation
        # requiring two tokens (drop + potential fill), consistent with shuffle.
        for pip, pid in to_drop:
            if not self._allow_replace(ip, need_ops=2):
                # cannot replace now; stop dropping more peers
                break
            if self.remove_peer_by_ip(ip, pip):
                # record drop event
                self.metrics["replacement_events"].append([time.time(), ip, "drop_low_trust", pip])
                # reset streak counter for the dropped peer so it restarts when re-added
                self.low_trust_streak.pop((ip, pid), None)

        # fill to target (avoid duplicates/attacker, obey global hints)
        peers = self.current_peers(ip)
        existing = {ip_of_remote_address(p['network']['remoteAddress']) for p in peers}
        # list candidate honest peers excluding self and attacker and those already connected
        candidates = [hip for hip in self.honest_ips if hip not in (ip, self.attacker_ip) and hip not in existing]
        # prefer higher hint peers
        candidates.sort(key=lambda x: self.global_layer.get_hint(x), reverse=True)
        while len(peers) < conf["TARGET_MIN_PEERS"] and candidates:
            hip = candidates.pop(0)
            enode = self.nodes[hip].enode
            if enode and self.add_peer(ip, enode):
                # record fill event
                self.metrics["replacement_events"].append([time.time(), ip, "add_fill", hip])
                # when adding an honest peer in adaptive mode, bump its trust slightly above
                # the drop threshold and reset its streak to make it "sticky".  We
                # identify the remote peer by its node_id; if unavailable, we
                # simply skip the trust bump.
                if self.mode == "adaptive":
                    remote_id = self.nodes[hip].node_id
                    if remote_id:
                        drop_thr = conf.get("TRUST_DROP_THRESHOLD", 0.5)
                        # promote trust to slightly above threshold so the peer isn't
                        # immediately evicted on the next trust-manager tick
                        self.nodes[ip].trust[remote_id] = max(
                            self.nodes[ip].trust.get(remote_id, conf.get("TRUST_INIT", 0.5)), drop_thr + 0.10
                        )
                        # reset streak counter for the newly added peer
                        self.low_trust_streak[(ip, remote_id)] = 0
                peers = self.current_peers(ip)
                existing.add(hip)

    # PATCH: token-bucket helper (adaptive replacement cap)
    def _allow_replace(self, ip: str, need_ops: int = 2) -> bool:
        cap = int(self.cfg["DEFENSE"].get("MAX_REPL_PER_MIN"))
        b = self.tokens[ip]
        now = time.monotonic()
        # refill at 'cap' tokens per 60s
        elapsed = now - b["t"]
        b["tokens"] = min(cap, b["tokens"] + (cap * elapsed / 60.0))
        b["t"] = now
        if b["tokens"] >= need_ops:
            b["tokens"] -= need_ops
            return True
        return False

    def _shuffle_step(self, ip: str, reason: str = "shuffle", replace_n: Optional[int] = None):
        """
        Perform a shuffle by dropping and reconnecting to peers.

        This helper no longer relies on the orchestrator's current mode to
        decide how many peers to replace. Callers should explicitly pass
        the desired number of peers to replace via ``replace_n``. When
        ``replace_n`` is ``None``, the function falls back to previous
        behaviour: one peer for fixed/random modes and two peers when the
        node has been stuck under eclipse for more than twice the
        ``STUCK_ECLIPSE_SEC`` threshold.

        Parameters
        ----------
        ip : str
            The IP address of the node performing the shuffle.
        reason : str
            A short label describing why the shuffle was invoked (used in
            metrics and alerts).
        replace_n : Optional[int]
            How many peers to drop and replace. If ``None``, the value
            depends on the orchestrator's mode and eclipse duration.
        """
        n = self.nodes[ip]
        conf = self.cfg["DEFENSE"]
        peers = self.current_peers(ip)
        if not peers:
            return

        # Determine how long we've been eclipsed (no honest peers).
        stuck_for = 0.0
        if ip in self.eclipse_since:
            stuck_for = time.time() - self.eclipse_since[ip]

        # Decide how many peers to replace.
        if replace_n is None:
            # default: one replacement; adaptive doubles when deeply eclipsed
            if self.mode in ("fixed", "random", "baseline"):
                replace_n_local = 1
            else:
                replace_n_local = 1
                if stuck_for >= 2 * float(conf.get("STUCK_ECLIPSE_SEC", 12)):
                    replace_n_local = 2
        else:
            replace_n_local = max(0, int(replace_n))

        # Prefer dropping attacker peers first; otherwise drop lowest-trust/hint peers
        attacker_peers = [p for p in peers if ip_of_remote_address(p["network"]["remoteAddress"]) == self.attacker_ip]
        if attacker_peers:
            to_drop = attacker_peers[: min(replace_n_local, len(attacker_peers))]
        else:
            # Sort by ascending trust then ascending global hint
            to_drop = sorted(
                peers,
                key=lambda p: (
                    n.trust.get(p.get("id"), conf["TRUST_INIT"]),
                    self.global_layer.get_hint(ip_of_remote_address(p["network"]["remoteAddress"]))
                ),
            )[: min(replace_n_local, len(peers))]

        # Drop selected peers
        for p in to_drop:
            pip = ip_of_remote_address(p["network"]["remoteAddress"])
            if self.remove_peer_by_ip(ip, pip):
                self.metrics["replacement_events"].append([time.time(), ip, f"{reason}_drop", pip])
                # Longer ban for attacker peers
                if pip == self.attacker_ip:
                    self.ban_until[pip] = time.time() + float(conf.get("BAN_COOLDOWN_ATTACKER_SEC", 45))
                    self.global_layer.post_alert("drop_attacker", ip, pip, {"reason": reason})
                else:
                    self.ban_until[pip] = time.time() + float(conf.get("BAN_COOLDOWN_SEC", 15))

        # Add new honest candidates. Avoid duplicates and the attacker.
        peers = self.current_peers(ip)
        existing = {ip_of_remote_address(p["network"]["remoteAddress"]) for p in peers}
        # Only honest candidates (excluding self and attacker)
        candidates = [hip for hip in self.honest_ips if hip not in (ip, self.attacker_ip) and hip not in existing]
        # Prefer peers with higher global hints
        candidates.sort(key=lambda x: self.global_layer.get_hint(x), reverse=True)
        # Attempt to add the same number of peers as we dropped
        for hip in candidates[: len(to_drop)]:
            enode = self.nodes[hip].enode
            if enode and self.add_peer(ip, enode):
                self.metrics["replacement_events"].append([time.time(), ip, f"{reason}_add", hip])
                # In adaptive mode, promote the connection to trusted
                if self.mode == "adaptive":
                    try:
                        json_rpc(ip, self.nodes[ip].cfg.http_port, "admin_addTrustedPeer", [enode])
                    except Exception:
                        pass

# --- TX-DEFCON helpers ---
    def _enter_tx_defcon(self, ip: str):
        if ip in self.defcon_nodes:
            return
        self.defcon_nodes.add(ip)
        try:
            self.stop_node(ip)
            self.start_node(ip, discovery=True)
            print(f"[DEFCON] Entered TX-DEFCON for {ip}")
            if hasattr(self, "global_layer"):
                self.global_layer.post_alert("tx_defcon_enter", ip, self.attacker_ip, {"mode": "enter"})
        except Exception as e:
            print(f"[DEFCON] enter failed {ip}: {e}")   

    def _exit_tx_defcon(self, ip: str):
        if ip not in self.defcon_nodes:
            return
        self.defcon_nodes.discard(ip)
        try:
            self.stop_node(ip)
            self.start_node(ip, discovery=True)
            print(f"[DEFCON] Exited TX-DEFCON for {ip}")
            if hasattr(self, "global_layer"):
                self.global_layer.post_alert("tx_defcon_exit", ip, self.attacker_ip, {"mode": "exit"})
        except Exception as e:
            print(f"[DEFCON] exit failed {ip}: {e}")


    def _adaptive_monitor_loop(self, ip: str):
        conf = self.cfg["DEFENSE"]
        a_thr = conf["ADAPTIVE_THRESHOLDS"]
        cooldown_sec = float(conf.get("SHUFFLE_COOLDOWN_SEC"))

        # per-node debounce/hysteresis state
        s = self._adp_state.setdefault(ip, {"hi": 0, "lo": 0, "last_shuffle": 0.0})

        while not self.stop_event.is_set():
            time.sleep(conf["MANAGER_INTERVAL_SEC"])
            # snapshot
            honest_conn, attacker_conn, others, peers = self._classify_peers(ip)
            peer_ips = [ip_of_remote_address(p["network"]["remoteAddress"]) for p in peers]
            ent = entropy(peer_ips)
            peercount = len(peers)
            has_honest = len(honest_conn) > 0

            # tx timeout ratio
            win = max(1, int(conf.get("TX_WINDOW", 4)))
            
            tx_timeout_ratio = 0.0
            if getattr(self, "tx_delay_recent", None):
                vals = self.tx_delay_recent[-win:] or []
                if vals:
                    vs = sorted(vals)
                    idx = max(0, int(math.ceil(0.95*len(vs))) - 1)
                    p95 = vs[idx]
                    thresh = max(float(conf.get("TX_P95_SPIKE_MS", 50)), p95)
                    tx_timeout_ratio = sum(1 for v in vals if v > thresh) / max(1, len(vals))
            elif self.tx_recent:
                tx_timeout_ratio = (sum(self.tx_recent[-win:]) / min(len(self.tx_recent), win)) if self.tx_recent else 0.0

            # eclipse tracking
            if not has_honest:
                self.eclipse_since.setdefault(ip, time.time())
            else:
                self.eclipse_since.pop(ip, None)
            stuck_for = time.time() - self.eclipse_since.get(ip, time.time()) if not has_honest else 0

            # risk scoring + hysteresis
            lo_ent = a_thr.get("MIN_IP_ENTROPY", 1.2) - a_thr.get("ENTROPY_HYSTERESIS", 0.1)
            risk_entropy = (ent < a_thr.get("MIN_IP_ENTROPY", 1.2))
            risk_entropy_lo = (ent < lo_ent)
            risk_no_honest = (not has_honest)
            risk_low_peers = (peercount < int(conf.get("MIN_PEERCOUNT", 2)))
            risk_att_ratio = (len(attacker_conn) / max(1, peercount)) > float(conf.get("MAX_ATTACKER_RATIO", 0.4))
            risk_timeouts = (tx_timeout_ratio >= float(a_thr.get("TX_TIMEOUT_RATIO")))
            s.setdefault('flood_hi', 0); s.setdefault('flood_lo', 0)
            if risk_timeouts:
                s['flood_hi'] += 1; s['flood_lo'] = 0
            else:
                s['flood_lo'] += 1; s['flood_hi'] = 0
            hi_need = self.cfg.get('RISK_CONSEC_HI', 4)
            lo_need = self.cfg.get('RISK_CONSEC_LO', 2)
            if s['flood_hi'] >= hi_need and ip not in self.defcon_nodes:
                self._enter_tx_defcon(ip)
            if s['flood_lo'] >= lo_need and ip in self.defcon_nodes:
                self._exit_tx_defcon(ip)

            risk = (
              0.50 * int(risk_no_honest) +
              0.20 * int(risk_att_ratio) +
              0.15 * int(risk_timeouts) +
              0.10 * int(risk_entropy) +
              0.05 * int(risk_low_peers)
            )

            if risk >= 0.5:
                s["hi"] += 1; s["lo"] = 0
            else:
                s["lo"] += 1; s["hi"] = 0

            hi_need = int(a_thr.get("RISK_CONSEC_HI"))
            lo_need = int(a_thr.get("RISK_CONSEC_LO"))
            should_act = (s["hi"] >= hi_need)
            if s["lo"] >= lo_need:
                s["hi"] = 0

            now = time.monotonic()
            cool_ok = (now - s["last_shuffle"]) >= cooldown_sec

            trigger = None
            if risk_no_honest and stuck_for >= float(conf.get("STUCK_ECLIPSE_SEC", 12)):
                trigger = f"stuck_eclipse({int(stuck_for)}s)"
            elif risk_no_honest:
                trigger = "no_honest_peer"
            elif risk_att_ratio:
                trigger = f"attacker_ratio"
            elif risk_timeouts:
                trigger = f"tx_timeouts({tx_timeout_ratio:.2f})"
            elif risk_entropy:
                trigger = f"low_entropy({ent:.2f})"
            elif risk_low_peers:
                trigger = f"low_peercount({peercount})"

            if not (should_act and cool_ok and trigger):
                continue

            # raise on-chain alert for traceability
            self.global_layer.post_alert("adaptive_trigger", ip, self.attacker_ip,
                                         {"trigger": trigger, "entropy": ent, "peers": peercount})

            # add-first healing; only drop if still unhealthy
            if trigger.startswith("no_honest_peer") or trigger.startswith("stuck_eclipse"):
                self._force_recovery(ip, min_add=max(1, int(conf.get("MIN_HONEST_PEERS", 2))))
                h2, a2, _, peers2 = self._classify_peers(ip)
                if not h2 and conf.get("RECOVERY_HARD_RESET", True):
                    for p in list(peers2):
                        self.remove_peer_by_ip(ip, ip_of_remote_address(p["network"]["remoteAddress"]))
                    self.metrics["replacement_events"].append([time.time(), ip, "guard_full_reset", "all"])
                    self._force_recovery(ip, min_add=max(1, int(conf.get("MIN_HONEST_PEERS", 2))))
                s["last_shuffle"] = now
                self.last_adaptive_action[ip] = now
                continue
            else:
                need = max(0, int(conf.get("MIN_HONEST_PEERS", 2)) - len(honest_conn))
                if need > 0:
                    self._force_recovery(ip, min_add=need)
                    h2, _, _, _ = self._classify_peers(ip)
                    if len(h2) >= int(conf.get("MIN_HONEST_PEERS", 2)):
                        s["last_shuffle"] = now
                        self.last_adaptive_action[ip] = now
                        continue

            # token-bucket cap on replacements in ADAPTIVE
            if not self._allow_replace(ip, need_ops=2):
                continue

            ent_floor = float(a_thr.get("MIN_IP_ENTROPY", 1.2))
            ent_short = max(0.0, ent_floor - ent)
            attacker_ratio = len(attacker_conn) / max(1, len(peers))
            replace_n = 1
            if (not has_honest) or (stuck_for >= float(a_thr.get("STUCK_ECLIPSE_SEC", conf.get("STUCK_ECLIPSE_SEC", 20)))):
                replace_n = 2
            replace_n += int(math.ceil(ent_short / 0.3))
            if attacker_ratio >= float(a_thr.get("MAX_ATTACKER_RATIO", 0.4)):
                replace_n += 1
            replace_n = min(replace_n, 4)

            self._shuffle_step(ip, reason=f"adaptive:{trigger}", replace_n=replace_n)
            s["last_shuffle"] = now
            self.last_adaptive_action[ip] = now

    # ---------- connection guard (1s) ----------
    def _connection_guard_loop(self, ip: str):
        conf = self.cfg["DEFENSE"]
        min_honest = int(conf.get("MIN_HONEST_PEERS", 2))
        interval = float(conf.get("GUARD_INTERVAL_SEC"))
        while not self.stop_event.is_set():
            try:
                self._ban_sweep(ip)
                honest_conn, attacker_conn, others, peers = self._classify_peers(ip)
                # Drop "others" to avoid slot poisoning
                for op in list(others):
                    if self.remove_peer_by_ip(ip, op):
                        self.metrics["replacement_events"].append([time.time(), ip, "guard_drop_other", op])
                # Enforce honest baseline
                if len(honest_conn) < min_honest:
                    need = max(1, min_honest - len(honest_conn))
                    self._force_recovery(ip, min_add=need)
            except Exception as e:
                print(f"[Guard] {ip}: {e}")
            time.sleep(interval)

    # ---------- BLUE controllers ----------
    class MetricCollector:
        def __init__(self, orch, ip): self.orch, self.ip = orch, ip
        def tick(self, t: int): self.orch._record_metrics_tick(t)

    class TrustManagerCtrl:
        def __init__(self, orch, ip): self.orch, self.ip = orch, ip
        def run(self, stop_event, interval_sec: float):
            while not stop_event.is_set():
                try: self.orch._trust_manager_step(self.ip)
                except Exception as e: print(f"[TrustManager] {self.ip}: {e}")
                # align to monotonic cadence
                now = time.monotonic()
                k = math.floor((now - self.orch.start_mono) / interval_sec) + 1
                wake = self.orch.start_mono + k*interval_sec
                to = max(0.0, wake - time.monotonic())
                if stop_event.wait(timeout=to): break

    class MTDEnforcerCtrl:
        def __init__(self, orch, ip): self.orch, self.ip = orch, ip
        def shuffle_fixed(self):
            """
            For fixed mode we explicitly replace exactly one peer. Passing
            ``replace_n=1`` decouples the shuffle logic from the orchestrator's
            internal mode.
            """
            self.orch._shuffle_step(self.ip, reason="fixed", replace_n=1)

        def shuffle_random(self):
            """
            Random mode also performs a single replacement per shuffle
            invocation. The timing of invocations is still random but the
            amount of churn is fixed.
            """
            self.orch._shuffle_step(self.ip, reason="random", replace_n=1)

        def shuffle_adaptive(self, trig):
            """
            In adaptive mode we allow the shuffle helper to decide how many
            peers to replace based on eclipse duration. We do not override
            ``replace_n`` here so that the default behaviour kicks in.
            The ``trig`` string is appended to the reason for metrics.
            """
            self.orch._shuffle_step(self.ip, reason=f"adaptive:{trig}")

    class ConnectionGuardCtrl:
        def __init__(self, orch, ip): self.orch, self.ip = orch, ip
        def run(self, stop_event, interval_sec: float):
            while not stop_event.is_set():
                try:
                    self.orch._ban_sweep(self.ip)
                    honest_conn, attacker_conn, others, _ = self.orch._classify_peers(self.ip)
                    for op in list(others):
                        if self.orch.remove_peer_by_ip(self.ip, op):
                            self.orch.metrics["replacement_events"].append([time.time(), self.ip, "guard_drop_other", op])
                    min_honest = int(self.orch.cfg["DEFENSE"].get("MIN_HONEST_PEERS", 2))
                    if len(honest_conn) < min_honest:
                        self.orch._force_recovery(self.ip, min_add=max(1, min_honest - len(honest_conn)))
                except Exception as e:
                    print(f"[Guard] {self.ip}: {e}")
                # align to monotonic cadence
                now = time.monotonic()
                k = math.floor((now - self.orch.start_mono) / interval_sec) + 1
                wake = self.orch.start_mono + k*interval_sec
                to = max(0.0, wake - time.monotonic())
                if stop_event.wait(timeout=to): break

    class AnomalyDetectorCtrl:
        def __init__(self, orch, ip): self.orch, self.ip = orch, ip
        def run(self, stop_event, interval_sec: float):
            # delegate: adaptive loop already runs its own while
            self.orch._adaptive_monitor_loop(self.ip)

    # ---------- controller wiring ----------
    def _wire_controllers(self):
        self.controllers = {}
        for ip in self.honest_ips:
            self.controllers[ip] = {
                "metrics": GethOrchestrator.MetricCollector(self, ip),
                "trust": GethOrchestrator.TrustManagerCtrl(self, ip),
                "mtd": GethOrchestrator.MTDEnforcerCtrl(self, ip),
                "guard": GethOrchestrator.ConnectionGuardCtrl(self, ip),
                "anomaly": GethOrchestrator.AnomalyDetectorCtrl(self, ip),
            }

    # ---------- threads ----------
    def _start_trust_threads(self):
        threads = []; interval = self.cfg["DEFENSE"]["MANAGER_INTERVAL_SEC"]
        for ip in self.honest_ips:
            t = threading.Thread(target=self.controllers[ip]["trust"].run,
                                 args=(self.stop_event, interval), daemon=True)
            t.start(); threads.append(t)
        return threads

    def _start_shuffle_threads_fixed(self):
        conf = self.cfg["DEFENSE"]; threads=[]
        def loop(ip: str):
            first = True
            while not self.stop_event.is_set():
                T = float(conf.get("SHUFFLE_INTERVAL_SEC", 120))
                # Sleep until the next multiple of T from start_mono
                now = time.monotonic()
                k = math.floor((now - self.start_mono) / T) + 1
                wake = self.start_mono + k * T
                to = max(0.0, wake - time.monotonic())
                if self.stop_event.wait(timeout=to): break
                try: self.controllers[ip]["mtd"].shuffle_fixed()
                except Exception as e: print(f"[Shuffle/fixed] {ip}: {e}")
        for ip in self.honest_ips:
            t = threading.Thread(target=loop, args=(ip,), daemon=True); t.start(); threads.append(t)
        return threads

    def _start_shuffle_threads_random(self, duration_sec: int):
        """Random shuffler with delay constrained so first/any delay never exceeds half the run + global cap.
        Deterministic: per-node RNG derived from global seed; schedule anchored to self.start_mono.
        """
        conf = self.cfg["DEFENSE"]; threads=[]
        lo   = float(conf.get("SHUFFLE_MIN_SEC", 10))
        hi   = float(conf.get("SHUFFLE_MAX_SEC", 60))
        cap  = float(conf.get("MAX_SHUFFLE_CAP_SEC", 180.0))
        half = max(1.0, float(duration_sec) / 2.0)

        def bounded_delay(rng):
            d = rng.uniform(lo, hi)
            return min(d, half, cap)

        def loop(ip: str):
            rng = self._rng_for(ip)
            offset = bounded_delay(rng)  # first firing
            while not self.stop_event.is_set():
                wake = self.start_mono + offset
                to = max(0.0, wake - time.monotonic())
                if self.stop_event.wait(timeout=to):
                    break
                try:
                    self._shuffle_step(ip, reason="random")
                except Exception as e:
                    print(f"[Shuffle/random] {ip}: {e}")
                offset += bounded_delay(rng)

        for ip in self.honest_ips:
            t = threading.Thread(target=loop, args=(ip,), daemon=True); t.start(); threads.append(t)
        return threads


    def _start_adaptive_threads(self):
        threads=[]; interval = self.cfg["DEFENSE"]["MANAGER_INTERVAL_SEC"]
        for ip in self.honest_ips:
            t = threading.Thread(target=self.controllers[ip]["anomaly"].run,
                                 args=(self.stop_event, interval), daemon=True)
            t.start(); threads.append(t)
        return threads

    def _start_guard_threads(self):
        if self.mode != "adaptive":
            return
        threads=[]; interval = float(self.cfg["DEFENSE"].get("GUARD_INTERVAL_SEC"))
        for ip in self.honest_ips:
            t = threading.Thread(target=self.controllers[ip]["guard"].run,
                                 args=(self.stop_event, interval), daemon=True)
            t.start(); threads.append(t)
        return threads

    def _start_port_hop_threads(self, randomize: bool=False):
        conf = self.cfg['DEFENSE']; threads=[]
        def loop(ip: str):
            while not self.stop_event.is_set():
                delay = conf["PORT_HOP_INTERVAL_SEC"] if not randomize else self._rng_for(ip).uniform(conf["SHUFFLE_MIN_SEC"], conf["SHUFFLE_MAX_SEC"])
                # sleep aligned to base
                now = time.monotonic(); wake = now + delay
                to = max(0.0, wake - time.monotonic())
                if self.stop_event.wait(timeout=to): return
                try: self.restart_with_new_port(ip, delta=conf["PORT_HOP_DELTA"], discovery=True)
                except Exception as e: print(f"[PortHop] {ip}: {e}")
        for ip in self.honest_ips:
            t = threading.Thread(target=loop, args=(ip,), daemon=True); t.start(); threads.append(t)
        return threads

    def _start_global_threads(self):
        # green-box loops
        t1 = threading.Thread(target=self.global_layer.gossip_loop, daemon=True); t1.start()
        t2 = threading.Thread(target=self.global_layer.onchain_loop, daemon=True); t2.start()
        t3 = threading.Thread(target=self.global_layer.federated_loop, daemon=True); t3.start()
        return [t1,t2,t3]

    # ---------- runners ----------
    def _start_all(self, discovery_for: Dict[str,bool]):
        boot_ip = next(ip for ip, st in self.nodes.items() if st.cfg.role == "boot")
        self.start_node(boot_ip, discovery=discovery_for.get(boot_ip, True))
        boot_enode = self.nodes[boot_ip].enode

        import threading
        threads = []
        def _start(ip): self.start_node_with_boot(ip, discovery=discovery_for.get(ip, True), boot_enode=boot_enode)
        for ip in self.nodes:
            if ip == boot_ip: continue
            t = threading.Thread(target=_start, args=(ip,), daemon=True)
            t.start(); threads.append(t)
        for t in threads: t.join()
        self._warm_connect_parallel(fanout_per_node=6)

        for ip in self.nodes:
            for other in self.nodes:
                if other == ip: continue
                self.nodes[ip].known_enodes[other] = self.nodes[other].enode

    def _warm_connect_parallel(self, fanout_per_node: int = 6):
        import threading, time, random
        honest = [ip for ip in self.honest_ips if ip != self.attacker_ip]
        threads = []
        def _connect(src, dst):
            try:
                enode = self.nodes[dst].enode
                if not enode: return
                time.sleep(self._rng_for(src).uniform(0.02, 0.10))
                self.add_peer(src, enode)
            except Exception: pass
        for src in honest:
            fan = 0
            cands = [d for d in honest if d != src]
            self._rng_for(src).shuffle(cands)
            for dst in cands:
                t = threading.Thread(target=_connect, args=(src, dst), daemon=True)
                t.start(); threads.append(t)
                fan += 1
                if fan >= fanout_per_node: break
        for t in threads: t.join()

    def start_node_with_boot(self, ip: str, discovery=True, boot_enode: Optional[str]=None, logfile: Optional[str]=None):
            n = self.nodes[ip]
            n.ssh.connect()
            
            # --- ADD THESE LINES ---
            print(f"[{ip}] Wiping old datadir state...")
            # This removes the peer database and discovery cache
            n.ssh.exec(f"rm -rf {n.cfg.datadir}/geth/nodes; rm -f {n.cfg.datadir}/geth/peers.json; mkdir -p {n.cfg.datadir}")
            # -----------------------

            # n.ssh.exec(f"mkdir -p {n.cfg.datadir}")
            logpath = logfile or f"{n.cfg.datadir}/geth_run.log"

            retries = int(self.cfg.get("START_RETRIES", 3))
            backoff = float(self.cfg.get("RETRY_BACKOFF_SEC", 3))
            port_to = int(self.cfg.get("PORT_READY_TIMEOUT", 20))
            rpc_to  = int(self.cfg.get("RPC_READY_TIMEOUT", 30))
            last_err = None

            for attempt in range(1, retries+1):
                cmd = (
                    f"nohup {self.geth} "
                    f"{self._common_flags(n, http=True, discovery=discovery, bootnodes=boot_enode)} "
                    f"> {logpath} 2>&1 & echo $!"
                )
                rc, out, err = n.ssh.exec(cmd)
                if rc != 0:
                    last_err = RuntimeError(f"start rc={rc}: {err.strip()}")
                else:
                    try:
                        self._wait_for_port(ip, n.cfg.http_port, port_to)
                        info = self._wait_for_rpc_ready(ip, n.cfg.http_port, rpc_to)
                        n.enode = info.get("enode"); n.node_id = info.get("id")
                        print(f"[{ip}] started ok: {n.enode}")
                        return
                    except Exception as e:
                        last_err = e
                try:
                    self.stop_node(ip)
                except Exception:
                    pass
                if attempt < retries:
                    sleep_for = backoff * attempt
                    print(f"[StartNode] {ip} attempt {attempt} failed: {last_err}. Retry in {sleep_for:.1f}s")
                    time.sleep(sleep_for)
            raise RuntimeError(f"Failed to start node {ip} after {retries} attempts: {last_err}")

    def _monitor_loop(self, duration_sec: int):
        start = self.start_mono; last_tick = start
        while (time.monotonic() - start) < duration_sec and not self.stop_event.is_set():
            t = int(time.monotonic() - start)
            try: self._record_metrics_tick(t)
            except Exception as e: print(f"[Monitor] tick error: {e}")
            sleep_left = 1 - (time.monotonic() - last_tick)
            if sleep_left > 0: time.sleep(sleep_left)
            last_tick = time.monotonic()

    def _write_csvs(self, prefix: str):
        tsdir = os.path.join(self.results_root, prefix)
        os.makedirs(tsdir, exist_ok=True)
        def write(name, header, rows):
            path = os.path.join(tsdir, name)
            with open(path, 'w', newline='') as f:
                w = csv.writer(f); w.writerow(header); w.writerows(rows)
            print(f"[Write] {path} ({len(rows)} rows)")
        write("peer_count.csv", ["t","node","peer_count"], self.metrics["peer_count"])
        write("ip_entropy.csv", ["t","node","ip_entropy"], self.metrics["ip_entropy"])
        write("trust_stats.csv", ["t","node","trust_mean","trust_std"], self.metrics["trust_stats"])
        write("dsr.csv", ["t","node","defended"], self.metrics["dsr"])
        write("replacement_events.csv", ["time","node","action","peer"], self.metrics["replacement_events"])
        write("churn.csv", ["time","node","added","removed"], self.metrics["churn"])
        write("tx_propagation.csv", ["send_time","txhash","source","dest","delay_ms","timeout","status"], self.metrics["tx_propagation"])
        exp_rows = [[ip, self.nodes[ip].malicious_exposure_seconds] for ip in self.honest_ips]
        write("malicious_exposure.csv", ["node","exposure_seconds"], exp_rows)
        if self.metrics.get("honest_counts"):
            write("honest_counts.csv", ["t","node","honest_count"], self.metrics["honest_counts"])
    # ---------- scenarios ----------
    def run_baseline(self, duration_sec: int):
        self.start_mono = time.monotonic()
        print("[Baseline] start")
        self.stop_event.clear(); self._reset_metrics(); self._wire_controllers()
        discover = {ip: (self.nodes[ip].cfg.role != 'honest') for ip in self.nodes}  # honest nodiscover
        self._start_all(discover)
        self.connect_all_to_attacker()
        self.disconnect_all_except_attacker()
        self._start_global_threads()
        self._start_attackers_if_enabled()
        if self.cfg.get("TX_TEST",{}).get("ENABLE"):
            threading.Thread(target=self._tx_propagation_loop, daemon=True).start()
        self._monitor_loop(duration_sec)
        self._write_csvs(prefix="baseline")
        self.stop_event.set()
        for ip in list(self.nodes.keys()): self.stop_node(ip)
        print("[Baseline] done")

    def run_fixed_safe(self, duration_sec: int):
        try:
            self.run_fixed(duration_sec)
        except Exception as e:
            print(f"[Fixed] Unexpected error during run: {e}")

    def run_fixed(self, duration_sec: int):
        self.start_mono = time.monotonic()
        print("[Fixed] start")
        self.mode = "fixed"
        CONFIG['DEFENSE']['TARGET_MIN_PEERS'] = 2
        self.stop_event.clear(); self._reset_metrics(); self._wire_controllers()
        
        # Start boot + others with discovery OFF for honest nodes
        # (discovery left ON for boot/attacker)
        # discover = {ip: (self.nodes[ip].cfg.role != 'honest') for ip in self.nodes}
        # self._start_all(discover)  # this seeds ~fanout=6 via _warm_connect_parallel

        for ip in self.nodes: self.start_node(ip, discovery=False)
        for ip in self.nodes:
            for other in self.nodes:
                if other != ip: self.nodes[ip].known_enodes[other] = self.nodes[other].enode

        # self.connect_honests_among_themselves()
        self.partial_connect_honests()
        self.connect_all_to_attacker()
        self.disconnect_all_except_attacker()
        st = time.time()
        self._start_global_threads()
        self._start_shuffle_threads_fixed()
        if self.cfg['DEFENSE'].get('ENABLE_PORT_HOP'): self._start_port_hop_threads()
        self._start_attackers_if_enabled()
        if self.cfg.get("TX_TEST",{}).get("ENABLE"):
            threading.Thread(target=self._tx_propagation_loop, daemon=True).start()
        self._monitor_loop(duration_sec)
        self._write_csvs(prefix="fixed")
        self.stop_event.set()
        # self.disconnect_all()
        for ip in list(self.nodes.keys()): self.stop_node(ip)
        print("[Fixed] run duration: {:.1f}s".format(time.time() - st))
        print("[Fixed] done")

    def run_random(self, duration_sec: int):
        self.start_mono = time.monotonic()
        print("[Random] start")
        self.mode = "random"
        CONFIG['DEFENSE']['TARGET_MIN_PEERS'] = 2
        self.stop_event.clear(); self._reset_metrics(); self._wire_controllers()
        for ip in self.nodes: self.start_node(ip, discovery=False)
        for ip in self.nodes:
            for other in self.nodes:
                if other != ip: self.nodes[ip].known_enodes[other] = self.nodes[other].enode
        # self.connect_honests_among_themselves()
        self.partial_connect_honests()
        self.connect_all_to_attacker()
        self.disconnect_all_except_attacker()
        st = time.time()
        self._start_global_threads()
        self._start_shuffle_threads_random(duration_sec)
        if self.cfg['DEFENSE'].get('ENABLE_PORT_HOP'): self._start_port_hop_threads(randomize=True)
        self._start_attackers_if_enabled()
        if self.cfg.get("TX_TEST",{}).get("ENABLE"):
            threading.Thread(target=self._tx_propagation_loop, daemon=True).start()
        self._monitor_loop(duration_sec)
        self._write_csvs(prefix="random")
        self.stop_event.set()
        # self.disconnect_all()
        for ip in list(self.nodes.keys()): self.stop_node(ip)
        print("[Random] run duration: {:.1f}s".format(time.time() - st))
        print("[Random] done")

    def run_adaptive(self, duration_sec: int):
        self.start_mono = time.monotonic()
        print("[Adaptive] start")
        self.mode = "adaptive"
        self.stop_event.clear(); self._reset_metrics(); self._wire_controllers()
        for ip in self.nodes: self.start_node(ip, discovery=False)
        for ip in self.nodes:
            for other in self.nodes:
                if other != ip:
                    self.nodes[ip].known_enodes[other] = self.nodes[other].enode

            print(f"[INIT] Node {ip} ready:")

            # Correct method name: eth_chainId
            cid_hex = json_rpc(ip, self.nodes[ip].cfg.http_port, "eth_chainId")
            chain_id = int(cid_hex, 16)
            print(f"  chainId: {chain_id}")

            latest = json_rpc(ip, self.nodes[ip].cfg.http_port, "eth_getBlockByNumber", ["latest", False]) or {}
            print(f"  latest.number: {latest.get('number')}  baseFeePerGas_present: {'baseFeePerGas' in latest}")

            ni = json_rpc(ip, self.nodes[ip].cfg.http_port, "admin_nodeInfo") or {}
            proto_eth = (ni.get("protocols") or {}).get("eth") or {}
            # If available, this often contains fork config (including chainId) on newer geth builds:
            cfg = proto_eth.get("config")
            print(f"  admin.protocols.eth.network: {proto_eth.get('network')}")
            print(f"  admin.protocols.eth.genesis: {proto_eth.get('genesis')}")
            if isinstance(cfg, dict):
                print(f"  admin.protocols.eth.config.chainId: {cfg.get('chainId')}")

        # self.connect_honests_among_themselves()
        self.partial_connect_honests()
        self.connect_all_to_attacker()
        self.disconnect_all_except_attacker()
        st = time.time()
        self._start_global_threads()

        # PATCH: Non-real-time mode skips adaptive/guard threads
        if not self.cfg['DEFENSE'].get('NON_REALTIME_MODE', False):
            # Trust manager + adaptive monitors only in adaptive
            self._start_trust_threads()
            self._start_adaptive_threads()
            if self.cfg['DEFENSE'].get('ENABLE_PORT_HOP'): self._start_port_hop_threads()
            # Connection guard is adaptive-only
            for hip in self.honest_ips:
                threading.Thread(target=self._connection_guard_loop, args=(hip,), daemon=True).start()

        self._start_attackers_if_enabled()
        if self.cfg.get("TX_TEST",{}).get("ENABLE"):
            threading.Thread(target=self._tx_propagation_loop, daemon=True).start()
        self._monitor_loop(duration_sec)
        self._write_csvs(prefix="adaptive")
        self.stop_event.set()
        # self.disconnect_all()
        for ip in list(self.nodes.keys()): self.stop_node(ip)
        print("[Adaptive] run duration: {:.1f}s".format(time.time() - st))
        print("[Adaptive] done")

    # ---------- attackers ----------
    
    def _attack_tx_flood_loop(self):
        atk = self.cfg.get("ATTACK", {})
        if not (atk.get("ENABLE") and atk.get("TX_FLOOD")): 
            return
        src_ip = atk.get("TX_FROM_NODE_IP")
        qps = int(atk.get("TX_FLOOD_QPS", 2))
        dur = int(atk.get("TX_FLOOD_DURATION_SEC", 60))
        deadline = time.time() + dur
        # Unlock the attacker's account if needed
        if atk.get("TX_FROM_ACCOUNT") is not None:
            try:
                json_rpc(src_ip, self.nodes[src_ip].cfg.http_port, "personal_unlockAccount",
                         [atk["TX_FROM_ACCOUNT"], atk.get("TX_FROM_PASSPHRASE",""), 600])
            except Exception:
                pass

        interval = 1.0/max(qps,1)
        while time.time() < deadline and not self.stop_event.is_set():
            # --- LGTDA Features: -----------------------
            # 1) Padded dust transaction with max data (~128 KB) to a contract address
            # 2) Gas price in Level B (1 gwei < price < baseFee) so tx is broadcast but not mined
            # -----------------------------------------
            # Build a 128 KB data payload (hex string of zeros)
            data_payload = "0x" + "0" * (128 * 1024 * 2)
            # Try to fetch current base fee to set gas price to ~90% of base fee
            try:
                block = json_rpc(src_ip, self.nodes[src_ip].cfg.http_port,
                                 "eth_getBlockByNumber", ["latest", False])
                base_fee = int(block.get("baseFeePerGas", "0x0"), 16)
                gas_price = int(base_fee * 0.9)
            except Exception:
                gas_price = 5_000_000_000
            if gas_price <= 1_000_000_000:
                gas_price = 2_000_000_000

            gas_limit = max(int(atk.get("TX_GAS", 21000)), 600000)

            tx = {
                "from": atk.get("TX_FROM_ACCOUNT"),
                "to": atk.get("TX_TO_ADDR"),
                "value": hex(int(atk.get("TX_VALUE_WEI", 0))),
                "gas": hex(gas_limit),
                "gasPrice": hex(gas_price),
                "data": data_payload
            }
            try:
                json_rpc(src_ip, self.nodes[src_ip].cfg.http_port,
                         "eth_sendTransaction", [tx])
            except Exception:
                pass
            time.sleep(interval)

    def _attack_conn_churn_loop(self):
        atk = self.cfg.get("ATTACK", {})
        if not (atk.get("ENABLE") and atk.get("CONN_CHURN")):
            return

        targets = atk.get("CHURN_TARGETS") #or list(self.honest_ips)
        ops_per_sec = float(atk.get("CHURN_OPS_PER_SEC", 0.5))
        duration_sec = int(atk.get("CHURN_DURATION_SEC", 120))
        k = int(atk.get("CHURN_K", 2))  # honest peers to drop per iteration
        attacker_enode = self.nodes[self.attacker_ip].enode

        deadline = time.time() + duration_sec
        while time.time() < deadline and not self.stop_event.is_set():
            for victim in targets:
                # snapshot honest peer list
                before = self._current_honest_peer_records(victim)
                if before:
                    # choose up to k honest peers to drop
                    to_drop = self._rng_for(victim).sample(before, min(k, len(before)))
                    for peer_ip, _ in to_drop:
                        self.remove_peer_hard(victim, peer_ip)

                # optionally re-add attacker to fill freed slots
                try:
                    if attacker_enode:
                        self.add_peer(victim, attacker_enode)
                except Exception as e:
                    print(f"[Attack] add_peer({victim}, attacker) failed: {e}")

                after = self._current_honest_peer_records(victim)
                print(f"[Attack] victim={victim} honest_before={len(before)} honest_after={len(after)}")

            if ops_per_sec > 0:
                time.sleep(1.0 / ops_per_sec)


    def _attack_rpc_hammer_loop(self):
        atk = self.cfg.get("ATTACK",{})
        if not (atk.get("ENABLE") and atk.get("RPC_HAMMER")): return
        methods = atk.get("RPC_METHODS",["net_peerCount"])
        qps = int(atk.get("RPC_QPS",10)); dur = int(atk.get("RPC_DURATION_SEC",30))
        deadline = time.time()+dur; ips = CONFIG.get('ATTACK',{}).get('RPC_TARGETS') or list(self.honest_ips)
        victims = [self.nodes[ip] for ip in ips]
        i=0; interval = 1.0/max(qps,1)
        while time.time() < deadline and not self.stop_event.is_set():
            n = victims[i % len(victims)]; m = methods[i % len(methods)]
            try: json_rpc(n.cfg.ip, n.cfg.http_port, m)
            except Exception: pass
            i += 1; time.sleep(interval)

    def _start_attackers_if_enabled(self):
        threads = []
        t1 = threading.Thread(target=self._attack_tx_flood_loop, daemon=True); t1.start(); threads.append(t1)
        t2 = threading.Thread(target=self._attack_conn_churn_loop, daemon=True); t2.start(); threads.append(t2)
        t3 = threading.Thread(target=self._attack_rpc_hammer_loop, daemon=True); t3.start(); threads.append(t3)
        if self.cfg.get("ATTACK",{}).get("ENABLE"):
            print("[Attack] simulators started")
        return threads


# ============================
# ========== ANALYZER ========
# ============================

def analyze(results_dir: str, strategies: List[str], dsr_scope: str = 'attacked'):
    # defaults (always defined)
    repl_per_min: float = 0.0
    mean_peer_count: float = 0.0
    ip_entropy_mean: float = 0.0
    mean_delay: float = float("nan")
    timeout_ratio: float = float("nan")
    exposure: float = 0.0
    trust_mean: float = 0.0
    if pd is None or plt is None:
        print("pandas/matplotlib not installed. `pip install pandas matplotlib`."); return
    rows = []
    # Determine victims scope per mode from attack_victims.csv when dsr_scope='attacked'
    all_honest = set([n["ip"] for n in CONFIG["NODES"] if n["role"] in ("honest","boot")])
    victims_by_mode = {}
    for strat in strategies:
        path = os.path.join(results_dir, strat)
        vic_path = os.path.join(path, "attack_victims.csv")
        if os.path.exists(vic_path):
            try:
                vips = []
                with open(vic_path) as vf:
                    next(vf, None)
                    for row in csv.reader(vf):
                        if row: vips.append(row[0])
                victims_by_mode[strat] = vips
            except Exception:
                victims_by_mode[strat] = []
        else:
            victims_by_mode[strat] = []

    for strat in strategies:
        path = os.path.join(results_dir, strat)
        if not os.path.isdir(path):
            continue
        # ---------- required ----------
        dsr_path = os.path.join(path, "dsr.csv")
        if not os.path.exists(dsr_path):
            continue
        dsr_df = pd.read_csv(dsr_path)
        # duration (seconds) from ticks
        if dsr_df.empty:
            duration_sec = 0
        else:
            tmin, tmax = dsr_df["t"].min(), dsr_df["t"].max()
            duration_sec = int(max(1, (tmax - tmin + 1)))
        # victims scope
        if dsr_scope == 'attacked' and victims_by_mode.get(strat):
            victims = set(victims_by_mode.get(strat, []))
        else:
            victims = set(all_honest)
        # per-node DSR
        dsr_sub = dsr_df[dsr_df["node"].isin(victims)]
        per_node = dsr_sub.groupby("node")["defended"].mean()
        dsr = float(per_node.mean() * 100.0) if not per_node.empty else 0.0
        asr = 100.0 - dsr
        # ---------- exposure ----------
        exposure = 0.0
        p = os.path.join(path, "malicious_exposure.csv")
        if os.path.exists(p):
            exdf = pd.read_csv(p)
            exposure = float(exdf["exposure_seconds"].mean()) if not exdf.empty else 0.0
        # ---------- trust mean ----------
        trust_mean = 0.0
        p = os.path.join(path, "trust_stats.csv")
        if os.path.exists(p):
            tdf = pd.read_csv(p)
            trust_mean = float(tdf["trust_mean"].mean()) if not tdf.empty else 0.0

        # ---------- replacements per min ----------
        repl_per_min = 0.0
        # replacements/min
        p = os.path.join(path, "replacement_events.csv")
        if os.path.exists(p):
            rcnt = len(pd.read_csv(p))
            repl_per_min = rcnt / (duration_sec / 60.0) if duration_sec > 0 else 0.0

        # ---------- mean_peer_count ----------
        mean_peer_count = 0.0
        p = os.path.join(path, "peer_count.csv")
        if os.path.exists(p):
            pcdf = pd.read_csv(p)
            mean_peer_count = float(pcdf["peer_count"].mean()) if not pcdf.empty else 0.0
        # ---------- ip entropy ----------
        ip_entropy_mean = 0.0
        p = os.path.join(path, "ip_entropy.csv")
        if os.path.exists(p):
            idf = pd.read_csv(p)
            ip_entropy_mean = float(idf["ip_entropy"].mean()) if not idf.empty else 0.0
        # ---------- tx propagation ----------
        mean_delay = float("nan"); timeout_ratio = float("nan")
        p = os.path.join(path, "tx_propagation.csv")
        if os.path.exists(p):
            txdf = pd.read_csv(p)
            if not txdf.empty:
                ok = txdf[txdf["delay_ms"] >= 0]
                mean_delay = float(ok["delay_ms"].mean()) if not ok.empty else float("nan")
                if "timeout" in txdf.columns:
                    timeout_ratio = float((txdf["timeout"] == 1).mean())


        rows.append({
            "strategy": strat,
            "avg_dsr": dsr,
            "avg_asr": asr,
            "replacements_per_min": repl_per_min,
            "mean_peer_count": mean_peer_count,
            "mean_ip_entropy": ip_entropy_mean,
            "mean_tx_delay_ms": mean_delay if not pd.isna(mean_delay) else 0.0,
            "tx_timeout_ratio": timeout_ratio if not pd.isna(timeout_ratio) else 0.0,
            "exposure_secs": exposure,
            "trust_mean": trust_mean,
            "duration_sec": duration_sec,
        })
    if not rows:
        print("No results found to analyze."); return
    df = pd.DataFrame(rows)
    out_csv = os.path.join(results_dir, "summary_report.csv")
    df.to_csv(out_csv, index=False)
    print(f"[Analyze] wrote {out_csv}")
    # ---------- bar: ASR/DSR ----------
    fig, ax = plt.subplots(figsize=(8,4))
    x = range(len(df))
    ax.bar([i-0.2 for i in x], df['avg_asr'], width=0.4, label='ASR')
    ax.bar([i+0.2 for i in x], df['avg_dsr'], width=0.4, label='DSR')
    ax.set_xticks(list(x)); ax.set_xticklabels(df['strategy'])
    ax.set_ylabel('%'); ax.set_title('Eclipse Attack Outcomes by Strategy')
    ax.legend()
    out_png = os.path.join(results_dir, "summary_plot.png")
    plt.tight_layout(); plt.savefig(out_png)
    print(f"[Analyze] wrote {out_png}")
    # ---------- scatter: Overhead vs DSR ----------
    fig2, ax2 = plt.subplots(figsize=(7,4))
    ax2.scatter(df['replacements_per_min'], df['avg_dsr'])
    for i, row in df.iterrows():
        ax2.annotate(row['strategy'], (row['replacements_per_min'], row['avg_dsr']), xytext=(5,5), textcoords='offset points')
    ax2.set_xlabel('Replacements per minute (overhead)')
    ax2.set_ylabel('DSR (%)')
    ax2.set_title('Defense Overhead vs DSR')
    out_png2 = os.path.join(results_dir, "overhead_vs_dsr.png")
    plt.tight_layout(); plt.savefig(out_png2)
    print(f"[Analyze] wrote {out_png2}")
    # ---- summary.csv (required schema) ----
    try:
        summary_rows = []
        for strat in df['strategy']:
            mode_path = os.path.join(results_dir, strat)
            # RPM computation
            rpm_mean = rpm_peak = 0.0
            try:
                ev = pd.read_csv(os.path.join(mode_path, 'replacement_events.csv'))
                if not ev.empty and 'time' in ev.columns and 'node' in ev.columns:
                    # per-node per-minute rates
                    ev['minute'] = (ev['time'] // 60).astype(int)
                    rpm = ev.groupby(['node','minute']).size().groupby('node').mean()
                    rpm_mean = float(rpm.mean()) if not rpm.empty else 0.0
                    rpm_peak = float(ev.groupby('minute').size().max()) if not ev.empty else 0.0
            except Exception:
                pass
            # DSR recompute with scope
            dpath = os.path.join(mode_path, 'dsr.csv')
            dsr_df2 = pd.read_csv(dpath) if os.path.exists(dpath) else pd.DataFrame()
            vics = victims_by_mode.get(strat, [])
            victims2 = set(vics) if (dsr_scope == 'attacked' and vics) else set(all_honest)
            per_node2 = dsr_df2[dsr_df2['node'].isin(victims2)].groupby('node')['defended'].mean()
            dsr_val = float(per_node2.mean() * 100.0) if not per_node2.empty else 0.0
            # 95% CI (normal approx)
            n_nodes = max(len(per_node2), 1)
            p = float(per_node2.mean()) if not per_node2.empty else 0.0
            se = math.sqrt(max(p*(1-p)/max(n_nodes,1), 0.0))
            ci_low = float(max(0.0, (p - 1.96*se) * 100.0))
            ci_high = float(min(100.0, (p + 1.96*se) * 100.0))
            summary_rows.append({
                "mode": strat,
                "nodes": int(len(all_honest)),
                "attackers": int(sum(1 for n in CONFIG["NODES"] if n.get("role")=='attacker')),
                "dsr": round(dsr_val, 3),
                "dsr_ci_low": round(ci_low, 3),
                "dsr_ci_high": round(ci_high, 3),
                "rpm_mean": round(rpm_mean, 3),
                "rpm_peak": round(rpm_peak, 3),
                "duration_s": int(rows[0].get("duration_sec", 0)),
                "dsr_scope": dsr_scope,
                "attack_victim_count": int(len(vics))
            })
        s_df = pd.DataFrame(summary_rows, columns=[
            "mode","nodes","attackers","dsr","dsr_ci_low","dsr_ci_high","rpm_mean","rpm_peak","duration_s","dsr_scope","attack_victim_count"
        ])
        s_out = os.path.join(results_dir, "summary.csv")
        s_df.to_csv(s_out, index=False)
        # pretty text
        with open(os.path.join(results_dir, "summary.txt"), "w") as sf:
            sf.write(s_df.to_string(index=False))
        print(f"[Analyze] wrote {s_out} and summary.txt")
    except Exception as e:
        print("[Analyze] summary.csv generation failed:", e)



# ============================
# ============ CLI ===========
# ============================
def main():
    ap = argparse.ArgumentParser(description="Eclipse defense validator with MTD strategies (Blue+Green)")
    ap.add_argument('--run', default='baseline,fixed,random,adaptive', help='Comma separated scenarios to run')
    ap.add_argument('--duration-baseline', type=int, default=240)
    ap.add_argument('--duration-fixed', type=int, default=240)
    ap.add_argument('--duration-random', type=int, default=240)
    ap.add_argument('--duration-adaptive', type=int, default=240)
    ap.add_argument('--results-dir', default=CONFIG['RESULTS_DIR'])
    ap.add_argument('--analyze', action='store_true')
    ap.add_argument('--strategies', default='baseline,fixed,random,adaptive')
    # PATCH: CLI toggle for non-real-time mode
    ap.add_argument('--non-realtime', action='store_true', help='Disable adaptive/guard threads; rely on scheduled shuffles & federated epochs')
    
    ap.add_argument('--duration', type=int, help='Duration (seconds) to apply per mode; overrides per-mode durations')
    ap.add_argument('--seed', type=int, default=0, help='Global seed for deterministic RNG')
    ap.add_argument('--hosts-file', default='hosts.txt', help='Hosts inventory file (one JSON object per line)')
    ap.add_argument('--attack-victim-list', default=None, help='Comma-separated IPs to target as victims')
    ap.add_argument('--attack-victim-count', type=int, default=None, help='Number of victims to select deterministically')
    ap.add_argument('--attack-eligible', choices=['honest','all'], default='honest', help='Eligible roles for victim selection')
    ap.add_argument('--dsr-scope', choices=['attacked','all'], default='attacked', help='DSR scope for aggregation')
    args = ap.parse_args()
    # Deterministic seed and inventory
    seed = int(args.seed)
    try:
        import numpy as _np
        _np.random.seed(seed)
    except Exception:
        pass

    # Load nodes deterministically from hosts file (preserve input order)
    try:
        CONFIG["NODES"] = nodes_from_file(args.hosts_file)
    except Exception as e:
        print(f"[FATAL] Failed to read hosts file {args.hosts_file}: {e}"); sys.exit(1)

    # Optional single --duration applies per mode
    if args.duration is not None:
        args.duration_baseline = args.duration_fixed = args.duration_random = args.duration_adaptive = int(args.duration)

    # Compute config hash (SHA256 of hosts file) for run fingerprinting
    try:
        with open(args.hosts_file, 'rb') as _hf:
            hosts_sha256 = hashlib.sha256(_hf.read()).hexdigest()
    except Exception as e:
        hosts_sha256 = None


    if args.analyze:
        analyze(args.results_dir, [s.strip() for s in args.strategies.split(',') if s.strip()], dsr_scope=args.dsr_scope)
        return

    CONFIG['RESULTS_DIR'] = args.results_dir
    if args.non_realtime:
        CONFIG['DEFENSE']['NON_REALTIME_MODE'] = True

    orch = GethOrchestrator(CONFIG)

    # Seed into orchestrator and global RNG
    orch.seed = seed
    orch.global_rng = random.Random(seed)
    orch.dsr_scope = args.dsr_scope
    orch.hosts_file = args.hosts_file
    orch.hosts_sha256 = hosts_sha256
    # Deterministic victim selection
    # Eligible set
    eligible_roles = ('honest',) if args.attack_eligible == 'honest' else ('honest','boot','bystander')
    eligible = [n['ip'] for n in CONFIG["NODES"] if (n.get('role') in eligible_roles)]
    eligible = sorted(eligible)
    victims = None
    if args.attack_victim_list:
        victims = [ip.strip() for ip in args.attack_victim_list.split(',') if ip.strip()]
        missing = [ip for ip in victims if ip not in eligible]
        if missing:
            print(f"[FATAL] attack-victim-list contains IPs not in eligible set: {missing}"); sys.exit(2)
        if args.attack_victim_count:
            print("[Warn] --attack-victim-list provided; --attack-victim-count ignored.")
    elif args.attack_victim_count:
        k = int(args.attack_victim_count)
        if k > len(eligible):
            print(f"[FATAL] --attack-victim-count {k} exceeds eligible population {len(eligible)}"); sys.exit(2)
        victims = orch.global_rng.sample(eligible, k)
    else:
        victims = []  # empty means no targeted victims
    orch.victim_ips = victims[:]

    # Apply victims to attack modules (churn/RPC hammer) deterministically
    CONFIG.setdefault("ATTACK", {}).setdefault("CONN_CHURN", True)
    CONFIG["ATTACK"]["CHURN_TARGETS"] = victims[:]
    CONFIG["ATTACK"]["RPC_TARGETS"] = victims[:] if victims else None

    # Persist frozen victim list (run root)
    os.makedirs(args.results_dir, exist_ok=True)
    root_victims_csv = os.path.join(args.results_dir, "attack_victims.csv")
    with open(root_victims_csv, 'w', newline='') as f:
        w = csv.writer(f); w.writerow(["ip","role"])
        role_by_ip = {n['ip']: n.get('role') for n in CONFIG["NODES"]}
        for ip in victims:
            w.writerow([ip, role_by_ip.get(ip)])
    print(f"[Init] Selected {len(victims)} attack victims; wrote {root_victims_csv}")
    


    
    for mode in [s.strip() for s in args.run.split(',') if s.strip()]:
        # Write per-mode config.json and attack_victims.csv
        mode_dir = os.path.join(args.results_dir, mode)
        os.makedirs(mode_dir, exist_ok=True)
        cfg_dump = {
            "seed": seed,
            "dsr_scope": args.dsr_scope,
            "hosts_file": args.hosts_file,
            "config_hash": hosts_sha256,
            "cli_args": vars(args),
            "victims": orch.victim_ips,
        }
        with open(os.path.join(mode_dir, "config.json"), "w") as _cf:
            json.dump(cfg_dump, _cf, indent=2, sort_keys=True)
        with open(os.path.join(mode_dir, "attack_victims.csv"), "w", newline='') as _vf:
            w = csv.writer(_vf); w.writerow(["ip","role"])
            role_by_ip = {n['ip']: n.get('role') for n in CONFIG["NODES"]}
            for ip in orch.victim_ips:
                w.writerow([ip, role_by_ip.get(ip)])
        if mode == 'baseline':
            orch.run_baseline(args.duration_baseline)
        elif mode == 'fixed':
            CONFIG['DEFENSE']['SHUFFLE_MODE'] = 'fixed'
            orch.run_fixed_safe(args.duration_fixed)
        elif mode == 'random':
            CONFIG['DEFENSE']['SHUFFLE_MODE'] = 'random'
            orch.run_random(args.duration_random)
        elif mode == 'adaptive':
            CONFIG['DEFENSE']['SHUFFLE_MODE'] = 'adaptive'
            orch.run_adaptive(args.duration_adaptive)
        else:
            print(f"Unknown run mode: {mode}")
    analyze(args.results_dir, [s.strip() for s in args.strategies.split(',') if s.strip()], dsr_scope=args.dsr_scope)
if __name__ == "__main__":
    main()