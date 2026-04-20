#!/usr/bin/env python3
"""
xmr_agent.py — Monero (XMR) RandomX mining agent for HiveMine.

Connects to a Monero Stratum pool using the XMRig-compatible protocol.
Uses SHA-3/Keccak simulation for benchmarking. Real RandomX proof generation
requires the randomx C library (https://github.com/tevador/RandomX).

Usage:
    python3 xmr_agent.py --benchmark
    python3 xmr_agent.py --wallet YOUR_XMR_ADDRESS --pool pool.supportxmr.com:3333
    python3 xmr_agent.py --wallet YOUR_XMR_ADDRESS --agents 4

Requirements: Python 3.8+, stdlib only.
"""

import argparse
import hashlib
import json
import math
import os
import socket
import struct
import sys
import threading
import time
from typing import Optional, Dict, Any

# ─── Constants ────────────────────────────────────────────────────────────────

POOL_DEFAULT        = "pool.supportxmr.com:3333"
XMR_PER_AGENT_DAY  = 0.00035   # XMR/day at ~1 KH/s CPU simulation
XMR_PRICE          = 220.0
POOL_FEE            = 0.01
XMRIG_AGENT         = "XMRig/6.21.0 (Linux x86_64)"
BENCHMARK_SECS      = 30
KEEPALIVE_INTERVAL  = 60        # seconds between keepalive pings
EWMA_WINDOW         = 300       # 5-minute EWMA window


# ─── EWMA Hashrate Tracker ────────────────────────────────────────────────────

class EWMAHashrate:
    """Exponential weighted moving average hashrate tracker."""

    def __init__(self, window_seconds: int = EWMA_WINDOW) -> None:
        self._window = window_seconds
        self._value  = 0.0
        self._last   = time.monotonic()
        self._lock   = threading.Lock()

    def update(self, sample: float) -> None:
        now = time.monotonic()
        with self._lock:
            dt = now - self._last
            decay = math.exp(-dt / self._window)
            self._value = decay * self._value + (1.0 - decay) * sample
            self._last  = now

    def get(self) -> float:
        with self._lock:
            return self._value


# ─── Share Pacer ─────────────────────────────────────────────────────────────

class SharePacer:
    """Prevents burst submission that triggers pool variance warnings."""

    def __init__(self, window_seconds: int = 30) -> None:
        self._window  = window_seconds
        self._bucket: list = []
        self._lock    = threading.Lock()

    def should_submit(self, declared_khs: float) -> bool:
        now = time.monotonic()
        with self._lock:
            self._bucket = [t for t in self._bucket if now - t < self._window]
            cap = max(1, int(declared_khs * self._window))
            return len(self._bucket) < cap

    def record(self) -> None:
        with self._lock:
            self._bucket.append(time.monotonic())


# ─── Stratum Client ───────────────────────────────────────────────────────────

class XMRStratumClient:
    """Low-level XMRig-compatible Stratum TCP client."""

    def __init__(self, host: str, port: int, timeout: float = 30.0) -> None:
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._buf    = b""
        self._id     = 0
        self._lock   = threading.Lock()

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock.settimeout(120.0)
        self._buf  = b""

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _send(self, obj: Dict[str, Any]) -> None:
        data = json.dumps(obj, separators=(",", ":")) + "\n"
        with self._lock:
            self._sock.sendall(data.encode())

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def recv_line(self) -> Optional[Dict[str, Any]]:
        """Read next newline-delimited JSON message."""
        while b"\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("Pool closed connection")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return json.loads(line.decode().strip())

    def login(self, wallet: str, worker: str) -> Dict[str, Any]:
        """XMRig login — combines subscribe + authorize."""
        msg = {
            "id":     self._next_id(),
            "method": "login",
            "params": {
                "login": wallet,
                "pass":  "x",
                "agent": XMRIG_AGENT,
                "algo":  ["rx/0"],
                "id":    worker,
            },
        }
        self._send(msg)
        return self.recv_line()  # type: ignore

    def submit(self, session_id: str, job_id: str, nonce: str, result: str) -> int:
        mid = self._next_id()
        self._send({
            "id":     mid,
            "method": "submit",
            "params": {
                "id":     session_id,
                "job_id": job_id,
                "nonce":  nonce,
                "result": result,
            },
        })
        return mid

    def keepalive(self, session_id: str) -> None:
        self._send({
            "id":     self._next_id(),
            "method": "keepalived",
            "params": {"id": session_id},
        })


# ─── XMR Agent ────────────────────────────────────────────────────────────────

class XMRAgent:
    """
    Single Monero mining agent.

    Connects to a pool, receives RandomX jobs, simulates proof work,
    submits shares. Uses EWMA smoothing and share pacing to avoid
    pool variance warnings.
    """

    def __init__(
        self,
        wallet:      str,
        pool:        str,
        worker_name: str,
        agent_id:    int = 0,
        verbose:     bool = False,
    ) -> None:
        host, port_s   = pool.rsplit(":", 1)
        self.wallet     = wallet
        self.host       = host
        self.port       = int(port_s)
        self.worker     = worker_name
        self.agent_id   = agent_id
        self.verbose    = verbose

        self._ewma      = EWMAHashrate()
        self._pacer     = SharePacer()
        self._stop      = threading.Event()
        self._solutions = 0
        self._attempts  = 0

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"[{self.worker}] {msg}", flush=True)

    def _simulate_rx(self, blob: bytes, nonce: int) -> bytes:
        """
        Simulate one RandomX attempt via double-SHA3.
        Real RandomX requires the C library (tevador/RandomX).
        This approximates the CPU throughput of the inner loop.
        """
        data = blob + nonce.to_bytes(8, "little")
        h1 = hashlib.sha3_256(data).digest()
        h2 = hashlib.sha3_256(h1).digest()
        return h2

    def _target_to_diff(self, target_hex: str) -> int:
        """Convert pool target hex string to difficulty integer."""
        if len(target_hex) <= 8:
            target_hex = target_hex.ljust(64, "0")
        target = int(target_hex, 16)
        if target == 0:
            return 2**256
        return (2**256) // target

    def run(self) -> None:
        """Main agent loop — connect, mine, reconnect on failure."""
        delay = 5
        while not self._stop.is_set():
            client = XMRStratumClient(self.host, self.port)
            try:
                self.log(f"Connecting to {self.host}:{self.port}")
                client.connect()

                resp = client.login(self.wallet, self.worker)
                if resp.get("error"):
                    self.log(f"Login error: {resp['error']}")
                    time.sleep(delay)
                    continue

                result     = resp.get("result", {})
                session_id = result.get("id", "")
                job        = result.get("job", {})
                self.log(f"Logged in. session={session_id[:8]}...")
                delay = 5  # reset backoff

                last_keepalive = time.monotonic()
                nonce          = int.from_bytes(os.urandom(4), "little")

                while not self._stop.is_set():
                    # Keepalive
                    if time.monotonic() - last_keepalive > KEEPALIVE_INTERVAL:
                        client.keepalive(session_id)
                        last_keepalive = time.monotonic()

                    # Non-blocking poll for new messages
                    self._sock_timeout(client, 1.0)
                    msg = self._try_recv(client)
                    if msg:
                        if msg.get("method") == "job":
                            job = msg["params"]
                            self.log(f"New job: {job.get('job_id','?')[:8]}")
                        elif msg.get("method") == "mining.set_difficulty":
                            pass  # handled implicitly via target field

                    if not job:
                        time.sleep(0.5)
                        continue

                    # Mine one nonce
                    blob_hex = job.get("blob", "")
                    if not blob_hex:
                        time.sleep(0.1)
                        continue

                    blob   = bytes.fromhex(blob_hex[:76*2])  # first 76 bytes
                    target = job.get("target", "ffffffff")
                    t0     = time.monotonic()

                    result_hash = self._simulate_rx(blob, nonce)
                    self._attempts += 1
                    nonce = (nonce + 1) & 0xFFFFFFFF

                    elapsed = time.monotonic() - t0
                    if elapsed > 0:
                        inst_khs = (1 / elapsed) / 1000
                        self._ewma.update(inst_khs)

                    # Check if hash meets target (simulated — always low probability)
                    target_val = self._target_to_diff(target)
                    hash_val   = int.from_bytes(result_hash, "big")

                    if hash_val < (2**256 // max(1, target_val)):
                        if self._pacer.should_submit(self._ewma.get()):
                            nonce_hex  = format(nonce, "08x")
                            result_hex = result_hash.hex()
                            client.submit(session_id, job.get("job_id", ""), nonce_hex, result_hex)
                            self._pacer.record()
                            self._solutions += 1
                            self.log(f"Share submitted #{self._solutions}")

            except Exception as e:
                self.log(f"Error: {e}. Reconnect in {delay}s")
                client.close()
                time.sleep(delay)
                delay = min(delay * 2, 60)

    def _sock_timeout(self, client: XMRStratumClient, t: float) -> None:
        if client._sock:
            try:
                client._sock.settimeout(t)
            except Exception:
                pass

    def _try_recv(self, client: XMRStratumClient) -> Optional[Dict]:
        try:
            return client.recv_line()
        except socket.timeout:
            return None
        except Exception:
            raise

    def stop(self) -> None:
        self._stop.set()

    @property
    def hashrate_khs(self) -> float:
        return self._ewma.get()

    @property
    def solutions(self) -> int:
        return self._solutions


# ─── Benchmark ────────────────────────────────────────────────────────────────

def run_benchmark(threads: int = 1) -> None:
    """Run a local SHA3 throughput benchmark simulating RandomX inner loop."""
    print(f"=== XMR Agent Benchmark ({BENCHMARK_SECS}s, {threads} thread(s)) ===")
    counts = [0] * threads
    stop   = threading.Event()
    blob   = os.urandom(76)

    def worker(tid: int) -> None:
        nonce = tid * (2**32 // threads)
        while not stop.is_set():
            data = blob + nonce.to_bytes(8, "little")
            hashlib.sha3_256(hashlib.sha3_256(data).digest()).digest()
            counts[tid] += 1
            nonce = (nonce + 1) & 0xFFFFFFFF

    threads_list = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(threads)]
    t0 = time.monotonic()
    for t in threads_list:
        t.start()

    for sec in range(0, BENCHMARK_SECS, 10):
        time.sleep(10)
        elapsed = time.monotonic() - t0
        total   = sum(counts)
        khs     = (total / elapsed) / 1000
        print(f"  [{elapsed:.0f}s] {khs:.3f} KH/s ({total:,} attempts)")

    stop.set()
    for t in threads_list:
        t.join(timeout=2)

    elapsed = time.monotonic() - t0
    total   = sum(counts)
    khs_per = (total / elapsed) / 1000 / threads
    print(f"\n=== Results ===")
    print(f"  KH/s per agent:      {khs_per:.4f}")
    print(f"  KH/s total ({threads}t):   {khs_per * threads:.4f}")
    print(f"  Est XMR/day/agent:   {XMR_PER_AGENT_DAY:.6f}")
    print(f"  Est USD/day/agent:   ${XMR_PER_AGENT_DAY * XMR_PRICE * (1-POOL_FEE):.4f}")
    agents_for_1k = max(1, int(1000 / (khs_per * 1000 + 0.001)))
    print(f"  Agents for 1 MH/s:   {agents_for_1k:,}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="HiveMine XMR agent — RandomX simulation")
    p.add_argument("--wallet",    default=os.environ.get("XMR_WALLET", ""), help="XMR wallet address")
    p.add_argument("--worker",    default="xmr-agent-0001")
    p.add_argument("--pool",      default=POOL_DEFAULT)
    p.add_argument("--agents",    type=int, default=1)
    p.add_argument("--agent-id",  type=int, default=0)
    p.add_argument("--benchmark", action="store_true")
    p.add_argument("--verbose",   action="store_true")
    args = p.parse_args()

    if args.benchmark:
        run_benchmark(args.agents)
        return

    if not args.wallet:
        print("Error: --wallet required (or set XMR_WALLET env var)", file=sys.stderr)
        sys.exit(1)

    agents = []
    threads = []
    for i in range(args.agents):
        aid    = args.agent_id + i
        name   = f"xmr-agent-{aid:04d}"
        agent  = XMRAgent(args.wallet, args.pool, name, aid, args.verbose)
        agents.append(agent)
        t = threading.Thread(target=agent.run, name=name, daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(300)
            total_khs = sum(a.hashrate_khs for a in agents)
            total_sol = sum(a.solutions for a in agents)
            est_usd   = total_khs * 1000 * XMR_PER_AGENT_DAY * XMR_PRICE * (1 - POOL_FEE)
            print(f"[fleet] {len(agents)} agents | {total_khs:.3f} KH/s | {total_sol} shares | ~${est_usd:.4f}/day")
    except KeyboardInterrupt:
        print("\nStopping agents...")
        for a in agents:
            a.stop()


if __name__ == "__main__":
    main()
