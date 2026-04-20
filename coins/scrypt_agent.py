"""
scrypt_agent.py — HiveMine DOGE + LTC merged mining agent.

Uses Scrypt algorithm over Stratum v1 with AuxPOW for merged mining.

Merged mining overview:
    - One Scrypt computation satisfies both LTC and DOGE difficulty targets
      simultaneously.  The miner connects to ONE pool (LTC primary) which
      handles the DOGE AuxPOW bookkeeping automatically.
    - The pool pays out both LTC and DOGE to their respective wallet addresses.
    - From the miner's perspective, the protocol is identical to solo-LTC
      Stratum v1; the merge logic is entirely server-side.

Scrypt parameters (Litecoin / Dogecoin):
    N=1024, r=1, p=1  (the original Litecoin Scrypt parameters)

Python stdlib does not expose the Scrypt mining inner loop natively;
hashlib.scrypt is available in 3.6+ via OpenSSL but is too slow for
real mining.  This implementation uses a SHA-256 simulation loop for
benchmarking and structural demonstration; a production deployment needs
a compiled Scrypt extension (e.g. scrypt-jane or cpuminer-opt).

Usage:
    python scrypt_agent.py --ltc-wallet LTC_ADDR --doge-wallet DOGE_ADDR --agents 2
    python scrypt_agent.py --benchmark
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import socket
import string
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
POOL_DEFAULT = "ltc.viabtc.com:3333"
DOGE_PER_AGENT_PER_DAY = 12.0    # at CPU Scrypt ~50 KH/s
LTC_PER_AGENT_PER_DAY = 0.0035
DOGE_PRICE = 0.18
LTC_PRICE = 85.0
POOL_FEE = 0.01

# Litecoin Scrypt parameters
SCRYPT_N = 1024
SCRYPT_R = 1
SCRYPT_P = 1
SCRYPT_DKLEN = 32

BACKOFF_MIN = 5           # seconds
BACKOFF_MAX = 60          # seconds
HEARTBEAT_INTERVAL = 60   # seconds between pings
SHARE_BUCKET_SECONDS = 30 # share-pacing bucket width
EWMA_ALPHA = 0.05         # exponential moving average factor for hashrate

KNOWN_POOLS: Dict[str, str] = {
    "viabtc":  "ltc.viabtc.com:3333",
    "binance": "ltc.poolbinance.com:3333",
    "f2pool":  "ltc.f2pool.com:8888",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_worker_suffix(n: int = 4) -> str:
    """Return a random alphanumeric suffix of length *n*."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def scrypt_hash(data: bytes) -> bytes:
    """
    Compute Scrypt(data) with the Litecoin/Dogecoin parameters.

    Uses Python's ``hashlib.scrypt`` (OpenSSL backend, available Python 3.6+).
    For CPU benchmarking, falls back to a double-SHA-256 approximation if
    OpenSSL Scrypt is unavailable (e.g. restricted builds).

    Args:
        data: Input data to hash (typically 80-byte block header).

    Returns:
        32-byte Scrypt digest.
    """
    try:
        return hashlib.scrypt(
            password=data,
            salt=data,          # Litecoin uses the header as both password and salt
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
        )
    except (AttributeError, ValueError):
        # Fallback: double-SHA-256 loop approximating Scrypt cost
        h = hashlib.sha256(data).digest()
        for _ in range(SCRYPT_N):
            h = hashlib.sha256(h).digest()
        return h


def double_sha256(data: bytes) -> bytes:
    """Return SHA-256(SHA-256(*data*)) — the standard Bitcoin/Litecoin hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def merkle_root(branches: List[str], coinbase_hash: bytes) -> bytes:
    """
    Compute the Merkle root by iterating over pool-supplied branches.

    Args:
        branches:      List of hex-encoded Merkle branch hashes from the pool.
        coinbase_hash: Double-SHA-256 of the assembled coinbase transaction.

    Returns:
        32-byte Merkle root.
    """
    current = coinbase_hash
    for branch_hex in branches:
        branch = bytes.fromhex(branch_hex)
        current = double_sha256(current + branch)
    return current


# ---------------------------------------------------------------------------
# Stratum client
# ---------------------------------------------------------------------------

class StratumClient:
    """
    Low-level Stratum v1 TCP client.

    Handles newline-delimited JSON framing over a persistent TCP socket.
    Thread-safe for concurrent reads and writes.

    Args:
        host:    Pool hostname.
        port:    Pool TCP port.
        timeout: Socket read/connect timeout in seconds.
    """

    def __init__(self, host: str, port: int, timeout: float = 30.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._recv_buf = ""
        self._lock = threading.Lock()
        self._msg_id = 0

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open a TCP connection to the pool."""
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._recv_buf = ""

    def close(self) -> None:
        """Close the TCP socket gracefully."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def connected(self) -> bool:
        """True when the underlying socket is open."""
        return self._sock is not None

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    def next_id(self) -> int:
        """Atomically increment and return the next JSON-RPC message id."""
        with self._lock:
            self._msg_id += 1
            return self._msg_id

    def send(self, payload: Dict[str, Any]) -> None:
        """
        Serialise *payload* as JSON and write it to the socket.

        Args:
            payload: Dict conforming to Stratum JSON-RPC.

        Raises:
            OSError: If the socket is not connected or write fails.
        """
        if not self._sock:
            raise OSError("Not connected")
        line = json.dumps(payload) + "\n"
        with self._lock:
            self._sock.sendall(line.encode())

    def readline(self) -> Optional[Dict[str, Any]]:
        """
        Read one newline-terminated JSON message from the socket.

        Blocks until a full line arrives or the socket timeout expires.

        Returns:
            Parsed JSON dict, or None on timeout/empty read.

        Raises:
            OSError: On socket error or clean close by the remote side.
        """
        if not self._sock:
            return None
        while "\n" not in self._recv_buf:
            try:
                chunk = self._sock.recv(4096).decode(errors="replace")
            except socket.timeout:
                return None
            if not chunk:
                raise OSError("Connection closed by pool")
            self._recv_buf += chunk
        line, self._recv_buf = self._recv_buf.split("\n", 1)
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None


# ---------------------------------------------------------------------------
# EWMA hashrate tracker
# ---------------------------------------------------------------------------

class EWMAHashrate:
    """
    Exponential weighted moving average hashrate tracker.

    Accumulates completed hashes and emits a smoothed KH/s estimate
    each time update() is called.

    Args:
        alpha:  Smoothing factor per update (0 < alpha < 1).
        window: Nominal window in seconds (informational only).
    """

    def __init__(self, alpha: float = EWMA_ALPHA, window: float = 300.0) -> None:
        self.alpha = alpha
        self.window = window
        self._lock = threading.Lock()
        self._hashes: int = 0
        self._last_time: float = time.monotonic()
        self._ewma_khs: float = 0.0

    def add_hashes(self, count: int) -> None:
        """Record *count* additional hashes completed."""
        with self._lock:
            self._hashes += count

    def update(self) -> float:
        """
        Compute the current EWMA KH/s and reset the internal counter.

        Returns:
            Smoothed hashrate in KH/s.
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_time or 1e-9
            instant_khs = (self._hashes / elapsed) / 1000.0
            self._ewma_khs = (
                self.alpha * instant_khs + (1 - self.alpha) * self._ewma_khs
            )
            self._hashes = 0
            self._last_time = now
            return self._ewma_khs

    @property
    def khs(self) -> float:
        """Return the most recently computed EWMA KH/s without resetting."""
        return self._ewma_khs


# ---------------------------------------------------------------------------
# Share pacer
# ---------------------------------------------------------------------------

class SharePacer:
    """
    Rate-limits share submissions to prevent burst behaviour.

    Allows at most *max_per_bucket* shares per *bucket_seconds* sliding window.

    Args:
        max_per_bucket: Maximum shares allowed per bucket.
        bucket_seconds: Duration of each bucket in seconds.
    """

    def __init__(
        self, max_per_bucket: int = 4, bucket_seconds: float = SHARE_BUCKET_SECONDS
    ) -> None:
        self.max_per_bucket = max_per_bucket
        self.bucket_seconds = bucket_seconds
        self._lock = threading.Lock()
        self._bucket_start = time.monotonic()
        self._count = 0

    def allow(self) -> bool:
        """
        Return True if a share submission is permitted right now.

        Resets the counter when the current bucket expires.
        """
        with self._lock:
            now = time.monotonic()
            if now - self._bucket_start >= self.bucket_seconds:
                self._bucket_start = now
                self._count = 0
            if self._count < self.max_per_bucket:
                self._count += 1
                return True
            return False


# ---------------------------------------------------------------------------
# Scrypt mining agent (DOGE + LTC merged)
# ---------------------------------------------------------------------------

class ScryptAgent:
    """
    Full DOGE + LTC merged mining agent over Stratum v1.

    Connects to a merged-mining LTC pool (ViaBTC, Binance, or F2Pool),
    receives work via mining.notify, runs the Scrypt inner loop, and
    submits shares.  The pool automatically handles the DOGE AuxPOW and
    pays out both currencies.

    Pool authentication format (ViaBTC style)::

        username = "LTC_WALLET.WORKER/DOGE_WALLET"
        password = "x"

    Args:
        ltc_wallet:  Litecoin wallet address.
        doge_wallet: Dogecoin wallet address.
        worker:      Worker suffix (e.g. ``scrypt-agent-ab3f``).
        host:        Pool hostname.
        port:        Pool TCP port.
        agent_id:    Numeric ID used in log prefixes for multi-agent runs.
    """

    def __init__(
        self,
        ltc_wallet: str,
        doge_wallet: str,
        worker: str,
        host: str,
        port: int,
        agent_id: int = 0,
    ) -> None:
        self.ltc_wallet = ltc_wallet
        self.doge_wallet = doge_wallet
        self.worker = worker
        self.host = host
        self.port = port
        self.agent_id = agent_id
        self.log = logging.getLogger(f"ScryptAgent-{agent_id}")

        self._client = StratumClient(host, port)
        self._hashrate = EWMAHashrate()
        self._pacer = SharePacer()

        self._current_job: Optional[Dict[str, Any]] = None
        self._job_lock = threading.Lock()
        self._running = False

        self._submit_counter = 0
        self._accepted = 0
        self._rejected = 0
        self._stats_lock = threading.Lock()

        # Pool may send extranonce1 / extranonce2_size on subscribe
        self._extranonce1: str = "00000000"
        self._extranonce2_size: int = 4

    # ------------------------------------------------------------------
    # Pool auth string
    # ------------------------------------------------------------------

    @property
    def _auth_name(self) -> str:
        """Return pool authentication username in ViaBTC merged-mining format."""
        return f"{self.ltc_wallet}.{self.worker}/{self.doge_wallet}"

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """
        Connect and authenticate with the pool.

        Performs: TCP connect → mining.subscribe → mining.authorize.

        Raises:
            OSError: Propagated from StratumClient if TCP fails.
        """
        self._client.connect()
        self._subscribe()
        self._authorize()

    def connect_with_backoff(self) -> None:
        """
        Retry connect() with exponential backoff until successful.

        Delay sequence: 5 s → 10 s → 20 s → 40 s → 60 s (capped).
        """
        delay = BACKOFF_MIN
        attempt = 0
        while True:
            try:
                self.log.info(
                    "Connecting to %s:%d (attempt %d)", self.host, self.port, attempt + 1
                )
                self.connect()
                self.log.info("Connected and authenticated as %s", self._auth_name)
                return
            except OSError as exc:
                self.log.warning("Connection failed: %s — retrying in %ds", exc, delay)
                time.sleep(delay)
                delay = min(delay * 2, BACKOFF_MAX)
                attempt += 1

    def _subscribe(self) -> None:
        """
        Send mining.subscribe and parse the pool's extranonce response.

        The pool returns ``[session_id, extranonce1, extranonce2_size]``
        which are stored for coinbase assembly.
        """
        msg_id = self._client.next_id()
        self._client.send({
            "id": msg_id,
            "method": "mining.subscribe",
            "params": ["scrypt-agent/1.0"],
        })
        resp = self._client.readline()
        if resp and isinstance(resp.get("result"), list):
            result = resp["result"]
            # result[0] = [[sub_id, session_id], ...], result[1] = extranonce1, result[2] = size
            if len(result) >= 3:
                self._extranonce1 = result[1] or self._extranonce1
                self._extranonce2_size = int(result[2]) if result[2] else self._extranonce2_size
        self.log.debug(
            "Subscribe OK | extranonce1=%s size=%d", self._extranonce1, self._extranonce2_size
        )

    def _authorize(self) -> None:
        """Send mining.authorize with merged-mining credentials."""
        msg_id = self._client.next_id()
        self._client.send({
            "id": msg_id,
            "method": "mining.authorize",
            "params": [self._auth_name, "x"],
        })
        resp = self._client.readline()
        self.log.debug("Authorize response: %s", resp)

    # ------------------------------------------------------------------
    # Job handling
    # ------------------------------------------------------------------

    def handle_notify(self, params: List[Any]) -> None:
        """
        Process an incoming mining.notify message.

        Stores the new job for pickup by mine_job().  If clean_jobs is
        True any in-progress work should be abandoned.

        Args:
            params: The ``params`` list from mining.notify.
                    Expected layout: [job_id, prevhash, coinb1, coinb2,
                                      merkle_branch, version, nbits, ntime,
                                      clean_jobs]
        """
        if len(params) < 9:
            self.log.warning("Malformed notify params (len=%d)", len(params))
            return
        job: Dict[str, Any] = {
            "job_id":         params[0],
            "prevhash":       params[1],
            "coinb1":         params[2],
            "coinb2":         params[3],
            "merkle_branch":  params[4],
            "version":        params[5],
            "nbits":          params[6],
            "ntime":          params[7],
            "clean_jobs":     params[8],
        }
        with self._job_lock:
            self._current_job = job
        self.log.info("New job: id=%s clean=%s", job["job_id"], job["clean_jobs"])

    def _build_header(self, job: Dict[str, Any], extranonce2: bytes, nonce: int) -> bytes:
        """
        Assemble the 80-byte block header for Scrypt hashing.

        Layout (all little-endian per Bitcoin/Litecoin convention):
            4B version | 32B prevhash | 32B merkle_root | 4B ntime | 4B nbits | 4B nonce

        Args:
            job:          Current job dictionary.
            extranonce2:  Extra nonce 2 bytes for coinbase variation.
            nonce:        32-bit nonce to embed.

        Returns:
            80-byte header bytes.
        """
        # Assemble coinbase: coinb1 + extranonce1 + extranonce2 + coinb2
        coinbase_hex = (
            job["coinb1"]
            + self._extranonce1
            + extranonce2.hex()
            + job["coinb2"]
        )
        coinbase_bytes = bytes.fromhex(coinbase_hex)
        cb_hash = double_sha256(coinbase_bytes)

        # Merkle root
        branches: List[str] = job["merkle_branch"] if isinstance(job["merkle_branch"], list) else []
        mroot = merkle_root(branches, cb_hash)

        def _parse_int(val: Any) -> int:
            if isinstance(val, str):
                return int(val, 16)
            return int(val)

        version = _parse_int(job["version"])
        nbits   = _parse_int(job["nbits"])
        ntime   = _parse_int(job["ntime"])

        prevhash = bytes.fromhex(job["prevhash"]) if job["prevhash"] else b"\x00" * 32

        header = (
            struct.pack("<I", version)
            + prevhash[:32]
            + mroot[:32]
            + struct.pack("<I", ntime)
            + struct.pack("<I", nbits)
            + struct.pack("<I", nonce & 0xFFFFFFFF)
        )
        return header

    def mine_job(
        self, job: Dict[str, Any], duration: float = 5.0
    ) -> Optional[Tuple[int, bytes, bytes]]:
        """
        Run the Scrypt inner loop for *duration* seconds on *job*.

        Each iteration hashes an 80-byte header with an incrementing nonce.
        A share is detected when the first two bytes of the Scrypt digest
        are zero (simulated difficulty target).  All iterations are counted
        for the EWMA hashrate tracker.

        Args:
            job:      Current job dictionary.
            duration: Mining slice duration in seconds.

        Returns:
            ``(nonce, extranonce2, hash_bytes)`` if a share is found,
            else ``None``.
        """
        extranonce2 = os.urandom(self._extranonce2_size)
        nonce = random.randint(0, 0xFFFFFFFF)
        deadline = time.monotonic() + duration
        batch = 0

        while time.monotonic() < deadline:
            header = self._build_header(job, extranonce2, nonce)
            digest = scrypt_hash(header)
            batch += 1
            nonce = (nonce + 1) & 0xFFFFFFFF

            # Simulated share: first two bytes both zero
            if digest[0] == 0 and digest[1] == 0:
                self._hashrate.add_hashes(batch)
                return nonce, extranonce2, digest

            if batch % 20 == 0:
                self._hashrate.add_hashes(batch)
                batch = 0

        self._hashrate.add_hashes(batch)
        return None

    # ------------------------------------------------------------------
    # Share submission
    # ------------------------------------------------------------------

    def submit_share(
        self,
        job: Dict[str, Any],
        nonce: int,
        extranonce2: bytes,
    ) -> None:
        """
        Submit a share to the pool via mining.submit.

        Respects the SharePacer to prevent bursting.  Counts accepted
        and rejected shares for stats reporting.

        Args:
            job:          The job that produced the share.
            nonce:        Winning 32-bit nonce.
            extranonce2:  Extra nonce 2 bytes used when building the header.
        """
        if not self._pacer.allow():
            self.log.debug("Share paced — skipping submission")
            return
        msg_id = self._client.next_id()
        with self._stats_lock:
            self._submit_counter += 1

        ntime_str = job["ntime"] if isinstance(job["ntime"], str) else f"{job['ntime']:08x}"
        payload = {
            "id":     msg_id,
            "method": "mining.submit",
            "params": [
                self._auth_name,
                job["job_id"],
                extranonce2.hex(),
                ntime_str,
                f"{nonce:08x}",
            ],
        }
        try:
            self._client.send(payload)
            self.log.info(
                "Share submitted: job=%s nonce=%08x en2=%s",
                job["job_id"], nonce, extranonce2.hex(),
            )
        except OSError as exc:
            self.log.warning("Submit failed: %s", exc)

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        """Send a periodic ping to keep the TCP connection alive."""
        while self._running:
            time.sleep(HEARTBEAT_INTERVAL)
            if not self._running:
                break
            try:
                self._client.send({
                    "id": self._client.next_id(),
                    "method": "mining.ping",
                    "params": [],
                })
                self.log.debug("Heartbeat sent")
            except OSError:
                pass  # reconnect loop will handle the dropped connection

    # ------------------------------------------------------------------
    # Stats reporting
    # ------------------------------------------------------------------

    def _stats_loop(self) -> None:
        """Periodically log hashrate and estimated earnings for LTC and DOGE."""
        while self._running:
            time.sleep(30)
            khs = self._hashrate.update()
            # Scale estimated daily yield by hashrate relative to 50 KH/s baseline
            scale = khs / 50.0
            daily_doge = DOGE_PER_AGENT_PER_DAY * scale * (1 - POOL_FEE)
            daily_ltc  = LTC_PER_AGENT_PER_DAY  * scale * (1 - POOL_FEE)
            daily_usd  = daily_doge * DOGE_PRICE + daily_ltc * LTC_PRICE
            with self._stats_lock:
                a, r = self._accepted, self._rejected
            self.log.info(
                "Hashrate: %.2f KH/s | Shares: +%d/-%d | Est: %.2f DOGE + %.5f LTC/day ($%.4f)",
                khs, a, r, daily_doge, daily_ltc, daily_usd,
            )

    # ------------------------------------------------------------------
    # Receive loop
    # ------------------------------------------------------------------

    def _recv_loop(self) -> None:
        """
        Read messages from the pool and dispatch them.

        Handles:
        - mining.notify          → handle_notify()
        - mining.set_difficulty  → logged
        - RPC responses          → share accept/reject counting
        - Disconnect             → reconnect with backoff
        """
        while self._running:
            try:
                msg = self._client.readline()
            except OSError as exc:
                self.log.warning("Receive error: %s — reconnecting", exc)
                self._client.close()
                self.connect_with_backoff()
                continue
            if msg is None:
                continue
            method = msg.get("method")
            if method == "mining.notify":
                self.handle_notify(msg.get("params", []))
            elif method == "mining.set_difficulty":
                self.log.info("Difficulty update: %s", msg.get("params"))
            elif method == "mining.set_extranonce":
                params = msg.get("params", [])
                if len(params) >= 2:
                    self._extranonce1 = params[0]
                    self._extranonce2_size = int(params[1])
                    self.log.info(
                        "Extranonce update: en1=%s size=%d",
                        self._extranonce1, self._extranonce2_size,
                    )
            elif msg.get("id") is not None:
                result = msg.get("result")
                if result is True:
                    with self._stats_lock:
                        self._accepted += 1
                    self.log.info("Share accepted")
                elif result is False or "error" in msg:
                    with self._stats_lock:
                        self._rejected += 1
                    self.log.warning("Share rejected: %s", msg.get("error"))

    # ------------------------------------------------------------------
    # Mining loop
    # ------------------------------------------------------------------

    def _mine_loop(self) -> None:
        """Main mining loop: wait for a job, call mine_job(), submit on hit."""
        while self._running:
            with self._job_lock:
                job = self._current_job
            if job is None:
                time.sleep(0.5)
                continue
            result = self.mine_job(job, duration=5.0)
            if result is not None:
                nonce, extranonce2, _ = result
                self.submit_share(job, nonce, extranonce2)

    # ------------------------------------------------------------------
    # Public run / stop
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the agent in the current thread.

        Spawns background threads for pool message receive, heartbeat,
        and stats reporting, then enters the mining loop.  Reconnects
        automatically on any pool disconnect.
        """
        self._running = True
        self.connect_with_backoff()

        threads = [
            threading.Thread(target=self._recv_loop,      daemon=True, name=f"recv-{self.agent_id}"),
            threading.Thread(target=self._heartbeat_loop, daemon=True, name=f"hb-{self.agent_id}"),
            threading.Thread(target=self._stats_loop,     daemon=True, name=f"stats-{self.agent_id}"),
        ]
        for t in threads:
            t.start()

        try:
            self._mine_loop()
        finally:
            self._running = False
            self._client.close()

    def stop(self) -> None:
        """Signal the agent to stop after the current mining slice."""
        self._running = False


# ---------------------------------------------------------------------------
# Benchmark mode
# ---------------------------------------------------------------------------

def run_benchmark(num_agents: int = 1, duration: float = 30.0) -> None:
    """
    Run a standalone Scrypt benchmark for *duration* seconds.

    Spawns *num_agents* threads each performing the Scrypt hash loop
    (or SHA-256 fallback) and reports per-agent and total KH/s along
    with estimated daily earnings.

    Args:
        num_agents: Number of parallel hashing threads.
        duration:   Benchmark duration in seconds.
    """
    print(f"[Benchmark] Scrypt (LTC/DOGE merged) | agents={num_agents} | duration={duration:.0f}s")
    results: List[float] = [0.0] * num_agents
    lock = threading.Lock()

    def _worker(idx: int) -> None:
        count = 0
        header = os.urandom(80)
        nonce = random.randint(0, 0xFFFFFFFF)
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            # Vary 4 nonce bytes
            h = header[:76] + struct.pack("<I", nonce & 0xFFFFFFFF)
            scrypt_hash(h)
            nonce += 1
            count += 1
        khs = count / duration / 1000.0
        with lock:
            results[idx] = khs
        print(f"  Agent {idx}: {khs:.3f} KH/s")

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(num_agents)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t0

    total_khs = sum(results)
    scale = total_khs / 50.0          # relative to 50 KH/s baseline
    daily_doge = DOGE_PER_AGENT_PER_DAY * num_agents * scale * (1 - POOL_FEE)
    daily_ltc  = LTC_PER_AGENT_PER_DAY  * num_agents * scale * (1 - POOL_FEE)
    daily_usd  = daily_doge * DOGE_PRICE + daily_ltc * LTC_PRICE

    print(f"\n[Benchmark] Total: {total_khs:.3f} KH/s over {elapsed:.1f}s")
    print(f"[Benchmark] Estimated: {daily_doge:.2f} DOGE + {daily_ltc:.5f} LTC/day  ≈  ${daily_usd:.4f}/day")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_pool(pool_str: str) -> Tuple[str, int]:
    """
    Parse a pool string of the form ``host:port`` or ``stratum+tcp://host:port``.

    Also accepts shorthand aliases from KNOWN_POOLS.

    Args:
        pool_str: Raw pool string from CLI argument.

    Returns:
        ``(host, port)`` tuple.

    Raises:
        ValueError: If the string cannot be parsed.
    """
    pool_str = pool_str.replace("stratum+tcp://", "").replace("stratum+ssl://", "")
    if pool_str in KNOWN_POOLS:
        pool_str = KNOWN_POOLS[pool_str]
    host, _, port_str = pool_str.rpartition(":")
    if not host or not port_str.isdigit():
        raise ValueError(f"Cannot parse pool string: {pool_str!r}")
    return host, int(port_str)


def main() -> None:
    """CLI entry point for the DOGE + LTC merged Scrypt mining agent."""
    parser = argparse.ArgumentParser(
        description=(
            "HiveMine DOGE + LTC merged mining agent — Scrypt over Stratum v1\n"
            "Connects to an LTC pool that handles DOGE AuxPOW merged mining."
        )
    )
    parser.add_argument(
        "--ltc-wallet",
        default=os.environ.get("LTC_WALLET", "LTC_WALLET_PLACEHOLDER"),
        help="Litecoin wallet address (env: LTC_WALLET)",
    )
    parser.add_argument(
        "--doge-wallet",
        default=os.environ.get("DOGE_WALLET", "DOGE_WALLET_PLACEHOLDER"),
        help="Dogecoin wallet address (env: DOGE_WALLET)",
    )
    parser.add_argument(
        "--worker",
        default=None,
        help="Worker name (default: scrypt-agent-XXXX)",
    )
    parser.add_argument(
        "--pool",
        default=os.environ.get("SCRYPT_POOL", POOL_DEFAULT),
        help=f"Pool host:port or alias {list(KNOWN_POOLS)} (default: {POOL_DEFAULT})",
    )
    parser.add_argument(
        "--agents",
        type=int,
        default=1,
        help="Number of parallel mining agents (default: 1)",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run a 30-second Scrypt benchmark instead of connecting to a pool",
    )
    parser.add_argument(
        "--benchmark-duration",
        type=float,
        default=30.0,
        help="Benchmark duration in seconds (default: 30)",
    )
    args = parser.parse_args()

    if args.benchmark:
        run_benchmark(num_agents=args.agents, duration=args.benchmark_duration)
        return

    try:
        host, port = _parse_pool(args.pool)
    except ValueError as exc:
        parser.error(str(exc))
        return

    agents: List[ScryptAgent] = []
    threads: List[threading.Thread] = []

    for i in range(args.agents):
        worker = args.worker or f"scrypt-agent-{_random_worker_suffix()}"
        agent = ScryptAgent(
            ltc_wallet=args.ltc_wallet,
            doge_wallet=args.doge_wallet,
            worker=worker,
            host=host,
            port=port,
            agent_id=i,
        )
        agents.append(agent)
        t = threading.Thread(target=agent.run, daemon=True, name=f"agent-{i}")
        threads.append(t)

    logging.info(
        "Starting %d DOGE/LTC agent(s) → %s:%d",
        args.agents, host, port,
    )

    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Ctrl+C received — stopping agents")
        for a in agents:
            a.stop()
        for t in threads:
            t.join(timeout=5)
        logging.info("All agents stopped")


if __name__ == "__main__":
    main()
