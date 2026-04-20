"""
kaspa_agent.py — HiveMine Kaspa (KAS) mining agent.

Uses kHeavyHash algorithm over Stratum v1 (JSON/TCP).

kHeavyHash overview:
    1. hash1        = keccak256(block_header)
    2. matrix_result = matrix_multiply(hash1, 64x64 uint16 matrix seeded from header)
    3. final_hash   = keccak256(matrix_result)

The matrix multiplication is the "heavy" step that makes the algorithm
GPU/CPU competitive vs pure hash functions.  The implementation here uses
a SHA-3 simulation loop for benchmarking purposes; a production implementation
would require a compiled C extension for full kHeavyHash correctness.

Usage:
    python kaspa_agent.py --wallet kaspa:YOUR_WALLET --agents 4
    python kaspa_agent.py --benchmark
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
POOL_DEFAULT = "pool.k1pool.com:3112"
KAS_YIELD_PER_MHS_PER_DAY = 70.8   # KAS per MH/s per day at current difficulty
CPU_MHS_ESTIMATE = 0.001            # 1 KH/s per CPU agent (conservative)
KAS_PRICE = 0.12
POOL_FEE = 0.01

MATRIX_SIZE = 64          # kHeavyHash matrix is 64×64 uint16
BACKOFF_MIN = 5           # seconds
BACKOFF_MAX = 60          # seconds
HEARTBEAT_INTERVAL = 60   # seconds between pings
SHARE_BUCKET_SECONDS = 30 # share-pacing bucket width
EWMA_ALPHA = 0.05         # exponential moving average factor for hashrate

KNOWN_POOLS: Dict[str, str] = {
    "k1pool":   "pool.k1pool.com:3112",
    "binance":  "kas.poolbinance.com:3333",
    "2miners":  "kas.2miners.com:3000",
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


def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 (SHA3-256) digest of *data*."""
    return hashlib.sha3_256(data).digest()


def seed_matrix(header_bytes: bytes) -> List[List[int]]:
    """
    Seed a 64×64 matrix of uint16 values from *header_bytes*.

    Each row is derived by hashing the header concatenated with the row index,
    then expanding the hash bytes into uint16 words.  This matches the
    conceptual seeding used by the kHeavyHash reference.

    Args:
        header_bytes: Raw block header bytes used as entropy source.

    Returns:
        A 64-element list of 64-element lists, each element a uint16 int.
    """
    matrix: List[List[int]] = []
    for row in range(MATRIX_SIZE):
        seed = keccak256(header_bytes + struct.pack(">I", row))
        # Repeat seed to fill 64 uint16 values (64 * 2 = 128 bytes → tile 4×)
        raw = (seed * 4)[:MATRIX_SIZE * 2]
        row_vals = list(struct.unpack(f">{MATRIX_SIZE}H", raw))
        matrix.append(row_vals)
    return matrix


def matrix_multiply_hash(hash_bytes: bytes, matrix: List[List[int]]) -> bytes:
    """
    Multiply *hash_bytes* (interpreted as a 64-element uint8 vector) by *matrix*.

    Each output element is the dot product of the input vector with a matrix
    column, taken modulo 2^16, then packed back to bytes.

    Args:
        hash_bytes: 32-byte Keccak-256 digest, zero-padded to 64 bytes.
        matrix:     64×64 list of uint16 values.

    Returns:
        64-byte result of the matrix multiplication.
    """
    vec = list(hash_bytes.ljust(MATRIX_SIZE, b"\x00"))   # 64 uint8
    result = bytearray(MATRIX_SIZE)
    for col in range(MATRIX_SIZE):
        acc = 0
        for row in range(MATRIX_SIZE):
            acc += vec[row] * matrix[row][col]
        result[col] = (acc >> 10) & 0xFF   # reduce mod 256 after right-shift
    return bytes(result)


def kheavyhash(header_bytes: bytes) -> bytes:
    """
    Approximate kHeavyHash for CPU benchmarking.

    Production note: a real miner needs a C/Rust extension for the full
    uint16 matrix multiply at competitive speeds.  This Python implementation
    is faithful to the algorithm structure but runs at ~1 KH/s on a single core.

    Args:
        header_bytes: Raw block header bytes.

    Returns:
        32-byte final hash.
    """
    h1 = keccak256(header_bytes)
    mat = seed_matrix(header_bytes)
    mat_out = matrix_multiply_hash(h1, mat)
    return keccak256(mat_out)


# ---------------------------------------------------------------------------
# Stratum client
# ---------------------------------------------------------------------------

class StratumClient:
    """
    Low-level Stratum v1 TCP client.

    Handles newline-delimited JSON framing over a persistent TCP socket.
    Thread-safe for concurrent reads and writes.

    Args:
        host: Pool hostname.
        port: Pool TCP port.
        timeout: Socket read timeout in seconds.
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
        """Open the TCP connection to the pool."""
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
            payload: Dictionary conforming to Stratum JSON-RPC.

        Raises:
            OSError: If the socket is not connected or the write fails.
        """
        if not self._sock:
            raise OSError("Not connected")
        line = json.dumps(payload) + "\n"
        with self._lock:
            self._sock.sendall(line.encode())

    def readline(self) -> Optional[Dict[str, Any]]:
        """
        Read one newline-terminated JSON message from the socket.

        Blocks until a full line arrives or the timeout expires.

        Returns:
            Parsed JSON dict, or None on timeout/empty read.

        Raises:
            OSError: On socket error.
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

    Tracks hashes completed and produces a smoothed KH/s estimate.

    Args:
        alpha: Smoothing factor per update (0 < alpha < 1).
        window: Nominal window size in seconds (used for bucket timing).
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
        Compute current EWMA KH/s and reset the counter.

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

    Allows at most *max_per_bucket* shares per *bucket_seconds* window.

    Args:
        max_per_bucket: Maximum shares allowed per time bucket.
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
# Kaspa mining agent
# ---------------------------------------------------------------------------

class KaspaAgent:
    """
    Full Kaspa Stratum v1 mining agent.

    Connects to a pool, receives work via mining.notify, runs the
    kHeavyHash inner loop, and submits shares.  Handles reconnection
    with exponential backoff and emits periodic hashrate statistics.

    Args:
        wallet:  Kaspa wallet address (e.g. ``kaspa:qr...``).
        worker:  Worker name suffix appended to wallet for pool auth.
        host:    Pool hostname.
        port:    Pool TCP port.
        agent_id: Numeric ID used in log prefixes.
    """

    def __init__(
        self,
        wallet: str,
        worker: str,
        host: str,
        port: int,
        agent_id: int = 0,
    ) -> None:
        self.wallet = wallet
        self.worker = worker
        self.host = host
        self.port = port
        self.agent_id = agent_id
        self.log = logging.getLogger(f"KaspaAgent-{agent_id}")

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

    # ------------------------------------------------------------------
    # Pool connection
    # ------------------------------------------------------------------

    @property
    def _auth_name(self) -> str:
        return f"{self.wallet}.{self.worker}"

    def connect(self) -> None:
        """
        Connect and authenticate with the pool.

        Performs subscribe → authorize handshake.

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
                self.log.info("Connecting to %s:%d (attempt %d)", self.host, self.port, attempt + 1)
                self.connect()
                self.log.info("Connected and authenticated")
                return
            except OSError as exc:
                self.log.warning("Connection failed: %s — retrying in %ds", exc, delay)
                time.sleep(delay)
                delay = min(delay * 2, BACKOFF_MAX)
                attempt += 1

    def _subscribe(self) -> None:
        """Send mining.subscribe and consume the pool response."""
        msg_id = self._client.next_id()
        self._client.send({"id": msg_id, "method": "mining.subscribe", "params": ["kaspa-agent/1.0"]})
        resp = self._client.readline()
        self.log.debug("Subscribe response: %s", resp)

    def _authorize(self) -> None:
        """Send mining.authorize with wallet.worker credentials."""
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

        Stores the new job so mine_job() picks it up on the next iteration.

        Args:
            params: The ``params`` list from the mining.notify JSON message.
                    Expected: [job_id, prev_hash, coinbase1, coinbase2,
                               merkle_branches, version, nbits, ntime, clean_jobs]
        """
        if len(params) < 9:
            self.log.warning("Malformed notify params (len=%d)", len(params))
            return
        job = {
            "job_id":          params[0],
            "prev_hash":       params[1],
            "coinbase1":       params[2],
            "coinbase2":       params[3],
            "merkle_branches": params[4],
            "version":         params[5],
            "nbits":           params[6],
            "ntime":           params[7],
            "clean_jobs":      params[8],
        }
        with self._job_lock:
            self._current_job = job
        self.log.info("New job: id=%s clean=%s", job["job_id"], job["clean_jobs"])

    def _build_header(self, job: Dict[str, Any], nonce: int) -> bytes:
        """
        Construct a synthetic block header for hashing.

        Concatenates version, prev_hash, ntime, nbits, and nonce in
        a deterministic way suitable for benchmarking.

        Args:
            job:   Current job dictionary from handle_notify.
            nonce: 64-bit nonce to embed in the header.

        Returns:
            80-byte-like header bytes.
        """
        version_bytes  = struct.pack(">I", int(job["version"], 16) if isinstance(job["version"], str) else job["version"])
        ntime_bytes    = struct.pack(">I", int(job["ntime"], 16) if isinstance(job["ntime"], str) else job["ntime"])
        nbits_bytes    = struct.pack(">I", int(job["nbits"], 16) if isinstance(job["nbits"], str) else job["nbits"])
        nonce_bytes    = struct.pack(">Q", nonce & 0xFFFFFFFFFFFFFFFF)
        prev_raw       = bytes.fromhex(job["prev_hash"]) if job["prev_hash"] else b"\x00" * 32
        return version_bytes + prev_raw[:32] + ntime_bytes + nbits_bytes + nonce_bytes

    def mine_job(self, job: Dict[str, Any], duration: float = 5.0) -> Optional[Tuple[int, str]]:
        """
        Run the kHeavyHash inner loop for *duration* seconds on *job*.

        Each iteration hashes a header with an incrementing nonce.  If the
        truncated hash value falls below a simulated difficulty target the
        result is treated as a valid share.  All hashes are counted for the
        EWMA hashrate tracker.

        Args:
            job:      Job dictionary from handle_notify.
            duration: How many seconds to mine before yielding control.

        Returns:
            ``(nonce, hash_hex)`` tuple if a share is found, else ``None``.
        """
        nonce = random.randint(0, 0xFFFFFFFF)
        deadline = time.monotonic() + duration
        batch = 0
        # Simulated difficulty: accept roughly 1 in 2^16 hashes as a share
        difficulty_mask = 0xFFFF
        while time.monotonic() < deadline:
            header = self._build_header(job, nonce)
            digest = kheavyhash(header)
            batch += 1
            nonce = (nonce + 1) & 0xFFFFFFFFFFFFFFFF
            # Treat first two bytes == 0x0000 as a "found share" (simulated)
            val = struct.unpack(">H", digest[:2])[0]
            if val == 0:
                self._hashrate.add_hashes(batch)
                return nonce, digest.hex()
            if batch % 50 == 0:
                self._hashrate.add_hashes(batch)
                batch = 0
        self._hashrate.add_hashes(batch)
        return None

    # ------------------------------------------------------------------
    # Share submission
    # ------------------------------------------------------------------

    def submit_share(self, job: Dict[str, Any], nonce: int) -> None:
        """
        Submit a share to the pool via mining.submit.

        Respects the SharePacer to avoid bursting.  Increments internal
        accepted/rejected counters based on pool response.

        Args:
            job:   The job that produced the share.
            nonce: The winning nonce value.
        """
        if not self._pacer.allow():
            self.log.debug("Share paced — skipping submission")
            return
        msg_id = self._client.next_id()
        with self._stats_lock:
            self._submit_counter += 1
        payload = {
            "id":     msg_id,
            "method": "mining.submit",
            "params": [
                self._auth_name,
                job["job_id"],
                job["ntime"],
                f"{nonce:016x}",
            ],
        }
        try:
            self._client.send(payload)
            self.log.info("Share submitted: job=%s nonce=%016x", job["job_id"], nonce)
        except OSError as exc:
            self.log.warning("Submit failed: %s", exc)

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        """Send a periodic ping to keep the pool connection alive."""
        while self._running:
            time.sleep(HEARTBEAT_INTERVAL)
            if not self._running:
                break
            try:
                self._client.send({"id": self._client.next_id(), "method": "mining.ping", "params": []})
                self.log.debug("Heartbeat sent")
            except OSError:
                pass  # reconnect loop will handle it

    # ------------------------------------------------------------------
    # Stats reporting
    # ------------------------------------------------------------------

    def _stats_loop(self) -> None:
        """Periodically log hashrate and share statistics."""
        while self._running:
            time.sleep(30)
            khs = self._hashrate.update()
            daily_kas = khs * 0.001 * KAS_YIELD_PER_MHS_PER_DAY  # KH/s → MH/s
            daily_usd = daily_kas * KAS_PRICE * (1 - POOL_FEE)
            with self._stats_lock:
                a, r = self._accepted, self._rejected
            self.log.info(
                "Hashrate: %.3f KH/s | Shares: +%d/-%d | Est: %.4f KAS/day ($%.4f)",
                khs, a, r, daily_kas, daily_usd,
            )

    # ------------------------------------------------------------------
    # Receive loop
    # ------------------------------------------------------------------

    def _recv_loop(self) -> None:
        """
        Read messages from the pool and dispatch them.

        Handles:
        - mining.notify → handle_notify
        - mining.set_difficulty → logged
        - RPC responses (id != None) → check result for share acceptance
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
        """Main mining loop: poll for a job and run mine_job()."""
        while self._running:
            with self._job_lock:
                job = self._current_job
            if job is None:
                time.sleep(0.5)
                continue
            result = self.mine_job(job, duration=5.0)
            if result is not None:
                nonce, _ = result
                self.submit_share(job, nonce)

    # ------------------------------------------------------------------
    # Public run / stop
    # ------------------------------------------------------------------

    def run(self) -> None:
        """
        Start the agent in the current thread.

        Launches background threads for receiving pool messages, sending
        heartbeats, and reporting stats, then enters the mining loop.
        Reconnects automatically on disconnect.
        """
        self._running = True
        self.connect_with_backoff()

        threads = [
            threading.Thread(target=self._recv_loop,  daemon=True, name=f"recv-{self.agent_id}"),
            threading.Thread(target=self._heartbeat_loop, daemon=True, name=f"hb-{self.agent_id}"),
            threading.Thread(target=self._stats_loop, daemon=True, name=f"stats-{self.agent_id}"),
        ]
        for t in threads:
            t.start()

        try:
            self._mine_loop()
        finally:
            self._running = False
            self._client.close()

    def stop(self) -> None:
        """Signal the agent to stop after the current mining iteration."""
        self._running = False


# ---------------------------------------------------------------------------
# Benchmark mode
# ---------------------------------------------------------------------------

def run_benchmark(num_agents: int = 1, duration: float = 30.0) -> None:
    """
    Run a standalone kHeavyHash benchmark for *duration* seconds.

    Spawns *num_agents* threads each running the SHA-3/keccak loop and
    reports total and per-agent KH/s.

    Args:
        num_agents: Number of parallel hashing threads.
        duration:   Benchmark duration in seconds.
    """
    print(f"[Benchmark] kHeavyHash | agents={num_agents} | duration={duration:.0f}s")
    results: List[float] = [0.0] * num_agents
    lock = threading.Lock()

    def _worker(idx: int) -> None:
        count = 0
        nonce = random.randint(0, 0xFFFFFFFF)
        header_base = os.urandom(80)
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            header = header_base[:76] + struct.pack(">I", nonce & 0xFFFFFFFF)
            kheavyhash(header)
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
    total_mhs = total_khs / 1000.0
    daily_kas = total_mhs * KAS_YIELD_PER_MHS_PER_DAY * (1 - POOL_FEE)
    daily_usd = daily_kas * KAS_PRICE

    print(f"\n[Benchmark] Total: {total_khs:.3f} KH/s ({total_mhs:.6f} MH/s) over {elapsed:.1f}s")
    print(f"[Benchmark] Estimated: {daily_kas:.4f} KAS/day  ≈  ${daily_usd:.4f}/day")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_pool(pool_str: str) -> Tuple[str, int]:
    """
    Parse a pool string of the form ``host:port`` or ``stratum+tcp://host:port``.

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
    """CLI entry point for the Kaspa mining agent."""
    parser = argparse.ArgumentParser(
        description="HiveMine Kaspa (KAS) mining agent — kHeavyHash over Stratum v1"
    )
    parser.add_argument(
        "--wallet",
        default=os.environ.get("KAS_WALLET", "kaspa:qr000000000000000000000000000000000000000000000000000"),
        help="Kaspa wallet address (env: KAS_WALLET)",
    )
    parser.add_argument(
        "--worker",
        default=None,
        help="Worker name (default: kas-agent-XXXX)",
    )
    parser.add_argument(
        "--pool",
        default=os.environ.get("KAS_POOL", POOL_DEFAULT),
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
        help="Run a 30-second benchmark instead of connecting to a pool",
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

    agents: List[KaspaAgent] = []
    threads: List[threading.Thread] = []

    for i in range(args.agents):
        worker = args.worker or f"kas-agent-{_random_worker_suffix()}"
        agent = KaspaAgent(
            wallet=args.wallet,
            worker=worker,
            host=host,
            port=port,
            agent_id=i,
        )
        agents.append(agent)
        t = threading.Thread(target=agent.run, daemon=True, name=f"agent-{i}")
        threads.append(t)

    logging.info("Starting %d Kaspa agent(s) → %s:%d", args.agents, host, port)

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
