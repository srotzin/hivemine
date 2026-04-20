#!/usr/bin/env python3
"""
hivemine_agent.py — Python fallback prover agent for HiveMine.

This script simulates the Aleo CoinbasePuzzle prover loop using Python's
hashlib/SHA-256, giving a meaningful CPU throughput estimate. It also
implements the ZKWork pool TCP client (binary protocol) so it can connect
to the pool and send registration messages.

It is NOT a real ZK prover — it cannot produce valid ProverSolution proofs
accepted by the Aleo network. Use the Rust binary for real mining.
This is a diagnostic/benchmark tool only.

Usage:
    python3 hivemine_agent.py --benchmark
    python3 hivemine_agent.py --wallet aleo1... --pool aleo.hk.zk.work:10003

Requirements: Python 3.8+, no external dependencies (stdlib only)
"""

import argparse
import hashlib
import os
import socket
import struct
import sys
import threading
import time
from typing import Optional, Tuple

# ─── Constants ────────────────────────────────────────────────────────────────

BENCHMARK_WALLET = "zkworkdb96e3a638663eeab8cf56d96408d1fd72982f"
BENCHMARK_SECS = 60
DEFAULT_POOL = "aleo.hk.zk.work:10003"
AE1_NOMINAL_MHS = 300.0       # Ice River AE1 nominal hashrate
AE1_TDP_WATTS = 500           # Ice River AE1 TDP

# ZKWork protocol message types
MSG_CONNECT      = 128
MSG_SUBMIT       = 129
MSG_DISCONNECT   = 130
MSG_PING         = 131

MSG_CONNECT_ACK  = 0
MSG_NOTIFY_JOB   = 1
MSG_SHUTDOWN     = 2
MSG_PONG         = 3

# AE1 fingerprint: firmware version, worker_type (2=ASIC), address_type (0=mainnet)
FIRMWARE = (1, 5, 0)
WORKER_TYPE = 2
ADDRESS_TYPE = 0
ALEO_ADDRESS_LEN = 63


# ─── Simulated hash function (approximates the puzzle's inner loop) ──────────

def simulate_prove_attempt(address: bytes, epoch_hash: bytes, counter: int) -> int:
    """
    Simulate one CoinbasePuzzle proof attempt.

    The real puzzle computes:
        nonce = SHA256(SHA256(address || epoch_hash || counter))[-8:]  → u64
        target = u64::MAX / root_as_u64  (where root is a Merkle root)

    We approximate this with two SHA-256 rounds and extract a 64-bit value.
    This benchmarks the raw CPU throughput in the same ballpark as the inner
    loop of the Rust prover before ZK proof generation overhead.

    Returns: simulated proof_target (u64 equivalent)
    """
    data = address + epoch_hash + counter.to_bytes(8, 'little')
    h1 = hashlib.sha256(data).digest()
    h2 = hashlib.sha256(h1).digest()
    root_as_u64 = struct.unpack_from('<Q', h2, 0)[0]
    if root_as_u64 == 0:
        return (1 << 64) - 1
    return ((1 << 64) - 1) // root_as_u64


# ─── ZKWork Pool Client ───────────────────────────────────────────────────────

class PoolClient:
    """Minimal ZKWork binary TCP protocol client."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.worker_id: Optional[int] = None
        self.pool_address: Optional[str] = None

    def connect(self, timeout: float = 15.0) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self.sock.settimeout(120.0)

    def close(self) -> None:
        if self.sock:
            try:
                self._send_disconnect()
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass

    def _send_raw(self, data: bytes) -> None:
        self.sock.sendall(data)

    def _recv_exact(self, n: int) -> bytes:
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Pool closed connection")
            buf += chunk
        return buf

    def send_connect(self, worker_name: str, wallet_address: str) -> None:
        """
        ZKWork MSG_CONNECT (128):
        [128][worker_type:u8][address_type:u8][v_major:u8][v_minor:u8][v_patch:u8]
        [name_len:u16_le][name:bytes][address:63_bytes_zero_padded]

        ZKWork stratum convention:
          worker_name  = "<zkwork_wallet>.<worker_short>"  e.g. zkworkabc.ae2agent-1
          wallet_address = the zkwork wallet string — zero-padded to 63 bytes in
                           the binary address field (pool ignores content, assigns
                           its own pool_addr back in the ACK).
        """
        name_b = worker_name.encode('utf-8')
        # ZKWork binary protocol: address field is always 63 bytes.
        # Pad or truncate the wallet string to fit — pool uses the name field
        # for routing; the address slot is just a fixed-size field in the frame.
        addr_raw = wallet_address.encode('utf-8')
        if len(addr_raw) < ALEO_ADDRESS_LEN:
            addr_b = addr_raw + b'\x00' * (ALEO_ADDRESS_LEN - len(addr_raw))
        else:
            addr_b = addr_raw[:ALEO_ADDRESS_LEN]

        msg = bytes([
            MSG_CONNECT,
            WORKER_TYPE,
            ADDRESS_TYPE,
            FIRMWARE[0], FIRMWARE[1], FIRMWARE[2],
        ])
        msg += struct.pack('<H', len(name_b))
        msg += name_b
        msg += addr_b
        self._send_raw(msg)

    def recv_connect_ack(self) -> Tuple[bool, int]:
        """
        Message 0: [0][is_accept:u8][pool_addr:63][worker_id:u32_le][sig:64]
        Returns (accepted, worker_id)
        """
        msg_type = self._recv_exact(1)[0]
        if msg_type != MSG_CONNECT_ACK:
            raise RuntimeError(f"Expected connect_ack (0), got {msg_type}")
        is_accept = self._recv_exact(1)[0] != 0
        pool_addr_b = self._recv_exact(ALEO_ADDRESS_LEN)
        self.pool_address = pool_addr_b.decode('utf-8', errors='replace')
        worker_id_b = self._recv_exact(4)
        self.worker_id = struct.unpack_from('<I', worker_id_b)[0]
        _sig = self._recv_exact(64)  # ignored
        return is_accept, self.worker_id

    def recv_message(self) -> Optional[dict]:
        """
        Read the next server message. Returns dict with 'type' key,
        or None on pool shutdown.
        """
        while True:
            msg_type = self._recv_exact(1)[0]
            if msg_type == MSG_NOTIFY_JOB:
                job_id = struct.unpack_from('<I', self._recv_exact(4))[0]
                target = struct.unpack_from('<Q', self._recv_exact(8))[0]
                ec_len = struct.unpack_from('<I', self._recv_exact(4))[0]
                if ec_len > 1_048_576:
                    raise RuntimeError(f"EpochChallenge too large: {ec_len}")
                ec_bytes = self._recv_exact(ec_len)
                return {'type': 'job', 'job_id': job_id, 'target': target, 'epoch_challenge': ec_bytes}
            elif msg_type == MSG_PONG:
                continue
            elif msg_type == MSG_SHUTDOWN:
                return None
            else:
                print(f"[warn] Unknown message type from pool: {msg_type}", file=sys.stderr)
                continue

    def send_submit(self, job_id: int, solution_bytes: bytes) -> None:
        """
        Message 129: [129][worker_id:u32_le][job_id:u32_le][sol_len:u32_le][sol:bytes]
        """
        msg = bytes([MSG_SUBMIT])
        msg += struct.pack('<I', self.worker_id or 0)
        msg += struct.pack('<I', job_id)
        msg += struct.pack('<I', len(solution_bytes))
        msg += solution_bytes
        self._send_raw(msg)

    def send_ping(self) -> None:
        self._send_raw(bytes([MSG_PING]))

    def _send_disconnect(self) -> None:
        msg = bytes([MSG_DISCONNECT])
        msg += struct.pack('<I', self.worker_id or 0)
        self._send_raw(msg)

    def handshake(self, worker_name: str, wallet_address: str) -> Tuple[bool, int]:
        self.send_connect(worker_name, wallet_address)
        return self.recv_connect_ack()


# ─── Benchmark ────────────────────────────────────────────────────────────────

def run_benchmark(wallet: str, num_threads: int = 1) -> None:
    print(f"=== HiveMine Python Benchmark ===")
    print(f"Duration:  {BENCHMARK_SECS}s")
    print(f"Threads:   {num_threads}")
    print(f"Wallet:    {wallet}")
    print()
    print("Note: This is a SHA-256 simulation of the puzzle inner loop.")
    print("      The real Rust prover uses snarkVM CoinbasePuzzle::prove().")
    print()

    total_attempts = [0] * num_threads
    lock = threading.Lock()
    stop_event = threading.Event()

    address_b = wallet.encode('utf-8')
    epoch_hash = b'\x00' * 32  # Simulated epoch hash

    def worker(tid: int):
        counter = tid * (2**63 // num_threads)
        local_count = 0
        # Low target — accept anything to measure throughput
        min_target = 0
        start = time.monotonic()
        while not stop_event.is_set():
            simulate_prove_attempt(address_b, epoch_hash, counter)
            local_count += 1
            counter += 1
            if local_count % 10_000 == 0:
                total_attempts[tid] = local_count
        total_attempts[tid] = local_count

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(num_threads)]
    start = time.monotonic()
    for t in threads:
        t.start()

    # Progress reporter
    last_total = 0
    last_time = start
    for sec in range(0, BENCHMARK_SECS, 10):
        time.sleep(10)
        now = time.monotonic()
        total = sum(total_attempts)
        elapsed = now - start
        delta = total - last_total
        delta_t = now - last_time
        cur_mhs = (delta / 1_000_000) / delta_t if delta_t > 0 else 0
        cum_mhs = (total / 1_000_000) / elapsed if elapsed > 0 else 0
        print(f"[{elapsed:.0f}s] Current: {cur_mhs:.4f} MH/s | Cumulative: {cum_mhs:.4f} MH/s | Attempts: {total:,}")
        last_total = total
        last_time = now

    stop_event.set()
    for t in threads:
        t.join(timeout=2.0)

    elapsed = time.monotonic() - start
    total = sum(total_attempts)
    mhs_per_agent = (total / 1_000_000) / elapsed / num_threads
    total_mhs = (total / 1_000_000) / elapsed

    agents_needed = max(1, int(AE1_NOMINAL_MHS / mhs_per_agent + 0.999))
    aggregate = mhs_per_agent * agents_needed

    print()
    print("========== BENCHMARK RESULTS (Python Simulation) ==========")
    print(f"Hardware (simulated):    Ice River AE1 ({AE1_NOMINAL_MHS:.0f} MH/s nominal, {AE1_TDP_WATTS} W)")
    print(f"Duration:                {elapsed:.1f}s")
    print(f"Threads:                 {num_threads}")
    print(f"Total attempts:          {total:,}")
    print(f"MH/s per agent:          {mhs_per_agent:.6f}")
    print(f"Total MH/s:              {total_mhs:.6f}")
    print("-----------------------------------------------------------")
    print(f"Agents to match 1x AE1 ({AE1_NOMINAL_MHS:.0f} MH/s): {agents_needed:,}")
    print(f"Aggregate at {agents_needed:,}x agents: {aggregate:.4f} MH/s")
    print()
    print("NOTE: Python throughput << Rust. The Rust binary (after build)")
    print("will be orders of magnitude faster due to compiled snarkVM + ZK prover.")
    print("============================================================")

    # Save results
    report = (
        "# HiveMine Python Simulation Benchmark Results\n\n"
        f"**Hardware (simulated):** Ice River AE1 ({AE1_NOMINAL_MHS:.0f} MH/s nominal, {AE1_TDP_WATTS} W TDP)  \n"
        f"**Duration:** {elapsed:.1f}s  \n"
        f"**Threads:** {num_threads}  \n"
        f"**Total attempts:** {total:,}  \n"
        f"**MH/s per agent:** {mhs_per_agent:.6f}  \n"
        f"**Total MH/s:** {total_mhs:.6f}  \n\n"
        "## AE1 Equivalence\n"
        f"- Agents needed to match 1x AE1 ({AE1_NOMINAL_MHS:.0f} MH/s): **{agents_needed:,}**  \n"
        f"- Aggregate at {agents_needed:,} agents: **{aggregate:.4f} MH/s**  \n\n"
        "> **Note:** This Python simulation uses SHA-256 hashing, not the real snarkVM ZK prover.  \n"
        "> The Rust `hivemine` binary provides accurate results using `CoinbasePuzzle::prove()`.  \n"
    )
    out_path = os.path.join(os.path.dirname(__file__), "..", "hivemine-python-benchmark.md")
    with open(out_path, "w") as f:
        f.write(report)
    print(f"Results saved to {os.path.abspath(out_path)}")


# ─── Pool mining simulation ───────────────────────────────────────────────────

def run_mining(wallet: str, pool: str, worker_name: str, agent_id: int = 0) -> None:
    """
    Connect to ZKWork pool, register, receive jobs, simulate proving, submit solutions.
    Since this is Python, submitted solutions will NOT be cryptographically valid,
    but the pool protocol exchange is real.
    """
    host, port_str = pool.rsplit(':', 1)
    port = int(port_str)

    client = PoolClient(host, port)
    reconnect_delay = 5

    while True:
        try:
            print(f"[{worker_name}] Connecting to {pool}...")
            client.connect()
            accepted, wid = client.handshake(worker_name, wallet)
            if not accepted:
                print(f"[{worker_name}] Pool rejected registration")
                break
            print(f"[{worker_name}] Registered! worker_id={wid}, pool_addr={client.pool_address}")

            address_b = wallet.encode('utf-8')
            solutions = 0
            nonce = int.from_bytes(os.urandom(8), 'little')

            while True:
                msg = client.recv_message()
                if msg is None:
                    print(f"[{worker_name}] Pool shutdown")
                    return

                job_id = msg['job_id']
                target = msg['target']
                print(f"[{worker_name}] Job {job_id}: target={target}")

                epoch_b = msg['epoch_challenge']
                # Simulate proving: iterate nonces until simulated target met
                job_start = time.monotonic()
                attempts = 0
                found = False
                while time.monotonic() - job_start < 30:
                    sim_target = simulate_prove_attempt(address_b, epoch_b[:32].ljust(32, b'\x00'), nonce)
                    attempts += 1
                    nonce = (nonce + 1) & 0xFFFFFFFFFFFFFFFF
                    if sim_target >= target:
                        found = True
                        break

                mhs = (attempts / 1_000_000) / (time.monotonic() - job_start)
                if found:
                    # Build a dummy solution payload (not cryptographically valid)
                    dummy_solution = b'\x00' * 32 + nonce.to_bytes(8, 'little') + b'\x00' * 24
                    client.send_submit(job_id, dummy_solution)
                    solutions += 1
                    print(f"[{worker_name}] Submitted solution #{solutions}: attempts={attempts}, {mhs:.4f} MH/s")
                else:
                    print(f"[{worker_name}] No solution in 30s for job {job_id}, {mhs:.4f} MH/s")

        except Exception as e:
            print(f"[{worker_name}] Error: {e}. Reconnecting in {reconnect_delay}s...", file=sys.stderr)
            time.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 60)
            client = PoolClient(host, port)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HiveMine Python fallback prover agent (simulation only)"
    )
    parser.add_argument("--wallet", default=BENCHMARK_WALLET, help="Aleo wallet address")
    parser.add_argument("--worker", default="ae1-agent-0001", help="Worker name")
    parser.add_argument("--pool", default=DEFAULT_POOL, help="Pool host:port")
    parser.add_argument("--benchmark", action="store_true", help="Run 60s benchmark and exit")
    parser.add_argument("--agents", type=int, default=1, help="Number of parallel threads")
    parser.add_argument("--agent-id", type=int, default=0, help="Base agent ID")
    args = parser.parse_args()

    if args.benchmark:
        run_benchmark(args.wallet, args.agents)
    else:
        # Start multiple agent threads
        threads = []
        import random
        for i in range(args.agents):
            aid = args.agent_id + i
            # Build the full ZKWork stratum name: wallet.ae2agent-N
            # If --worker was passed as the full stratum string already, use it;
            # otherwise construct it from the wallet + sequential id.
            if '.' in args.worker:
                # Already a full stratum string (orchestrator passes this)
                base_worker = args.worker.rsplit('.', 1)[0]  # strip any existing suffix
                name = f"{base_worker}.ae2agent-{aid + 1}" if args.agents > 1 else args.worker
            else:
                name = f"{args.wallet}.ae2agent-{aid + 1}"
            t = threading.Thread(
                target=run_mining,
                args=(args.wallet, args.pool, name, aid),
                daemon=True,
                name=name,
            )
            # Stagger thread starts slightly — natural ramp, avoids TCP SYN burst
            time.sleep(random.uniform(0.5, 2.0))
            t.start()
            threads.append(t)
        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print("\nInterrupted. Exiting.")


if __name__ == "__main__":
    main()
