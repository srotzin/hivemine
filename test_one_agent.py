#!/usr/bin/env python3
"""
test_one_agent.py — HiveMine single-agent ZKWork connection test.

Performs a handshake with the ZKWork Aleo pool, waits for the first job
dispatch, then disconnects cleanly. No mining runs. This is a connectivity
and authentication diagnostic only.

Usage:
    python3 test_one_agent.py

Requirements: Python 3.8+, no external dependencies (stdlib only)
"""

import socket
import struct
import sys
import time
from typing import Optional, Tuple

# ─── Config ───────────────────────────────────────────────────────────────────

POOL_HOST   = "aleo.asic.zk.work"
POOL_PORT   = 20002
WALLET      = "zkworkdb96e3a638663eeab8cf56d96408d1fd72982f"
WORKER_NAME = f"{WALLET}.ae2agent-1"

CONNECT_TIMEOUT_S = 15
ACK_TIMEOUT_S     = 20
JOB_TIMEOUT_S     = 20

# ZKWork binary protocol constants
MSG_CONNECT     = 128
MSG_DISCONNECT  = 130
MSG_CONNECT_ACK = 0
MSG_NOTIFY_JOB  = 1
MSG_PONG        = 3
MSG_SHUTDOWN    = 2

FIRMWARE      = (1, 5, 0)
WORKER_TYPE   = 2   # ASIC
ADDRESS_TYPE  = 0   # mainnet
ALEO_ADDR_LEN = 63

# ─── Protocol helpers ─────────────────────────────────────────────────────────

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Pool closed the connection unexpectedly")
        buf += chunk
    return buf


def _build_connect_frame(worker_name: str, wallet: str) -> bytes:
    name_b = worker_name.encode("utf-8")
    addr_raw = wallet.encode("utf-8")
    if len(addr_raw) < ALEO_ADDR_LEN:
        addr_b = addr_raw + b"\x00" * (ALEO_ADDR_LEN - len(addr_raw))
    else:
        addr_b = addr_raw[:ALEO_ADDR_LEN]

    frame  = bytes([MSG_CONNECT, WORKER_TYPE, ADDRESS_TYPE,
                    FIRMWARE[0], FIRMWARE[1], FIRMWARE[2]])
    frame += struct.pack("<H", len(name_b))
    frame += name_b
    frame += addr_b
    return frame


def _send_disconnect(sock: socket.socket, worker_id: int) -> None:
    msg = bytes([MSG_DISCONNECT]) + struct.pack("<I", worker_id)
    try:
        sock.sendall(msg)
    except Exception:
        pass


def _recv_connect_ack(sock: socket.socket) -> Tuple[bool, int, str]:
    """Returns (accepted, worker_id, pool_addr)."""
    msg_type = _recv_exact(sock, 1)[0]
    if msg_type != MSG_CONNECT_ACK:
        raise RuntimeError(f"Expected CONNECT_ACK (0), got {msg_type}")
    is_accept   = _recv_exact(sock, 1)[0] != 0
    pool_addr_b = _recv_exact(sock, ALEO_ADDR_LEN)
    pool_addr   = pool_addr_b.rstrip(b"\x00").decode("utf-8", errors="replace")
    worker_id   = struct.unpack_from("<I", _recv_exact(sock, 4))[0]
    _recv_exact(sock, 64)   # signature — ignored
    return is_accept, worker_id, pool_addr


def _recv_first_job(sock: socket.socket) -> Optional[dict]:
    """
    Wait for the pool to dispatch a job (MSG_NOTIFY_JOB = 1).
    Silently skips PONG frames. Returns job dict or None on shutdown.
    """
    while True:
        msg_type = _recv_exact(sock, 1)[0]
        if msg_type == MSG_NOTIFY_JOB:
            job_id   = struct.unpack_from("<I", _recv_exact(sock, 4))[0]
            target   = struct.unpack_from("<Q", _recv_exact(sock, 8))[0]
            ec_len   = struct.unpack_from("<I", _recv_exact(sock, 4))[0]
            if ec_len > 1_048_576:
                raise RuntimeError(f"EpochChallenge too large: {ec_len} bytes")
            ec_bytes = _recv_exact(sock, ec_len)
            return {"job_id": job_id, "target": target, "epoch_challenge": ec_bytes}
        elif msg_type == MSG_PONG:
            continue
        elif msg_type == MSG_SHUTDOWN:
            return None
        else:
            # Unknown message type — skip (pool may add new types)
            continue


# ─── Main test ────────────────────────────────────────────────────────────────

def main() -> int:
    """
    Returns 0 on success, 1 on failure.
    """
    print("=" * 60)
    print("  HiveMine — Single Agent ZKWork Connection Test")
    print("=" * 60)
    print(f"  Pool:    {POOL_HOST}:{POOL_PORT}  (ASIC stratum+tcp)")
    print(f"  Worker:  ae2agent-1")
    print(f"  Wallet:  {WALLET[:12]}...{WALLET[-4:]}")
    print()

    sock: Optional[socket.socket] = None
    worker_id = 0

    try:
        # Step 1 — TCP connect
        print(f"[1] Connecting to {POOL_HOST}:{POOL_PORT}...")
        t0 = time.monotonic()
        sock = socket.create_connection((POOL_HOST, POOL_PORT), timeout=CONNECT_TIMEOUT_S)
        tcp_ms = int((time.monotonic() - t0) * 1000)
        print(f"    TCP connected in {tcp_ms} ms")

        # Step 2 — Send CONNECT handshake
        print("[2] Sending CONNECT handshake...")
        frame = _build_connect_frame(WORKER_NAME, WALLET)
        sock.sendall(frame)
        print(f"  → CONNECT sent  worker='{WORKER_NAME}'  frame={len(frame)} bytes")

        # Step 3 — Wait for CONNECT_ACK
        print("[3] Waiting for CONNECT_ACK...")
        sock.settimeout(ACK_TIMEOUT_S)
        try:
            accepted, worker_id, pool_addr = _recv_connect_ack(sock)
        except socket.timeout:
            print(f"\n✗ TIMEOUT after {ACK_TIMEOUT_S}s — pool did not send CONNECT_ACK.")
            print("  Try again in 30 seconds (pool may be cold-starting).")
            return 1

        pool_addr_display = pool_addr if pool_addr.strip("\x00") else "(empty)"
        print()
        print("  ┌─ POOL RESPONSE ──────────────────────────────────┐")
        print(f"  │  accepted   : {accepted}")
        print(f"  │  worker_id  : {worker_id}")
        print(f"  │  pool_addr  : {pool_addr_display}")
        print("  └──────────────────────────────────────────────────┘")
        print()

        if not accepted:
            print("✗ REJECTED — pool did not accept this worker.")
            print("  Check wallet address and worker name format.")
            return 1

        print("✓ ACCEPTED — worker registered successfully!")

        # Step 4 — Wait for first job
        print("[4] Waiting for first job dispatch (up to 20s)...")
        sock.settimeout(JOB_TIMEOUT_S)
        try:
            job = _recv_first_job(sock)
        except socket.timeout:
            print(f"\n✗ TIMEOUT after {JOB_TIMEOUT_S}s — no job dispatched.")
            print("  Pool accepted us but sent no work. Try again shortly.")
            return 1

        if job is None:
            print("✗ Pool sent SHUTDOWN immediately after connect.")
            return 1

        ec_preview = job["epoch_challenge"][:8].hex()
        print(f"    Job received: job_id={job['job_id']}  target={job['target']}  "
              f"epoch_challenge={ec_preview}... ({len(job['epoch_challenge'])} bytes)")
        print()
        print("✓ FIRST JOB RECEIVED — pool is sending real work.")
        print("  Fleet is clear to launch.")

        # Step 5 — Clean disconnect
        print("[5] Sent DISCONNECT — exiting cleanly.")
        _send_disconnect(sock, worker_id)

    except ConnectionRefusedError:
        print(f"\n✗ CONNECTION REFUSED — port {POOL_PORT} is blocked on this network.")
        print("  Try from a different network (not corporate WiFi).")
        return 1
    except ConnectionResetError:
        print("\n✗ Connection reset by peer — pool rejected the handshake frame.")
        print("  Report full output to the AI for binary protocol debug.")
        return 1
    except OSError as e:
        print(f"\n✗ Network error: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        return 1
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    print()
    print("=" * 60)
    print("  Test complete — no mining ran, one clean registration.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
