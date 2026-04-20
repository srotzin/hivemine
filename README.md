# HiveMine — Aleo Prover Agent

Agent-based Aleo miner that wraps snarkVM's `Puzzle::prove()` and connects to the ZKWork pool. Each agent masquerades as an **Ice River AE1** ASIC miner (300 MH/s nominal, 500 W TDP).

## Architecture

```
hivemine
├── src/main.rs          — CLI, benchmark mode, pool mining loop
├── src/agent.rs         — AgentIdentity, AE1 fingerprint constants
├── src/pool_client.rs   — ZKWork binary TCP protocol (6block protocol)
├── hivemine_agent.py    — Python fallback (simulation only, no ZK proof)
└── build.sh             — One-shot build script
```

## Protocol Reference

ZKWork pool uses the [6block binary TCP protocol](https://github.com/6block/zkwork_aleo_protocol):

| Direction | Type | Message |
|-----------|------|---------|
| C → S | 128 | `connect`: `[worker_type][address_type][v_major][v_minor][v_patch][name_len:u16_le][name][address:63b]` |
| C → S | 129 | `submit`:  `[worker_id:u32_le][job_id:u32_le][sol_len:u32_le][solution]` |
| C → S | 130 | `disconnect`: `[worker_id:u32_le]` |
| C → S | 131 | `ping` |
| S → C | 0   | `connect_ack`: `[is_accept][pool_addr:63b][worker_id:u32_le][sig:64b]` |
| S → C | 1   | `notify_job`: `[job_id:u32_le][target:u64_le][epoch_len:u32_le][epoch_hash]` |
| S → C | 2   | `shutdown` |
| S → C | 3   | `pong` |

## AE1 Fingerprinting

Worker names follow the format `ae1-agent-NNNN` (zero-padded to 4 digits).
The connect message uses `worker_type = 2` (ASIC class) and firmware `v1.5.0`.

## Prerequisites

- Rust 1.75+ (install via `rustup`)
- ~500 MB disk for snarkVM parameters (cached after first run)
- Linux/macOS (Ubuntu 20.04+ recommended)

## Quick Start

### 1. Install & Build

```bash
git clone ... && cd hivemine
chmod +x build.sh && ./build.sh
```

Or manually:
```bash
source $HOME/.cargo/env
cargo build --release
```

### 2. Benchmark Mode

Run for 60 seconds and report MH/s:

```bash
./target/release/hivemine --benchmark
```

With 4 threads:
```bash
./target/release/hivemine --benchmark --agents 4
```

### 3. Pool Mining Mode

```bash
./target/release/hivemine \
  --wallet aleo1YOUR_WALLET_ADDRESS_HERE \
  --pool aleo.hk.zk.work:10003 \
  --worker ae1-agent-0001
```

Multiple parallel agents:
```bash
./target/release/hivemine \
  --wallet aleo1YOUR_WALLET_ADDRESS_HERE \
  --pool aleo.hk.zk.work:10003 \
  --agents 4
```

### 4. Multi-process Scaling

To run many agents across multiple processes:

```bash
# Process 0: agents 0-3
./target/release/hivemine --wallet aleo1... --pool aleo.hk.zk.work:10003 \
  --agents 4 --agent-id-base 0

# Process 1: agents 4-7
./target/release/hivemine --wallet aleo1... --pool aleo.hk.zk.work:10003 \
  --agents 4 --agent-id-base 4
```

### 5. Python Fallback (no Rust build required)

```bash
# Benchmark simulation
python3 hivemine_agent.py --benchmark --agents 2

# Pool connection simulation (sends real protocol bytes, but dummy solutions)
python3 hivemine_agent.py --wallet aleo1... --pool aleo.hk.zk.work:10003
```

> **Note:** The Python fallback uses SHA-256 to simulate the inner loop. It cannot produce cryptographically valid ZK proofs. Use the Rust binary for real mining.

## Pool Configuration

Steve's pool: `aleo.hk.zk.work:10003`

Other ZKWork endpoints:
- `aleo.asia1.zk.work:10003`
- `aleo.jp.zk.work:10003`
- `aleo.eu.zk.work:10003`

## snarkVM API

The prover uses the snarkVM 4.x `Puzzle` API:

```rust
use snarkvm_ledger_puzzle::Puzzle;
use snarkvm_ledger_puzzle_epoch::SynthesisPuzzle;
use snarkvm_circuit_network::AleoV0;
use snarkvm_console_network::MainnetV0 as Network;

let puzzle = Puzzle::<Network>::new::<SynthesisPuzzle<Network, AleoV0>>();

// prove(epoch_hash, address, counter, min_proof_target) -> Result<Solution<N>>
let solution = puzzle.prove(epoch_hash, address, counter, Some(min_target))?;
```

The pool sends `epoch_hash` (32-byte `N::BlockHash`) in `notify_job`. The prover iterates `counter` until a solution meets `target`.

## Performance Notes

| Build | Approx. time/attempt | Est. MH/s (2 vCPU) |
|-------|---------------------|---------------------|
| debug | ~4 s/attempt | ~0.00000025 MH/s |
| release (--release) | ~0.1–1 s/attempt | ~0.000001–0.00001 MH/s |

**CPU vs AE1:** The Ice River AE1 achieves 300 MH/s using dedicated ZK acceleration hardware. A 2 vCPU sandbox measures ~0.01–0.1 MH/s in optimized release mode (estimate), requiring **thousands of agents** to match a single AE1.

Run `--benchmark` with the release build to get exact numbers for your hardware.

## Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Rust workspace with snarkVM 4.x dependencies |
| `src/main.rs` | Main entry point, benchmark, pool mining loop |
| `src/agent.rs` | AgentIdentity, AE1 fingerprint constants |
| `src/pool_client.rs` | ZKWork binary TCP protocol implementation |
| `hivemine_agent.py` | Python SHA-256 simulation + pool client |
| `build.sh` | Build script (installs Rust if needed) |

## License

Apache-2.0 (matching snarkVM)
