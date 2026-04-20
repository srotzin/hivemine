# HiveMine — Coin Agents

Python mining agent clients for the HiveMine swarm. Python 3.8+ stdlib only — no external dependencies.

---

## kaspa_agent.py — Kaspa (KAS)

**Algorithm:** kHeavyHash (matrix multiply sandwiched between two Keccak-256 hashes)  
**Protocol:** Stratum v1 (JSON over TCP, newline-delimited)

### Supported pools

| Alias     | Host                        | Port |
|-----------|-----------------------------|------|
| `k1pool`  | `pool.k1pool.com`           | 3112 |
| `binance` | `kas.poolbinance.com`       | 3333 |
| `2miners` | `kas.2miners.com`           | 3000 |

### Usage

```bash
# Mine with 4 agents
python kaspa_agent.py --wallet kaspa:qrYOURWALLET --agents 4

# Mine against a specific pool
python kaspa_agent.py --wallet kaspa:qrYOURWALLET --pool kas.2miners.com:3000

# 30-second CPU benchmark
python kaspa_agent.py --benchmark --agents 4

# Wallet via environment variable
KAS_WALLET=kaspa:qrYOURWALLET python kaspa_agent.py
```

### Key constants (top of file)

```python
POOL_DEFAULT            = "pool.k1pool.com:3112"
KAS_YIELD_PER_MHS_PER_DAY = 70.8   # KAS per MH/s per day
CPU_MHS_ESTIMATE        = 0.001    # ~1 KH/s per CPU agent
KAS_PRICE               = 0.12
POOL_FEE                = 0.01
```

---

## scrypt_agent.py — DOGE + LTC Merged Mining

**Algorithm:** Scrypt (N=1024, r=1, p=1 — original Litecoin parameters)  
**Protocol:** Stratum v1 with AuxPOW merged mining  
**Merging:** Connect to ONE LTC pool; the pool handles DOGE AuxPOW automatically and pays both currencies

### Supported pools

| Alias     | Host                        | Port |
|-----------|-----------------------------|------|
| `viabtc`  | `ltc.viabtc.com`            | 3333 |
| `binance` | `ltc.poolbinance.com`       | 3333 |
| `f2pool`  | `ltc.f2pool.com`            | 8888 |

Pool auth format: `LTC_WALLET.WORKER/DOGE_WALLET` (ViaBTC merged mining convention)

### Usage

```bash
# Mine with 2 agents
python scrypt_agent.py --ltc-wallet YOUR_LTC_ADDR --doge-wallet YOUR_DOGE_ADDR --agents 2

# Mine against F2Pool
python scrypt_agent.py --ltc-wallet LTC_ADDR --doge-wallet DOGE_ADDR --pool ltc.f2pool.com:8888

# 30-second Scrypt benchmark
python scrypt_agent.py --benchmark --agents 2

# Wallets via environment variables
LTC_WALLET=LTC_ADDR DOGE_WALLET=DOGE_ADDR python scrypt_agent.py
```

### Key constants (top of file)

```python
POOL_DEFAULT          = "ltc.viabtc.com:3333"
DOGE_PER_AGENT_PER_DAY = 12.0   # at ~50 KH/s CPU Scrypt
LTC_PER_AGENT_PER_DAY  = 0.0035
DOGE_PRICE            = 0.18
LTC_PRICE             = 85.0
POOL_FEE              = 0.01
```

---

## Environment variables

| Variable      | Used by          | Description                      |
|---------------|------------------|----------------------------------|
| `KAS_WALLET`  | kaspa_agent.py   | Kaspa wallet address             |
| `KAS_POOL`    | kaspa_agent.py   | Override default pool            |
| `LTC_WALLET`  | scrypt_agent.py  | Litecoin wallet address          |
| `DOGE_WALLET` | scrypt_agent.py  | Dogecoin wallet address          |
| `SCRYPT_POOL` | scrypt_agent.py  | Override default pool            |

---

## Common features (both agents)

- **Reconnect:** exponential backoff (5 s → 10 s → 20 s → 40 s → 60 s cap)
- **Hashrate:** EWMA tracker with 5-minute smoothing window, reported every 30 s
- **Share pacing:** max 4 shares per 30-second bucket — no bursting
- **Heartbeat:** `mining.ping` every 60 s to keep the TCP connection alive
- **Thread safety:** all shared state guarded by `threading.Lock`
- **Graceful shutdown:** Ctrl+C stops all agent threads cleanly
- **Stdlib only:** `socket`, `hashlib`, `json`, `threading`, `time`, `struct`, `os`, `argparse`

---

## Algorithm notes

### kHeavyHash (Kaspa)

```
hash1        = keccak256(block_header)
matrix       = seed_64x64_uint16_matrix(block_header)
matrix_out   = matrix_multiply(hash1_as_vector, matrix)   ← the "heavy" step
final_hash   = keccak256(matrix_out)
```

The Python implementation approximates this faithfully but runs at ~1 KH/s per core.
A production deployment needs a C/Rust extension for competitive speeds.

### Scrypt (LTC / DOGE)

```
digest = scrypt(password=header, salt=header, N=1024, r=1, p=1, dklen=32)
```

Uses `hashlib.scrypt` (OpenSSL backend) when available; falls back to a
double-SHA-256 loop for structural benchmarking on restricted builds.
