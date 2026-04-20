"""
HiveMine Revenue Router
=======================
Aggregates simulated mining earnings across all coin agents and
flushes USD-equivalent estimates to HiveBank treasury at a
configurable interval.

Architecture
------------
- Each coin agent calls `router.record_earning(coin, usd_amount)` after
  a share is accepted.
- RouterThread flushes accumulated totals to HiveBank every N seconds.
- HiveBank endpoint receives a POST with the session total — no individual
  share data leaves this machine.

No external dependencies beyond stdlib.
"""

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("hivemine.revenue_router")

# ---------------------------------------------------------------------------
# Coin → USD exchange rate stubs (updated from live feed when available)
# ---------------------------------------------------------------------------

DEFAULT_RATES: dict[str, float] = {
    "ALEO": 0.30,     # ~$0.30/ALEO  — update from CoinGecko at startup
    "KAS":  0.14,     # ~$0.14/KAS
    "DOGE": 0.17,     # ~$0.17/DOGE
    "LTC":  82.00,    # ~$82/LTC
    "XMR":  155.00,   # ~$155/XMR
}


def fetch_live_rates() -> dict[str, float]:
    """Pull spot prices from CoinGecko (no API key, best-effort).
    Falls back to DEFAULT_RATES on any error.
    """
    ids = "aleonetwork,kaspa,dogecoin,litecoin,monero"
    url = (
        "https://api.coingecko.com/api/v3/simple/price"
        f"?ids={ids}&vs_currencies=usd"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HiveMine/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        mapping = {
            "ALEO": data.get("aleonetwork", {}).get("usd", DEFAULT_RATES["ALEO"]),
            "KAS":  data.get("kaspa", {}).get("usd", DEFAULT_RATES["KAS"]),
            "DOGE": data.get("dogecoin", {}).get("usd", DEFAULT_RATES["DOGE"]),
            "LTC":  data.get("litecoin", {}).get("usd", DEFAULT_RATES["LTC"]),
            "XMR":  data.get("monero", {}).get("usd", DEFAULT_RATES["XMR"]),
        }
        logger.info(f"[router] live rates: {mapping}")
        return mapping
    except Exception as exc:
        logger.warning(f"[router] rate fetch failed ({exc}), using defaults")
        return DEFAULT_RATES.copy()


# ---------------------------------------------------------------------------
# RevenueRouter
# ---------------------------------------------------------------------------

class RevenueRouter:
    """Thread-safe accumulator + periodic HiveBank flush."""

    def __init__(
        self,
        hivebank_endpoint: str,
        internal_key: str,
        founder_did: str,
        treasury_did: str,
        flush_interval: int = 3600,
        state_path: str = "hivemine-revenue.json",
        rates: dict | None = None,
    ):
        self.endpoint = hivebank_endpoint
        self.internal_key = internal_key
        self.founder_did = founder_did
        self.treasury_did = treasury_did
        self.flush_interval = flush_interval
        self.state_path = Path(state_path)
        self.rates: dict[str, float] = rates or fetch_live_rates()

        # Per-coin accumulators (coin_units and usd)
        self._lock = threading.Lock()
        self._coin_units: dict[str, float] = defaultdict(float)
        self._coin_usd: dict[str, float] = defaultdict(float)
        self._session_total_usd: float = 0.0
        self._lifetime_total_usd: float = 0.0
        self._flush_count: int = 0

        # Load persisted lifetime total
        self._load_state()

        # Rates refresh thread (every 15 min)
        self._rate_thread = threading.Thread(
            target=self._rate_refresh_loop, daemon=True
        )
        self._rate_thread.start()

        # Flush thread
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True
        )
        self._flush_thread.start()

        logger.info(
            f"[router] started — flush every {flush_interval}s → {self.endpoint}"
        )

    # ------------------------------------------------------------------
    # Public API (called by coin agents)
    # ------------------------------------------------------------------

    def record_earning(self, coin: str, units: float) -> None:
        """Record a coin unit earned (e.g. 0.5 ALEO).

        Args:
            coin:  uppercase ticker  e.g. "ALEO", "KAS", "DOGE", "LTC", "XMR"
            units: amount earned in native coin units
        """
        coin = coin.upper()
        rate = self.rates.get(coin, 0.0)
        usd = units * rate
        with self._lock:
            self._coin_units[coin] += units
            self._coin_usd[coin] += usd
            self._session_total_usd += usd

    def record_earning_usd(self, coin: str, usd: float) -> None:
        """Record a USD-denominated earning directly (when coin is unknown)."""
        coin = coin.upper()
        with self._lock:
            self._coin_usd[coin] += usd
            self._session_total_usd += usd

    def snapshot(self) -> dict:
        """Return a copy of current accumulators."""
        with self._lock:
            return {
                "session_total_usd": round(self._session_total_usd, 6),
                "lifetime_total_usd": round(self._lifetime_total_usd, 6),
                "flush_count": self._flush_count,
                "by_coin": {
                    c: {
                        "units": round(self._coin_units[c], 8),
                        "usd": round(self._coin_usd[c], 6),
                    }
                    for c in set(list(self._coin_units) + list(self._coin_usd))
                },
                "rates": self.rates,
            }

    # ------------------------------------------------------------------
    # Internal loops
    # ------------------------------------------------------------------

    def _flush_loop(self) -> None:
        while True:
            time.sleep(self.flush_interval)
            self._do_flush()

    def _do_flush(self) -> None:
        with self._lock:
            if self._session_total_usd == 0.0:
                logger.debug("[router] nothing to flush — $0 accumulated")
                return
            payload = {
                "action": "mining_revenue",
                "source": "hivemine",
                "founder_did": self.founder_did,
                "treasury_did": self.treasury_did,
                "usd_amount": round(self._session_total_usd, 6),
                "by_coin": {
                    c: {
                        "units": round(self._coin_units[c], 8),
                        "usd": round(self._coin_usd[c], 6),
                    }
                    for c in self._coin_usd
                },
                "flush_count": self._flush_count + 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            flushed = self._session_total_usd
            new_lifetime = self._lifetime_total_usd + flushed

        # POST outside lock
        success = self._post_to_hivebank(payload)
        if success:
            with self._lock:
                self._lifetime_total_usd = new_lifetime
                self._session_total_usd = 0.0
                for k in self._coin_usd:
                    self._coin_usd[k] = 0.0
                for k in self._coin_units:
                    self._coin_units[k] = 0.0
                self._flush_count += 1
            self._save_state()
            logger.info(
                f"[router] flushed ${flushed:.4f} → HiveBank "
                f"(lifetime ${new_lifetime:.4f}, flush #{payload['flush_count']})"
            )
        else:
            logger.warning(
                f"[router] flush failed — will retry next cycle "
                f"(${flushed:.4f} still buffered)"
            )

    def _post_to_hivebank(self, payload: dict) -> bool:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "x-hive-internal": self.internal_key,
                "X-Hive-DID": self.treasury_did,
                "User-Agent": "HiveMine-RevenueRouter/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                status = resp.status
                if 200 <= status < 300:
                    return True
                logger.warning(f"[router] HiveBank returned HTTP {status}")
                return False
        except urllib.error.HTTPError as exc:
            logger.warning(f"[router] HiveBank HTTP error {exc.code}: {exc.reason}")
            return False
        except Exception as exc:
            logger.warning(f"[router] HiveBank POST failed: {exc}")
            return False

    def _rate_refresh_loop(self) -> None:
        """Refresh exchange rates every 15 minutes."""
        while True:
            time.sleep(900)
            new_rates = fetch_live_rates()
            with self._lock:
                self.rates = new_rates

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _load_state(self) -> None:
        if self.state_path.exists():
            try:
                data = json.loads(self.state_path.read_text())
                self._lifetime_total_usd = data.get("lifetime_total_usd", 0.0)
                self._flush_count = data.get("flush_count", 0)
                logger.info(
                    f"[router] loaded state — lifetime ${self._lifetime_total_usd:.4f}, "
                    f"{self._flush_count} flushes"
                )
            except Exception as exc:
                logger.warning(f"[router] could not load state: {exc}")

    def _save_state(self) -> None:
        with self._lock:
            data = {
                "lifetime_total_usd": self._lifetime_total_usd,
                "flush_count": self._flush_count,
                "last_saved": datetime.now(timezone.utc).isoformat(),
            }
        try:
            self.state_path.write_text(json.dumps(data, indent=2))
        except Exception as exc:
            logger.warning(f"[router] could not save state: {exc}")


# ---------------------------------------------------------------------------
# Convenience factory (called from orchestrator.py)
# ---------------------------------------------------------------------------

def build_router(config: dict) -> "RevenueRouter | None":
    """Build a RevenueRouter from hivemine.json config.
    Returns None if revenue_router.enabled is false.
    """
    rc = config.get("revenue_router", {})
    if not rc.get("enabled", True):
        logger.info("[router] disabled in config — skipping")
        return None

    return RevenueRouter(
        hivebank_endpoint=rc.get(
            "hivebank_endpoint",
            "https://hivebank.onrender.com/v1/bank/treasury/deposit",
        ),
        internal_key=rc.get("hivebank_internal_key", ""),
        founder_did=rc.get("founder_did", ""),
        treasury_did=rc.get("treasury_did", "did:hive:hiveforce-ambassador"),
        flush_interval=rc.get("flush_interval_seconds", 3600),
        state_path="hivemine-revenue.json",
    )


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    print("=== HiveMine Revenue Router smoke test ===")
    router = RevenueRouter(
        hivebank_endpoint="https://hivebank.onrender.com/v1/bank/treasury/deposit",
        internal_key="hive_internal_125e04e071e8829be631ea0216dd4a0c9b707975fcecaf8c62c6a2ab43327d46",
        founder_did="did:hive:f150bbec-5660-413e-b305-d8d965b47845",
        treasury_did="did:hive:hiveforce-ambassador",
        flush_interval=10,  # flush every 10s in smoke test
    )

    # Simulate a 60-second run earning across all 4 coins
    print("Simulating 60s of earnings across ALEO / KAS / DOGE / LTC / XMR ...")
    for _ in range(60):
        router.record_earning("ALEO", 0.00547)   # ~197 ALEO/day / 36000s * 1s
        router.record_earning("KAS",  0.00231)
        router.record_earning("DOGE", 0.00116)
        router.record_earning("LTC",  0.0000023)
        router.record_earning("XMR",  0.0000019)
        time.sleep(1)

    snap = router.snapshot()
    print(json.dumps(snap, indent=2))
    print("Done — check above for flush log entries.")
