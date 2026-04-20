#!/usr/bin/env python3
"""
orchestrator.py — HiveMine Swarm Conductor

Master process that spawns and manages all mining agents across all coins
on your own machines. Reads config from hivemine.json, spawns agent
subprocesses, monitors health, restarts crashes, and reports fleet stats.

Usage:
    python3 orchestrator.py --config hivemine.json
    python3 orchestrator.py --config hivemine.json --dry-run
    python3 orchestrator.py --config hivemine.json --verbose
    python3 orchestrator.py --config hivemine.json --ramp-today 430

Requirements: Python 3.8+, stdlib only.
"""

import argparse
import json
import math
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, date
from pathlib import Path
from typing import Dict, List, Optional, Any

# Revenue router (optional — only imported if file is present)
try:
    from revenue_router import build_router as _build_router  # type: ignore
except ImportError:
    _build_router = None  # type: ignore

# ─── Paths ────────────────────────────────────────────────────────────────────

COINS_DIR = Path(__file__).parent / "coins"
AGENT_SCRIPTS = {
    "aleo":   Path(__file__).parent / "hivemine_agent.py",
    "kaspa":  COINS_DIR / "kaspa_agent.py",
    "scrypt": COINS_DIR / "scrypt_agent.py",
    "xmr":    COINS_DIR / "xmr_agent.py",
}

# ─── EWMA ─────────────────────────────────────────────────────────────────────

class EWMAHashrate:
    """5-minute exponential weighted moving average."""

    def __init__(self, window: int = 300) -> None:
        self._w     = window
        self._val   = 0.0
        self._last  = time.monotonic()
        self._lock  = threading.Lock()

    def update(self, sample: float) -> None:
        now = time.monotonic()
        with self._lock:
            dt = now - self._last
            decay      = math.exp(-dt / self._w)
            self._val  = decay * self._val + (1.0 - decay) * sample
            self._last = now

    def get(self) -> float:
        with self._lock:
            return self._val


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class CoinConfig:
    coin:        str
    count:       int
    wallet:      str
    pool:        str
    extra:       Dict[str, Any] = field(default_factory=dict)

    # Per-coin yield estimates (used for revenue display only)
    YIELD: Dict[str, Dict[str, float]] = field(default_factory=lambda: {
        "aleo":   {"per_agent_day_usd": 7.09,  "unit": "ALEO"},
        "kaspa":  {"per_agent_day_usd": 1.01,  "unit": "KAS"},
        "scrypt": {"per_agent_day_usd": 2.43,  "unit": "DOGE+LTC"},
        "xmr":    {"per_agent_day_usd": 0.077, "unit": "XMR"},
    })

    def est_usd_per_day(self) -> float:
        return self.YIELD.get(self.coin, {}).get("per_agent_day_usd", 0.0) * self.count


@dataclass
class AgentProcess:
    agent_id:    int
    coin:        str
    worker_name: str
    process:     Optional[subprocess.Popen]
    started_at:  float = field(default_factory=time.monotonic)
    restarts:    int   = 0
    alive:       bool  = True

    def is_running(self) -> bool:
        if self.process is None:
            return False
        return self.process.poll() is None

    def uptime(self) -> float:
        return time.monotonic() - self.started_at


# ─── Conductor ────────────────────────────────────────────────────────────────

class HiveMineConductor:
    """
    Master swarm conductor for HiveMine.

    Reads hivemine.json, spawns agent subprocesses on the local machine,
    monitors their health, restarts crashes, and reports fleet statistics
    every 5 minutes.
    """

    REPORT_INTERVAL  = 300   # 5 minutes
    HEALTH_INTERVAL  = 30    # check agent health every 30s
    MAX_RESTART_WAIT = 60    # max backoff before restarting a crashed agent

    def __init__(self, config_path: str, dry_run: bool = False, verbose: bool = False) -> None:
        self.config_path = config_path
        self.dry_run     = dry_run
        self.verbose     = verbose
        self.configs:    List[CoinConfig]   = []
        self.agents:     List[AgentProcess] = []
        self._stop       = threading.Event()
        self._lock       = threading.Lock()

    # ── Config ────────────────────────────────────────────────────────────────

    def load_config(self) -> None:
        """Load and validate hivemine.json."""
        with open(self.config_path) as f:
            raw = json.load(f)

        for entry in raw.get("fleet", []):
            coin = entry["coin"].lower()
            if coin not in AGENT_SCRIPTS:
                print(f"[warn] Unknown coin '{coin}' — skipping", file=sys.stderr)
                continue
            if not AGENT_SCRIPTS[coin].exists():
                print(f"[warn] Agent script for '{coin}' not found at {AGENT_SCRIPTS[coin]} — skipping")
                continue
            self.configs.append(CoinConfig(
                coin   = coin,
                count  = int(entry.get("count", 1)),
                wallet = entry.get("wallet", ""),
                pool   = entry.get("pool", ""),
                extra  = {k: v for k, v in entry.items()
                          if k not in ("coin", "count", "wallet", "pool")},
            ))

        # Apply ramp if configured
        ramp = raw.get("ramp", {})
        if ramp.get("enabled") and not self.dry_run:
            self._apply_ramp(ramp)

        total = sum(c.count for c in self.configs)
        print(f"[conductor] Config loaded — {len(self.configs)} coin(s), {total} total agents planned")

    def _apply_ramp(self, ramp: Dict[str, Any]) -> None:
        """Scale down agent counts based on ramp schedule."""
        apd        = int(ramp.get("agents_per_day", 430))
        start_str  = ramp.get("start_date", str(date.today()))
        start      = date.fromisoformat(start_str)
        days_in    = (date.today() - start).days + 1
        if days_in <= 0:
            days_in = 1
        max_agents = apd * days_in
        total      = sum(c.count for c in self.configs)
        if total <= max_agents:
            return   # already within ramp
        scale = max_agents / total
        for c in self.configs:
            c.count = max(1, int(c.count * scale))
        print(f"[ramp] Day {days_in} — scaling to {sum(c.c for c in self.configs)} agents "
              f"({apd}/day × {days_in} days = {max_agents} max)")

    # ── Fleet start ───────────────────────────────────────────────────────────

    def start_fleet(self) -> None:
        """Spawn all agent subprocesses."""
        for cfg in self.configs:
            for i in range(cfg.count):
                self._spawn_agent(cfg, i)

        total = len(self.agents)
        print(f"[conductor] Fleet started — {total} agents across {len(self.configs)} coin(s)")

    def _build_cmd(self, cfg: CoinConfig, agent_id: int) -> List[str]:
        """Build the subprocess command for one agent."""
        script = str(AGENT_SCRIPTS[cfg.coin])
        name   = f"{cfg.coin[:3]}-agent-{agent_id:04d}"

        cmd = [sys.executable, script,
               "--wallet",   cfg.wallet,
               "--worker",   name,
               "--pool",     cfg.pool,
               "--agent-id", str(agent_id),
               "--agents",   "1"]

        # Coin-specific extras
        if cfg.coin == "scrypt":
            doge = cfg.extra.get("doge_wallet", cfg.wallet)
            cmd += ["--doge-wallet", doge]
        if cfg.coin == "aleo":
            mix = cfg.extra.get("fingerprint_mix", {})
            if mix:
                # Pass as JSON env var — agent reads HIVEMINE_FINGERPRINT_MIX
                pass  # handled via env below

        return cmd

    def _spawn_agent(self, cfg: CoinConfig, local_id: int) -> AgentProcess:
        """Spawn a single agent subprocess."""
        global_id = len(self.agents)
        name      = f"{cfg.coin[:3]}-agent-{local_id:04d}"
        cmd       = self._build_cmd(cfg, local_id)

        if self.dry_run:
            print(f"  [dry-run] Would spawn: {' '.join(cmd)}")
            proc = None
        else:
            env = os.environ.copy()
            if cfg.coin == "aleo":
                mix = cfg.extra.get("fingerprint_mix", {})
                if mix:
                    env["HIVEMINE_FINGERPRINT_MIX"] = json.dumps(mix)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL if not self.verbose else None,
                stderr=subprocess.DEVNULL if not self.verbose else None,
                env=env,
            )
            if self.verbose:
                print(f"  [spawn] {name} pid={proc.pid}")

        agent = AgentProcess(
            agent_id    = global_id,
            coin        = cfg.coin,
            worker_name = name,
            process     = proc,
        )
        with self._lock:
            self.agents.append(agent)
        return agent

    # ── Health monitor ────────────────────────────────────────────────────────

    def health_monitor(self) -> None:
        """Background thread — checks agents every 30s, restarts dead ones."""
        restart_delays: Dict[int, float] = {}

        while not self._stop.is_set():
            time.sleep(self.HEALTH_INTERVAL)
            with self._lock:
                agents = list(self.agents)

            for agent in agents:
                if self.dry_run or agent.process is None:
                    continue
                if not agent.is_running():
                    delay = restart_delays.get(agent.agent_id, 5)
                    print(f"[health] {agent.worker_name} died (exit {agent.process.poll()}) "
                          f"— restarting in {delay:.0f}s (restart #{agent.restarts + 1})")
                    time.sleep(delay)
                    restart_delays[agent.agent_id] = min(delay * 2, self.MAX_RESTART_WAIT)

                    # Find its config
                    coin_cfg = next((c for c in self.configs if c.coin == agent.coin), None)
                    if coin_cfg:
                        local_id = int(agent.worker_name.split("-")[-1])
                        cmd      = self._build_cmd(coin_cfg, local_id)
                        try:
                            agent.process  = subprocess.Popen(cmd,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
                            agent.restarts += 1
                            agent.started_at = time.monotonic()
                            if self.verbose:
                                print(f"  [restart] {agent.worker_name} pid={agent.process.pid}")
                        except Exception as e:
                            print(f"  [error] Failed to restart {agent.worker_name}: {e}")
                else:
                    restart_delays[agent.agent_id] = 5  # reset on healthy

    # ── Stats & reporting ─────────────────────────────────────────────────────

    def fleet_reporter(self) -> None:
        """Background thread — prints fleet summary every 5 minutes."""
        while not self._stop.is_set():
            time.sleep(self.REPORT_INTERVAL)
            self.print_fleet_report()

    def print_fleet_report(self) -> None:
        """Print a formatted fleet status report."""
        with self._lock:
            agents = list(self.agents)

        by_coin: Dict[str, List[AgentProcess]] = {}
        for a in agents:
            by_coin.setdefault(a.coin, []).append(a)

        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        print(f"\n{'─'*60}")
        print(f"  HiveMine Fleet Report — {now}")
        print(f"{'─'*60}")

        total_healthy = 0
        total_est_usd = 0.0

        coin_yields = {
            "aleo":   7.09,
            "kaspa":  1.01,
            "scrypt": 2.43,
            "xmr":    0.077,
        }

        router = getattr(self, '_router', None)

        for coin, coin_agents in sorted(by_coin.items()):
            healthy = sum(1 for a in coin_agents if (a.process is None or a.is_running()))
            total   = len(coin_agents)
            est     = coin_yields.get(coin, 0.0) * healthy
            total_healthy += healthy
            total_est_usd += est
            restarts = sum(a.restarts for a in coin_agents)
            print(f"  {coin.upper():<8} {healthy:>5}/{total} agents  "
                  f"${est:>10,.2f}/day est  restarts={restarts}")
            # Record estimated per-interval earnings to revenue router
            if router and healthy > 0:
                # Convert daily est to per-report-interval (60s default)
                interval_usd = (est / 86400) * 60
                router.record_earning_usd(coin.upper(), interval_usd)

        print(f"{'─'*60}")
        print(f"  TOTAL    {total_healthy:>5}/{len(agents)} agents  "
              f"${total_est_usd:>10,.2f}/day est")
        print(f"  Monthly  ${total_est_usd * 30:>10,.2f}   "
              f"Annual ${total_est_usd * 365:>10,.2f}")
        if router:
            snap = router.snapshot()
            print(f"  Revenue  session=${snap['session_total_usd']:.4f} USD  "
                  f"lifetime=${snap['lifetime_total_usd']:.4f} USD  "
                  f"flushes={snap['flush_count']}")
        print(f"{'─'*60}\n")

    # ── Shutdown ──────────────────────────────────────────────────────────────

    def graceful_shutdown(self) -> None:
        """SIGTERM all agents and exit cleanly."""
        print("\n[conductor] Shutting down fleet...")
        self._stop.set()
        with self._lock:
            agents = list(self.agents)
        for agent in agents:
            if agent.process and agent.is_running():
                try:
                    agent.process.terminate()
                except Exception:
                    pass
        # Give them 5s to exit
        time.sleep(5)
        for agent in agents:
            if agent.process and agent.is_running():
                try:
                    agent.process.kill()
                except Exception:
                    pass
        print(f"[conductor] Fleet stopped. {len(agents)} agents terminated.")

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Load config, start fleet, run health monitor and reporter."""
        self.load_config()

        if self.dry_run:
            print("[dry-run] Simulating fleet startup — no processes will be spawned")

        # Start revenue router
        self._router = None
        if _build_router is not None:
            try:
                self._router = _build_router(self.config)
                if self._router:
                    print("[conductor] Revenue router started — flushing to HiveBank every "
                          f"{self.config.get('revenue_router', {}).get('flush_interval_seconds', 3600)}s")
            except Exception as exc:
                print(f"[conductor] Revenue router failed to start: {exc} (continuing without it)")

        self.start_fleet()
        self.print_fleet_report()

        # Start background threads
        health_t   = threading.Thread(target=self.health_monitor,  daemon=True, name="health")
        reporter_t = threading.Thread(target=self.fleet_reporter,   daemon=True, name="reporter")
        health_t.start()
        reporter_t.start()

        # Register signal handlers
        def _sig(sig, frame):
            self.graceful_shutdown()
            sys.exit(0)

        signal.signal(signal.SIGTERM, _sig)
        signal.signal(signal.SIGINT,  _sig)

        print(f"[conductor] Running. Ctrl+C or SIGTERM to stop.")
        try:
            while not self._stop.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.graceful_shutdown()


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="HiveMine Swarm Conductor")
    p.add_argument("--config",     default="hivemine.json", help="Path to hivemine.json")
    p.add_argument("--dry-run",    action="store_true",     help="Simulate without spawning")
    p.add_argument("--verbose",    action="store_true",     help="Show agent stdout/stderr")
    p.add_argument("--report",     action="store_true",     help="Print one fleet report and exit")
    args = p.parse_args()

    conductor = HiveMineConductor(args.config, dry_run=args.dry_run, verbose=args.verbose)

    if args.report:
        conductor.load_config()
        conductor.print_fleet_report()
        return

    conductor.run()


if __name__ == "__main__":
    main()
