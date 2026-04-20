"""
HiveMine → Hivelandia Land Claim
=================================
Each mining agent claims a parcel in Hivelandia when it first connects.
This populates the city map organically as the fleet grows.

Used by orchestrator.py — call claim_parcel(did, agent_name, coin) once
per agent on startup. Idempotent — safe to call on every restart.

No external dependencies beyond stdlib.
"""

import json
import logging
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("hivemine.land_claim")

HIVEGATE = "https://hivegate.onrender.com"
CLAIM_URL = f"{HIVEGATE}/v1/land/claim"

# Local cache — track which DIDs have already claimed to avoid hammering the endpoint
_claimed: set[str] = set()
_lock = threading.Lock()

# Persist claimed DIDs between restarts
_CACHE_FILE = Path("hivemine-land-claims.json")


def _load_cache() -> None:
    global _claimed
    if _CACHE_FILE.exists():
        try:
            data = json.loads(_CACHE_FILE.read_text())
            _claimed = set(data.get("claimed", []))
            logger.info(f"[land] loaded {len(_claimed)} prior claims from cache")
        except Exception as exc:
            logger.warning(f"[land] could not load claim cache: {exc}")


def _save_cache() -> None:
    try:
        with _lock:
            data = {"claimed": list(_claimed), "saved_at": datetime.now(timezone.utc).isoformat()}
        _CACHE_FILE.write_text(json.dumps(data, indent=2))
    except Exception as exc:
        logger.warning(f"[land] could not save claim cache: {exc}")


def claim_parcel(did: str, agent_name: str | None = None, coin: str | None = None) -> dict | None:
    """
    Claim a Hivelandia parcel for this agent's DID.
    Returns the parcel dict on success, None on failure (non-blocking).
    Idempotent — safe to call on every agent restart.
    """
    with _lock:
        if did in _claimed:
            return None  # Already claimed this session

    payload = json.dumps({
        "did":        did,
        "agent_name": agent_name,
        "coin":       coin,
        "metadata":   {"source": "hivemine", "claimed_at": datetime.now(timezone.utc).isoformat()},
    }).encode()

    req = urllib.request.Request(
        CLAIM_URL,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "HiveMine-LandClaim/1.0",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            parcel = body.get("parcel", {})
            parcel_id = parcel.get("parcel_id", "unknown")
            district = parcel.get("district", "unknown")
            already = body.get("already_claimed", False)
            if not already:
                logger.info(
                    f"[land] {agent_name or did[:20]} claimed parcel {parcel_id} "
                    f"in {district}"
                )
            with _lock:
                _claimed.add(did)
            _save_cache()
            return parcel
    except urllib.error.HTTPError as exc:
        # 4xx — don't retry, just log
        logger.debug(f"[land] claim HTTP {exc.code} for {did}: {exc.reason}")
    except Exception as exc:
        # Network failure — non-blocking, mining continues
        logger.debug(f"[land] claim failed for {did}: {exc}")

    return None


def claim_parcel_async(did: str, agent_name: str | None = None, coin: str | None = None) -> None:
    """Fire-and-forget land claim — does not block the mining agent."""
    t = threading.Thread(
        target=claim_parcel,
        args=(did, agent_name, coin),
        daemon=True,
        name=f"land-claim-{did[:12]}"
    )
    t.start()


# Load cache on import
_load_cache()
