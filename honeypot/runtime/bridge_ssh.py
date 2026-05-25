"""Bridge: when a honeytoken is exfiltrated via the web, alert the SSH side (Cowrie)."""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from honeypot.config import settings

logger = logging.getLogger(__name__)


def signal_token_leaked(token_id: str, attacker_ip: str, fingerprint: str,
                        endpoint: str, raw_response_excerpt: str):
    if not settings.ssh_bridge_enabled:
        return
    record = {
        "ts": time.time(),
        "token_id": token_id,
        "ip": attacker_ip,
        "fingerprint": fingerprint,
        "endpoint": endpoint,
        "excerpt": raw_response_excerpt[:300],
    }
    with settings.leak_log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    logger.warning("HONEYTOKEN LEAKED token=%s ip=%s endpoint=%s", token_id, attacker_ip, endpoint)


def primed_credentials() -> list[dict]:
    """Return creds Cowrie should accept (read by start_honeypot.py if desired)."""
    p: Path = settings.cowrie_credentials_file
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8"))
