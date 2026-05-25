"""Per-attacker session tracking & fingerprinting.

Kept in-memory for simplicity. For production swap the dict for Redis.
"""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AttackerSession:
    fingerprint: str
    ip: str
    user_agent: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    requests: int = 0
    trap_hits: int = 0
    breadcrumb_hits: int = 0
    honeytokens_seen: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    profile: str = "unknown"   # set by attacker_profiler


_sessions: dict[str, AttackerSession] = {}
_lock = threading.Lock()


def fingerprint_request(ip: str, user_agent: str) -> str:
    h = hashlib.sha256(f"{ip}|{user_agent}".encode()).hexdigest()
    return h[:16]


def get_or_create(ip: str, user_agent: str) -> AttackerSession:
    fp = fingerprint_request(ip, user_agent)
    with _lock:
        sess = _sessions.get(fp)
        if sess is None:
            sess = AttackerSession(fingerprint=fp, ip=ip, user_agent=user_agent)
            _sessions[fp] = sess
        return sess


def record_request(sess: AttackerSession, endpoint: str, is_trap: bool, is_breadcrumb: bool,
                   honeytoken_id: Optional[str] = None):
    with _lock:
        sess.last_seen = time.time()
        sess.requests += 1
        sess.endpoints.append(endpoint)
        if is_trap:
            sess.trap_hits += 1
        if is_breadcrumb:
            sess.breadcrumb_hits += 1
        if honeytoken_id and honeytoken_id not in sess.honeytokens_seen:
            sess.honeytokens_seen.append(honeytoken_id)


def all_sessions() -> list[AttackerSession]:
    with _lock:
        return list(_sessions.values())
