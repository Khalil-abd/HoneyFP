"""Adaptive tarpit: slow down responses for attackers that hit many traps,
or any session profiled as a scanner / automated fuzzer (even on 404s).

Goal: burn the attacker's scanning budget without ever delaying a casual visitor.
"""
from __future__ import annotations

import time

from honeypot.config import settings
from honeypot.runtime.session_tracker import AttackerSession

HOSTILE_PROFILES = {
    "sqlmap", "nikto", "nmap", "nuclei", "gobuster", "dirbuster",
    "ffuf", "zap", "burp", "wpscan", "feroxbuster", "automated_fuzzer",
    "engaged_human",
}


def is_hostile(sess: AttackerSession) -> bool:
    return sess.profile in HOSTILE_PROFILES


def compute_delay_ms(sess: AttackerSession) -> int:
    if not settings.tarpit_enabled:
        return 0
    if not is_hostile(sess) and sess.trap_hits == 0 and sess.breadcrumb_hits == 0:
        return 0
    aggression = sess.trap_hits + sess.breadcrumb_hits + min(sess.requests // 5, 20)
    delay = settings.tarpit_base_delay_ms * (settings.tarpit_growth ** aggression)
    return int(min(delay, settings.tarpit_max_delay_ms))


def apply(sess: AttackerSession) -> int:
    delay = compute_delay_ms(sess)
    if delay > 0:
        time.sleep(delay / 1000.0)
    return delay
