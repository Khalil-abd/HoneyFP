"""Adaptive tarpit: slow down responses for attackers that hit many traps.

Goal: burn the attacker's scanning budget without making the app feel obviously broken
to a casual visitor.
"""
from __future__ import annotations

import time

from honeypot.config import settings
from honeypot.runtime.session_tracker import AttackerSession


def compute_delay_ms(sess: AttackerSession) -> int:
    if not settings.tarpit_enabled:
        return 0
    aggression = sess.trap_hits + sess.breadcrumb_hits + min(sess.requests // 5, 20)
    delay = settings.tarpit_base_delay_ms * (settings.tarpit_growth ** aggression)
    return int(min(delay, settings.tarpit_max_delay_ms))


def apply(sess: AttackerSession) -> int:
    delay = compute_delay_ms(sess)
    if delay > 0:
        time.sleep(delay / 1000.0)
    return delay
