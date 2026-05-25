"""Classify attacker behaviour by inspecting their request stream.

Profile categories drive both the response style and the tarpit aggressiveness.
"""
from __future__ import annotations

from honeypot.runtime.session_tracker import AttackerSession

KNOWN_SCANNER_UA = {
    "sqlmap": "sqlmap",
    "nikto": "nikto",
    "nmap": "nmap",
    "nuclei": "nuclei",
    "gobuster": "gobuster",
    "dirbuster": "dirbuster",
    "ffuf": "ffuf",
    "zap": "zap",
    "burp": "burp",
    "wpscan": "wpscan",
    "feroxbuster": "feroxbuster",
}


def classify(sess: AttackerSession) -> str:
    ua = sess.user_agent.lower()
    for needle, label in KNOWN_SCANNER_UA.items():
        if needle in ua:
            return label

    request_rate = sess.requests / max(1.0, sess.last_seen - sess.first_seen)
    fuzz_signal = sess.requests >= 20 and len(set(sess.endpoints[-20:])) >= 15

    if fuzz_signal or request_rate > 4.0:
        return "automated_fuzzer"
    if sess.trap_hits >= 3 or sess.honeytokens_seen:
        return "engaged_human"
    if sess.requests <= 5:
        return "casual"
    return "manual"


def update_profile(sess: AttackerSession) -> str:
    sess.profile = classify(sess)
    return sess.profile
