"""Runtime LLM responder.

Sends a small, well-scoped prompt to Ollama (or Groq) per trap hit, then caches
the response so repeated identical payloads do not repeatedly hit the LLM.

Falls back to the static `decoy_template` from the blueprint if the LLM is down.
"""
from __future__ import annotations

import logging
from typing import Optional

import requests
from cachetools import LRUCache

from honeypot.architect.schema import TrapEndpoint
from honeypot.config import settings

logger = logging.getLogger(__name__)

_cache: LRUCache = LRUCache(maxsize=settings.responder_cache_size)


def _cache_key(trap_path: str, payload: str, profile: str) -> str:
    return f"{trap_path}|{profile}|{payload[:200]}"


def _ollama_generate(system: str, user: str) -> Optional[str]:
    try:
        r = requests.post(
            settings.ollama_url,
            json={
                "model": settings.ollama_model,
                "prompt": f"{system}\n\n[ATTACKER PAYLOAD]\n{user}\n\n[RAW SERVER RESPONSE]",
                "stream": False,
                "options": {"temperature": 0.4, "num_predict": 320},
            },
            timeout=settings.responder_timeout_s,
        )
        r.raise_for_status()
        return r.json().get("response", "").strip()
    except Exception as e:
        logger.warning("Ollama responder failed: %s", e)
        return None


def _groq_generate(system: str, user: str) -> Optional[str]:
    try:
        from groq import Groq
        client = Groq(api_key=settings.groq_api_key)
        completion = client.chat.completions.create(
            model=settings.groq_model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=0.4,
            max_tokens=320,
        )
        return completion.choices[0].message.content
    except Exception as e:
        logger.warning("Groq responder failed: %s", e)
        return None


def mutate_response(trap: TrapEndpoint, payload: str, profile: str = "manual") -> str:
    """Return the body of the deceptive HTTP response for this trap+payload."""
    key = _cache_key(trap.path, payload, profile)
    if key in _cache:
        return _cache[key]

    system = (
        trap.llm_mutation_prompt
        + "\n\nAttacker profile: "
        + profile
        + "\nNever break the fourth wall. Output only the raw HTTP response body."
    )
    user = f"Endpoint: {trap.path}\nVulnerability family: {trap.vuln_family}\nPayload: {payload}"

    out = None
    if settings.responder_provider == "ollama":
        out = _ollama_generate(system, user)
    elif settings.responder_provider == "groq":
        out = _groq_generate(system, user)

    if not out:
        out = trap.decoy_template.replace("{payload}", payload[:200])

    _cache[key] = out
    return out
