"""Trap routes: one Flask route per TrapEndpoint in the blueprint.

Each trap calls the LLM responder to mutate the body of a fake vulnerable response.
If the response surfaces a honeytoken, we signal the SSH bridge.
"""
from __future__ import annotations

import logging
from typing import Any

from flask import Flask, Response, g, request

from honeypot.architect.schema import DeceptionBlueprint, TrapEndpoint
from honeypot.generator.honeytokens import find_token_in_text
from honeypot.runtime.bridge_ssh import signal_token_leaked
from honeypot.runtime.responder import mutate_response

logger = logging.getLogger(__name__)


def _build_payload_string() -> str:
    pieces: list[str] = []
    if request.args:
        pieces.append("query=" + str(dict(request.args)))
    body = request.get_data(as_text=True)
    if body:
        pieces.append("body=" + body[:500])
    return " | ".join(pieces) or "(no payload)"


def _trap_view(trap: TrapEndpoint, blueprint: DeceptionBlueprint) -> Response:
    g.is_trap = True
    sess = g.get("session")
    profile = sess.profile if sess else "manual"

    payload = _build_payload_string()
    body = mutate_response(trap, payload, profile)

    leaked = find_token_in_text(body, blueprint.honeytokens)
    if leaked is None and trap.leaks_honeytoken_id:
        leaked = next((t for t in blueprint.honeytokens
                       if t.token_id == trap.leaks_honeytoken_id), None)
        if leaked:
            body = (
                body.rstrip()
                + f"\n\n# residual debug: DEPLOY_USER={leaked.username} "
                  f"DEPLOY_PASS={leaked.password} TOKEN={leaked.token_id}\n"
            )

    if leaked:
        g.honeytoken_id = leaked.token_id
        signal_token_leaked(
            token_id=leaked.token_id,
            attacker_ip=sess.ip if sess else "unknown",
            fingerprint=sess.fingerprint if sess else "unknown",
            endpoint=trap.path,
            raw_response_excerpt=body,
        )

    status = 500 if trap.vuln_family in {"sql_injection", "info_disclosure_debug", "generic_500"} else 200
    return Response(body, status=status, mimetype="text/plain")


def register_trap_routes(app: Flask, blueprint: DeceptionBlueprint) -> set[str]:
    """Register one Flask route per trap. Returns the set of paths now owned by traps
    so the caller can avoid registering legit pages on the same path."""
    used: set[tuple[str, str]] = set()
    owned_paths: set[str] = set()
    for trap in blueprint.traps:
        key = (trap.path, trap.method)
        if key in used:
            continue
        used.add(key)

        def make_view(t: TrapEndpoint = trap) -> Any:
            def view():
                return _trap_view(t, blueprint)
            view.__name__ = f"trap_{t.source_fp_alert_id.replace('-', '_')}"
            return view

        app.add_url_rule(
            trap.path,
            endpoint=f"trap::{trap.source_fp_alert_id}::{trap.method}",
            view_func=make_view(),
            methods=[trap.method],
        )
        owned_paths.add(trap.path)
        logger.info("Registered trap %s %s (family=%s)", trap.method, trap.path, trap.vuln_family)
    return owned_paths
