"""Trap routes: one Flask route per TrapEndpoint in the blueprint.

When a request lands on a trap path:
- If the request looks benign (no params, no malicious keywords, normal UA),
  serve a realistic page so a casual visitor does not see a broken site.
- If the request carries a malicious payload, fire the LLM responder to mutate
  a fake vulnerable response, detect honeytoken leaks, and signal the SSH bridge.
"""
from __future__ import annotations

import logging
from typing import Any

from flask import Flask, Response, g, render_template, request

from honeypot.architect.schema import DeceptionBlueprint, TrapEndpoint
from honeypot.generator.honeytokens import find_token_in_text
from honeypot.runtime.bridge_ssh import signal_token_leaked
from honeypot.runtime.responder import mutate_response

logger = logging.getLogger(__name__)

SUSPICIOUS_TOKENS = (
    "'", '"', "<script", "<svg", "javascript:", "onerror=",
    "union ", "select ", " or 1=1", " or '1'='1",
    "../", "..%2f", "%27", "%3c", "%22",
    "0x", "/etc/passwd", "/proc/self", "${", "$(",
    " sleep(", " benchmark(", ";--", "||", "&&",
)

LEGIT_FALLBACK_TEMPLATES = {
    "/profile": "profile.html",
    "/search": "search.html",
    "/dashboard": "dashboard.html",
    "/login": "login.html",
    "/about": "about.html",
}


def _build_payload_string() -> str:
    pieces: list[str] = []
    if request.args:
        pieces.append("query=" + str(dict(request.args)))
    body = request.get_data(as_text=True)
    if body:
        pieces.append("body=" + body[:500])
    return " | ".join(pieces) or "(no payload)"


def _looks_malicious(payload: str, trap: TrapEndpoint) -> bool:
    if payload == "(no payload)":
        return False
    p = payload.lower()
    for kw in trap.trigger_keywords:
        if kw and kw.lower() in p:
            return True
    return any(s in p for s in SUSPICIOUS_TOKENS)


def _legit_fallback(trap: TrapEndpoint, blueprint: DeceptionBlueprint) -> Response | None:
    """Return a normal-looking response when there is no attack payload.

    For paths shared with a legit page (/profile, /search, /dashboard, ...) we
    render the matching template. For API paths we return a generic 401 JSON.
    For everything else we return a plausible empty 200.
    """
    persona = blueprint.persona
    pages = blueprint.enabled_legit_pages

    tpl = LEGIT_FALLBACK_TEMPLATES.get(trap.path)
    if tpl:
        ctx = {"persona": persona, "pages": pages}
        if tpl == "profile.html":
            ctx["user"] = {"username": "guest", "email": "guest@example.com"}
        if tpl == "search.html":
            ctx.update(q=request.args.get("q", ""), results=[])
        if tpl == "dashboard.html":
            ctx.update(user="guest", orders=[], stats={"orders": 0, "revenue": 0,
                                                       "users": 0, "products": 0})
        if tpl == "login.html":
            ctx["error"] = None
        return Response(render_template(tpl, **ctx), status=200, mimetype="text/html")

    if trap.path.startswith("/api/"):
        return Response('{"error":"unauthorized"}', status=401, mimetype="application/json")

    return Response(
        f"<html><body><h1>{persona.name}</h1><p>Nothing here.</p></body></html>",
        status=200, mimetype="text/html",
    )


def _trap_view(trap: TrapEndpoint, blueprint: DeceptionBlueprint) -> Response:
    payload = _build_payload_string()
    sess = g.get("session")
    profile = sess.profile if sess else "manual"
    is_hostile_session = profile not in {"casual", "manual", "unknown"}

    if not _looks_malicious(payload, trap) and not is_hostile_session:
        return _legit_fallback(trap, blueprint) or Response("", status=200)

    g.is_trap = True
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
    mime = "application/json" if body.lstrip().startswith("{") else "text/plain"
    return Response(body, status=status, mimetype=mime)


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
