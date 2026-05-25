"""Flask app factory and request-level instrumentation."""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from flask import Flask, g, request

from honeypot.architect.architect import load_blueprint
from honeypot.config import TEMPLATE_DIR, settings
from honeypot.runtime import attacker_profiler, session_tracker, tarpit

logger = logging.getLogger(__name__)


def _log_interaction(record: dict):
    settings.interactions_log.parent.mkdir(parents=True, exist_ok=True)
    with settings.interactions_log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def create_app() -> Flask:
    blueprint = load_blueprint()

    app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
    app.secret_key = settings.secret_key
    app.config["BLUEPRINT"] = blueprint

    from honeypot.runtime.routes_app import register_app_routes
    from honeypot.runtime.routes_decoys import register_decoy_routes
    from honeypot.runtime.routes_traps import register_trap_routes

    trap_paths = register_trap_routes(app, blueprint)
    decoy_paths = register_decoy_routes(app, blueprint)
    register_app_routes(app, blueprint, reserved_paths=trap_paths | decoy_paths)

    @app.before_request
    def _before():
        g.t_start = time.time()
        g.session = session_tracker.get_or_create(
            request.remote_addr or "unknown",
            request.headers.get("User-Agent", "-"),
        )

    @app.after_request
    def _after(response):
        sess = g.get("session")
        if sess is None:
            return response

        path = request.path
        is_trap = getattr(g, "is_trap", False)
        is_breadcrumb = getattr(g, "is_breadcrumb", False)
        honeytoken_id = getattr(g, "honeytoken_id", None)

        session_tracker.record_request(sess, path, is_trap, is_breadcrumb, honeytoken_id)
        attacker_profiler.update_profile(sess)
        delay_ms = tarpit.apply(sess) if (is_trap or is_breadcrumb) else 0

        response.headers["Server"] = blueprint.persona.server_header
        response.headers["X-Powered-By"] = blueprint.persona.powered_by

        _log_interaction({
            "ts": time.time(),
            "ip": sess.ip,
            "fingerprint": sess.fingerprint,
            "profile": sess.profile,
            "method": request.method,
            "path": path,
            "query": request.query_string.decode("utf-8", "replace"),
            "body": request.get_data(as_text=True)[:500],
            "user_agent": sess.user_agent[:200],
            "status": response.status_code,
            "is_trap": is_trap,
            "is_breadcrumb": is_breadcrumb,
            "honeytoken_id": honeytoken_id,
            "tarpit_delay_ms": delay_ms,
            "latency_ms": int((time.time() - g.t_start) * 1000),
        })
        return response

    return app
