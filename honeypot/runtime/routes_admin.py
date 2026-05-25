"""Analyst-only admin routes (localhost only).

Exposes the FP -> Strategy lineage in the running honeypot itself, so you can
inspect the deception inventory from a browser without opening Streamlit.
"""
from __future__ import annotations

import json
import logging

from flask import Flask, abort, render_template, request

from honeypot.architect.schema import DeceptionBlueprint
from honeypot.config import settings

logger = logging.getLogger(__name__)

ALLOWED_IPS = {"127.0.0.1", "::1", "localhost"}


def _guard():
    if (request.remote_addr or "") not in ALLOWED_IPS:
        abort(404)


def register_admin_routes(app: Flask, blueprint: DeceptionBlueprint):
    if not settings.fp_alerts_path.exists():
        logger.warning("Admin: fp_alerts.json missing, lineage page will be empty")
        fp_by_id: dict = {}
        fp_count = 0
    else:
        fps = json.loads(settings.fp_alerts_path.read_text(encoding="utf-8"))
        fp_by_id = {a["alert_id"]: a for a in fps}
        fp_count = len(fps)

    @app.route("/_internal/strategies", methods=["GET"])
    def strategies():
        _guard()
        lineage = []
        for t in blueprint.traps:
            src = fp_by_id.get(t.source_fp_alert_id, {
                "alert_id": t.source_fp_alert_id,
                "alert_type": "(not found in fp_alerts.json)",
                "endpoint": t.path, "parameter": t.parameter, "evidence": "",
                "risk_level": "?", "confidence_level": "?",
                "source": "?", "classification": "?",
            })
            lineage.append({"trap": t.model_dump(), "fp": src})

        return render_template(
            "admin_strategies.html",
            bp=blueprint.model_dump(),
            lineage=lineage,
            fp_count=fp_count,
        )

    logger.info("Registered admin page at /_internal/strategies (localhost only)")
