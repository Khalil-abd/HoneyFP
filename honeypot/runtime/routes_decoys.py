"""Decoy breadcrumb routes: robots.txt, sitemap.xml, .env, /backup/, .git/* etc.

These serve materialised files written by the Generator. Hitting one of these is
a strong "this is a reconnaissance attempt" signal that we feed into profiling.
"""
from __future__ import annotations

import logging
import mimetypes
from pathlib import Path

from flask import Flask, Response, g

from honeypot.architect.schema import DeceptionBlueprint
from honeypot.config import DECOY_DIR

logger = logging.getLogger(__name__)


def _guess_mime(path: str) -> str:
    if path.endswith(".txt") or path.endswith(".env"):
        return "text/plain"
    if path.endswith(".xml"):
        return "application/xml"
    if path.endswith(".json"):
        return "application/json"
    if "/.git" in path:
        return "text/plain"
    guess, _ = mimetypes.guess_type(path)
    return guess or "text/plain"


def register_decoy_routes(app: Flask, blueprint: DeceptionBlueprint) -> set[str]:
    """Register a route per breadcrumb. Returns the set of owned paths."""
    seen: set[str] = set()
    for crumb in blueprint.breadcrumbs:
        if crumb.path in seen:
            continue
        seen.add(crumb.path)

        decoy_file: Path = DECOY_DIR / crumb.path.lstrip("/")

        def make_view(p: Path = decoy_file, web_path: str = crumb.path):
            def view():
                g.is_breadcrumb = True
                if not p.exists():
                    return Response(f"# breadcrumb file missing: {web_path}\n", status=404,
                                    mimetype="text/plain")
                content = p.read_text(encoding="utf-8", errors="replace")
                return Response(content, status=200, mimetype=_guess_mime(web_path))
            view.__name__ = f"decoy_{abs(hash(web_path))}"
            return view

        app.add_url_rule(
            crumb.path,
            endpoint=f"decoy::{crumb.path}",
            view_func=make_view(),
            methods=["GET"],
        )
        logger.info("Registered decoy %s -> %s", crumb.path, decoy_file)

    if "/backup/" not in seen:
        @app.route("/backup/", methods=["GET"])
        def backup_dir_listing():
            g.is_breadcrumb = True
            items = []
            backup_dir = DECOY_DIR / "backup"
            if backup_dir.exists():
                items = sorted(p.name for p in backup_dir.iterdir())
            rows = "".join(f'<tr><td><a href="/backup/{i}">{i}</a></td></tr>' for i in items)
            html = f"""<html><head><title>Index of /backup/</title></head>
<body><h1>Index of /backup/</h1><table>{rows or '<tr><td>(empty)</td></tr>'}</table>
<hr><address>{blueprint.persona.server_header}</address></body></html>"""
            return Response(html, status=200, mimetype="text/html")
        seen.add("/backup/")
    return seen
