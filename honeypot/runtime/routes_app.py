"""Legitimate-looking routes: home, search, login, dashboard, profile, about, swagger.

These give the honeypot the appearance of a real production app so attackers spend
time crawling and fingerprinting before they realise.
"""
from __future__ import annotations

import random

from flask import Flask, render_template, request

from honeypot.architect.schema import DeceptionBlueprint
from honeypot.generator.fake_db import query_table


def register_app_routes(app: Flask, blueprint: DeceptionBlueprint,
                         reserved_paths: set[str] | None = None):
    """Register legit-looking routes. Skip any path already owned by a trap/decoy
    so an FP-flagged endpoint stays a trap, not a friendly page."""
    persona = blueprint.persona
    pages = blueprint.enabled_legit_pages
    table_names = {t.name for t in blueprint.fake_db}
    reserved = reserved_paths or set()

    def _has(name: str) -> bool:
        return name in table_names

    def _register(path: str, view, methods=("GET",), endpoint: str | None = None):
        if path in reserved:
            return
        app.add_url_rule(path, endpoint=endpoint or view.__name__,
                         view_func=view, methods=list(methods))

    def home():
        products = query_table("products", limit=8) if _has("products") else []
        return render_template("home.html", persona=persona, pages=pages, products=products)

    def about():
        return render_template("about.html", persona=persona, pages=pages)

    def search():
        q = request.args.get("q", "").strip()
        results = []
        if q and _has("products"):
            safe = q.replace("'", "''")
            results = query_table("products", where_sql=f"name LIKE '%{safe}%'", limit=15)
        return render_template("search.html", persona=persona, pages=pages, q=q, results=results)

    def login():
        error = None
        if request.method == "POST":
            error = "Invalid credentials."
        return render_template("login.html", persona=persona, pages=pages, error=error)

    def dashboard():
        orders = query_table("orders", limit=8) if _has("orders") else []
        stats = {
            "orders": random.randint(120, 980),
            "revenue": f"{random.randint(20_000, 180_000):,}",
            "users": random.randint(300, 4_000),
            "products": random.randint(40, 600),
        }
        return render_template("dashboard.html", persona=persona, pages=pages,
                               user="admin", orders=orders, stats=stats)

    def profile():
        rows = query_table("users", limit=1) if _has("users") else []
        user = rows[0] if rows else {"username": "guest", "email": "guest@example.com"}
        return render_template("profile.html", persona=persona, pages=pages, user=user)

    def swagger():
        endpoints = [{"method": t.method, "path": t.path,
                      "description": t.vuln_family.replace("_", " ")}
                     for t in blueprint.traps[:12]]
        return render_template("swagger.html", persona=persona, pages=pages, endpoints=endpoints)

    _register("/", home)
    _register("/about", about)
    _register("/search", search)
    _register("/login", login, methods=("GET", "POST"))
    _register("/dashboard", dashboard)
    _register("/profile", profile)
    _register("/api/docs", swagger)

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error_404.html", persona=persona, pages=pages,
                               path=request.path, host=request.host), 404
