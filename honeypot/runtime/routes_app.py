"""Legitimate-looking routes: home, search, login, dashboard, profile, about, swagger.

These give the honeypot the appearance of a real production app so attackers spend
time crawling and fingerprinting before they realise.
"""
from __future__ import annotations

import random

from flask import Flask, render_template, request

from honeypot.architect.schema import DeceptionBlueprint
from honeypot.generator.fake_db import query_table


def _resolve_table(blueprint: DeceptionBlueprint, candidates: list[str]) -> str | None:
    """Find a fake-DB table matching any of the candidates, tolerant to singular/plural
    and capitalisation. Returns the actual table name as defined in the blueprint."""
    available = {t.name.lower(): t.name for t in blueprint.fake_db}
    for c in candidates:
        variants = {c, c.rstrip("s"), c + "s"}
        for v in variants:
            if v.lower() in available:
                return available[v.lower()]
    return blueprint.fake_db[0].name if blueprint.fake_db else None


def register_app_routes(app: Flask, blueprint: DeceptionBlueprint,
                         reserved_paths: set[str] | None = None):
    """Register legit-looking routes. Skip any path already owned by a trap/decoy
    so an FP-flagged endpoint stays a trap, not a friendly page."""
    persona = blueprint.persona
    pages = blueprint.enabled_legit_pages
    reserved = reserved_paths or set()

    products_tbl = _resolve_table(blueprint, ["products", "product", "items", "catalog"])
    orders_tbl = _resolve_table(blueprint, ["orders", "order", "purchases"])
    users_tbl = _resolve_table(blueprint, ["users", "user", "customers", "customer", "accounts"])

    def _register(path: str, view, methods=("GET",), endpoint: str | None = None):
        if path in reserved:
            return
        app.add_url_rule(path, endpoint=endpoint or view.__name__,
                         view_func=view, methods=list(methods))

    def _adapt_products(rows: list[dict]) -> list[dict]:
        """Make any row look like a product so the template never breaks."""
        out = []
        for r in rows:
            out.append({
                "name": r.get("name") or r.get("product_name") or f"Item {r.get('id', '')}",
                "sku": str(r.get("sku") or r.get("uuid") or r.get("id", "00000000")),
                "price": r.get("price") or round(random.uniform(9.99, 499.99), 2),
            })
        return out

    def home():
        rows = query_table(products_tbl, limit=8) if products_tbl else []
        return render_template("home.html", persona=persona, pages=pages,
                               products=_adapt_products(rows))

    def about():
        return render_template("about.html", persona=persona, pages=pages)

    def search():
        q = request.args.get("q", "").strip()
        results = []
        if q and products_tbl:
            safe = q.replace("'", "''")
            try:
                results = query_table(products_tbl, where_sql=f"name LIKE '%{safe}%'", limit=15)
            except Exception:
                results = query_table(products_tbl, limit=15)
        elif products_tbl:
            results = query_table(products_tbl, limit=15)
        return render_template("search.html", persona=persona, pages=pages, q=q,
                               results=_adapt_products(results))

    def login():
        error = None
        if request.method == "POST":
            error = "Invalid credentials."
        return render_template("login.html", persona=persona, pages=pages, error=error)

    def dashboard():
        orders_rows = query_table(orders_tbl, limit=8) if orders_tbl else []
        orders = [{
            "id": r.get("id", "?"),
            "customer_email": r.get("customer_email") or r.get("email") or "customer@example.com",
            "total": r.get("total") or r.get("amount") or round(random.uniform(20, 800), 2),
            "created_at": r.get("created_at") or r.get("date") or "2026-05-01",
        } for r in orders_rows]
        stats = {
            "orders": random.randint(120, 980),
            "revenue": f"{random.randint(20_000, 180_000):,}",
            "users": random.randint(300, 4_000),
            "products": random.randint(40, 600),
        }
        return render_template("dashboard.html", persona=persona, pages=pages,
                               user="admin", orders=orders, stats=stats)

    def profile():
        rows = query_table(users_tbl, limit=1) if users_tbl else []
        raw = rows[0] if rows else {}
        user = {
            "username": raw.get("username") or raw.get("name") or "guest",
            "email": raw.get("email") or "guest@example.com",
        }
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
