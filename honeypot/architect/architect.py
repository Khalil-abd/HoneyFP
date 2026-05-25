"""Architect: consume fp_alerts.json, ask the LLM for a DeceptionBlueprint."""
from __future__ import annotations

import json
import logging
import uuid
from collections import Counter
from pathlib import Path

from pydantic import ValidationError

from honeypot.architect.prompts import ARCHITECT_SYSTEM, ARCHITECT_USER_TEMPLATE
from honeypot.architect.schema import (
    AppPersona,
    Breadcrumb,
    DeceptionBlueprint,
    FakeColumn,
    FakeTable,
    Honeytoken,
    TrapEndpoint,
)
from honeypot.config import settings

logger = logging.getLogger(__name__)


# ---------- FP loading & deduplication ----------
def load_fp_alerts(path: Path | None = None) -> list[dict]:
    path = path or settings.fp_alerts_path
    if not path.exists():
        raise FileNotFoundError(f"FP alerts not found at {path}. Run the ZAP classifier first.")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def deduplicate_fps(alerts: list[dict], max_per_combo: int = 1, top_k: int = 5) -> list[dict]:
    """Keep the most common (endpoint, alert_type) combos to keep the prompt small.
    Trim each alert to the minimal fields the Architect actually needs."""
    counter: Counter = Counter()
    bucket: dict[tuple[str, str], dict] = {}
    for a in alerts:
        key = (a.get("endpoint", "/"), a.get("alert_type", "unknown"))
        counter[key] += 1
        bucket.setdefault(key, a)
    most_common = counter.most_common(top_k)
    keep_fields = ("alert_id", "alert_type", "endpoint", "parameter", "evidence")
    out = []
    for k, c in most_common:
        a = bucket[k]
        trimmed = {f: a.get(f, "") for f in keep_fields}
        trimmed["occurrences"] = c
        out.append(trimmed)
    return out


# ---------- LLM call ----------
def _call_groq(system_prompt: str, user_prompt: str) -> str:
    from groq import Groq

    if not settings.groq_api_key:
        raise RuntimeError("GROQ_API_KEY is empty. Set it in your .env file.")
    client = Groq(api_key=settings.groq_api_key)
    completion = client.chat.completions.create(
        model=settings.groq_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.6,
        response_format={"type": "json_object"},
        max_tokens=2500,
    )
    return completion.choices[0].message.content


def _call_ollama(system_prompt: str, user_prompt: str) -> str:
    import requests

    payload = {
        "model": settings.ollama_model,
        "prompt": f"{system_prompt}\n\n{user_prompt}",
        "format": "json",
        "stream": False,
    }
    r = requests.post(settings.ollama_url, json=payload, timeout=120)
    r.raise_for_status()
    return r.json().get("response", "{}")


def _llm_call(system_prompt: str, user_prompt: str) -> str:
    if settings.architect_provider == "groq":
        return _call_groq(system_prompt, user_prompt)
    return _call_ollama(system_prompt, user_prompt)


# ---------- Blueprint generation ----------
def generate_blueprint(fp_alerts: list[dict]) -> DeceptionBlueprint:
    deduped = deduplicate_fps(fp_alerts)
    logger.info("Architect: %d unique FP combinations selected", len(deduped))

    user_prompt = ARCHITECT_USER_TEMPLATE.format(
        fp_json=json.dumps(deduped, indent=2),
    )

    raw = _llm_call(ARCHITECT_SYSTEM, user_prompt)
    data = json.loads(raw)
    data.setdefault("blueprint_id", f"bp-{uuid.uuid4().hex[:8]}")

    try:
        return DeceptionBlueprint.model_validate(data)
    except ValidationError as e:
        logger.warning("LLM output failed validation, applying repair heuristics. Error: %s", e)
        return _repair_blueprint(data, deduped)


SQL_TYPE_MAP = {
    "FLOAT": "REAL", "DOUBLE": "REAL", "DECIMAL": "REAL", "NUMERIC": "REAL",
    "VARCHAR": "TEXT", "CHAR": "TEXT", "STRING": "TEXT",
    "INT": "INTEGER", "BIGINT": "INTEGER", "SMALLINT": "INTEGER", "BOOLEAN": "INTEGER",
    "DATETIME": "TEXT", "DATE": "TEXT", "TIMESTAMP": "TEXT", "JSON": "TEXT",
}

VALID_VULN_FAMILIES = {
    "sql_injection", "reflected_xss", "stored_xss", "open_redirect",
    "private_ip_disclosure", "info_disclosure_debug", "directory_browsing",
    "path_traversal", "ssrf", "broken_auth", "csrf", "command_injection",
    "generic_500",
}
VALID_BREADCRUMB_KINDS = {
    "robots_txt", "sitemap_xml", "env_file", "backup_archive",
    "git_config", "git_head", "swagger_doc", "directory_listing", "html_comment_hint",
}
VALID_LEAK_METHODS = {
    "robots_txt", "backup_file", "env_file", "git_config",
    "html_comment", "api_error_message", "directory_listing", "swagger_doc",
}


def _normalize_table(t: dict) -> dict:
    cols = t.get("columns") or []
    for c in cols:
        sql_type = (c.get("sql_type") or "TEXT").upper()
        c["sql_type"] = SQL_TYPE_MAP.get(sql_type, sql_type if sql_type in
                                         {"INTEGER", "TEXT", "REAL", "BLOB"} else "TEXT")
        c.setdefault("primary_key", False)
        c.setdefault("faker_provider", "word")
    t["columns"] = cols
    t.setdefault("row_count", 50)
    return t


def _normalize_trap(t: dict) -> dict:
    fam = (t.get("vuln_family") or "generic_500").lower()
    if fam not in VALID_VULN_FAMILIES:
        fam = "generic_500"
    t["vuln_family"] = fam
    t.setdefault("method", "GET")
    t.setdefault("trigger_keywords", [])
    t.setdefault("decoy_template", "Internal Server Error")
    t.setdefault("llm_mutation_prompt",
                 "You impersonate a vulnerable backend. Emit only the raw HTTP body.")
    return t


def _normalize_breadcrumb(c: dict) -> dict:
    kind = (c.get("kind") or "robots_txt").lower()
    if kind not in VALID_BREADCRUMB_KINDS:
        kind = "html_comment_hint"
    c["kind"] = kind
    return c


def _normalize_token(t: dict) -> dict:
    method = (t.get("leak_method") or "backup_file").lower()
    if method not in VALID_LEAK_METHODS:
        method = "backup_file"
    t["leak_method"] = method
    t.setdefault("token_id", f"ht-{uuid.uuid4().hex[:8]}")
    t.setdefault("extra", {})
    return t


def _safe_validate(model_cls, items: list[dict]) -> list:
    """Validate a list of dicts against a Pydantic model, skipping invalid items."""
    out = []
    for item in items:
        try:
            out.append(model_cls.model_validate(item))
        except ValidationError as e:
            logger.debug("Skipping invalid %s item: %s", model_cls.__name__, e)
    return out


def _repair_blueprint(data: dict, fp_alerts: list[dict]) -> DeceptionBlueprint:
    """Best-effort fixer. Normalises common LLM mistakes, skips invalid items,
    and falls back to sensible defaults when entire sections are missing."""
    try:
        persona = AppPersona.model_validate(data.get("persona") or {})
    except ValidationError:
        persona = AppPersona(
            name="Northwind Shop", tagline="Quality goods, delivered fast.",
            industry="e-commerce",
            tech_stack=["Apache 2.4.41", "PHP 7.4", "MySQL 5.7"],
        )

    tables = _safe_validate(FakeTable, [_normalize_table(t)
                                        for t in (data.get("fake_db") or _default_tables())])
    if not tables:
        tables = _safe_validate(FakeTable, [_normalize_table(t) for t in _default_tables()])

    traps_raw = data.get("traps") or _default_traps_from_fp(fp_alerts)
    traps = _safe_validate(TrapEndpoint, [_normalize_trap(t) for t in traps_raw])
    if not traps:
        traps = _safe_validate(TrapEndpoint,
                               [_normalize_trap(t) for t in _default_traps_from_fp(fp_alerts)])

    tokens_raw = list(data.get("honeytokens") or [])
    if not any(t.get("type") == "ssh_credentials" for t in tokens_raw):
        tokens_raw.append({
            "token_id": f"ht-{uuid.uuid4().hex[:8]}", "type": "ssh_credentials",
            "username": "deploy", "password": "Pr0d-S3rv3r!#2026",
            "leak_path": "/backup/db_backup_2026-04.tar.gz",
            "leak_method": "backup_file",
            "leak_hint": "Hinted at by a Disallow line in /robots.txt",
        })
    tokens = _safe_validate(Honeytoken, [_normalize_token(t) for t in tokens_raw])

    crumbs_raw = data.get("breadcrumbs") or _default_breadcrumbs(tokens)
    crumbs = _safe_validate(Breadcrumb, [_normalize_breadcrumb(c) for c in crumbs_raw])
    if not crumbs:
        crumbs = _safe_validate(Breadcrumb,
                                [_normalize_breadcrumb(c) for c in _default_breadcrumbs(tokens)])

    return DeceptionBlueprint(
        blueprint_id=data.get("blueprint_id", f"bp-{uuid.uuid4().hex[:8]}"),
        persona=persona,
        fake_db=tables,
        traps=traps,
        honeytokens=tokens,
        breadcrumbs=crumbs,
        enabled_legit_pages=data.get("enabled_legit_pages") or
            ["home", "login", "dashboard", "search", "profile", "about"],
    )


# ---------- Deterministic fallbacks ----------
def _default_tables() -> list[dict]:
    return [
        {
            "name": "users",
            "row_count": 50,
            "columns": [
                {"name": "id", "sql_type": "INTEGER", "faker_provider": "pyint", "primary_key": True},
                {"name": "username", "sql_type": "TEXT", "faker_provider": "user_name"},
                {"name": "email", "sql_type": "TEXT", "faker_provider": "email"},
                {"name": "password_hash", "sql_type": "TEXT", "faker_provider": "password"},
            ],
        },
        {
            "name": "products",
            "row_count": 80,
            "columns": [
                {"name": "id", "sql_type": "INTEGER", "faker_provider": "pyint", "primary_key": True},
                {"name": "name", "sql_type": "TEXT", "faker_provider": "product_name"},
                {"name": "price", "sql_type": "REAL", "faker_provider": "price"},
                {"name": "sku", "sql_type": "TEXT", "faker_provider": "uuid4"},
            ],
        },
        {
            "name": "orders",
            "row_count": 40,
            "columns": [
                {"name": "id", "sql_type": "INTEGER", "faker_provider": "pyint", "primary_key": True},
                {"name": "customer_email", "sql_type": "TEXT", "faker_provider": "email"},
                {"name": "total", "sql_type": "REAL", "faker_provider": "price"},
                {"name": "created_at", "sql_type": "TEXT", "faker_provider": "date_time"},
            ],
        },
    ]


def _default_traps_from_fp(fp_alerts: list[dict]) -> list[dict]:
    family_map = {
        "SQL Injection": "sql_injection",
        "Injection SQL": "sql_injection",
        "Cross Site Scripting (Reflected)": "reflected_xss",
        "Private IP Disclosure": "private_ip_disclosure",
        "Directory Browsing": "directory_browsing",
        "Information Disclosure - Debug Error Messages": "info_disclosure_debug",
    }
    out: list[dict] = []
    for a in fp_alerts:
        fam = family_map.get(a.get("alert_type", ""), "generic_500")
        out.append({
            "path": a.get("endpoint", "/unknown"),
            "method": "GET",
            "parameter": a.get("parameter") or None,
            "vuln_family": fam,
            "source_fp_alert_id": a.get("alert_id", "ZAP-?"),
            "trigger_keywords": [],
            "decoy_template": "Internal Server Error: {payload}",
            "llm_mutation_prompt": (
                "You impersonate the backend server. Emit only the raw HTTP body that a real "
                "vulnerable server of this family would emit when receiving the attacker payload. "
                "Stay terse, technical, and never address the user."
            ),
        })
    return out


def _default_breadcrumbs(tokens: list[Honeytoken]) -> list[dict]:
    ssh_token = next((t for t in tokens if t.type == "ssh_credentials"), None)
    leak_path = ssh_token.leak_path if ssh_token else "/backup/db_backup.tar.gz"
    return [
        {
            "kind": "robots_txt",
            "path": "/robots.txt",
            "content": (
                "User-agent: *\n"
                "Disallow: /admin\n"
                "Disallow: /backup/\n"
                "Disallow: /.git/\n"
                f"Disallow: {leak_path}\n"
            ),
            "discovery_hint": "Standard /robots.txt fuzz",
        },
        {
            "kind": "git_config",
            "path": "/.git/config",
            "content": (
                "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
                "[remote \"origin\"]\n\turl = git@gitlab.internal:platform/api.git\n"
            ),
            "discovery_hint": "Common dirbuster wordlist entry",
        },
    ]


# ---------- Persistence ----------
def save_blueprint(bp: DeceptionBlueprint, path: Path | None = None) -> Path:
    path = path or settings.blueprint_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write(bp.model_dump_json(indent=2))
    logger.info("Blueprint saved to %s", path)
    return path


def load_blueprint(path: Path | None = None) -> DeceptionBlueprint:
    path = path or settings.blueprint_path
    with path.open(encoding="utf-8") as f:
        return DeceptionBlueprint.model_validate_json(f.read())
