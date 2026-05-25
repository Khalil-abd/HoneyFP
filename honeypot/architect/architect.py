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


def deduplicate_fps(alerts: list[dict], max_per_combo: int = 1, top_k: int = 12) -> list[dict]:
    """Keep the most common (endpoint, alert_type) combos to keep the prompt small."""
    counter: Counter = Counter()
    bucket: dict[tuple[str, str], dict] = {}
    for a in alerts:
        key = (a.get("endpoint", "/"), a.get("alert_type", "unknown"))
        counter[key] += 1
        bucket.setdefault(key, a)
    most_common = counter.most_common(top_k)
    return [dict(bucket[k], occurrences=c) for k, c in most_common]


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
        max_tokens=8000,
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

    schema_json = json.dumps(DeceptionBlueprint.model_json_schema(), indent=2)[:6000]
    user_prompt = ARCHITECT_USER_TEMPLATE.format(
        fp_json=json.dumps(deduped, indent=2),
        schema_json=schema_json,
    )

    raw = _llm_call(ARCHITECT_SYSTEM, user_prompt)
    data = json.loads(raw)
    data.setdefault("blueprint_id", f"bp-{uuid.uuid4().hex[:8]}")

    try:
        return DeceptionBlueprint.model_validate(data)
    except ValidationError as e:
        logger.warning("LLM output failed validation, applying repair heuristics. Error: %s", e)
        return _repair_blueprint(data, deduped)


def _repair_blueprint(data: dict, fp_alerts: list[dict]) -> DeceptionBlueprint:
    """Best-effort fixer when the LLM omits required fields.

    Most failure modes are: missing token_id, missing breadcrumbs, or traps without
    leaks_honeytoken_id linkage. We fill them deterministically rather than throwing.
    """
    persona = AppPersona(**(data.get("persona") or {
        "name": "Northwind Shop",
        "tagline": "Quality goods, delivered fast.",
        "industry": "e-commerce",
        "tech_stack": ["Apache 2.4.41", "PHP 7.4", "MySQL 5.7"],
    }))

    tables = [FakeTable.model_validate(t) for t in (data.get("fake_db") or _default_tables())]
    traps_raw = data.get("traps") or _default_traps_from_fp(fp_alerts)
    traps = [TrapEndpoint.model_validate(t) for t in traps_raw]

    tokens_raw = data.get("honeytokens") or []
    if not any(t.get("type") == "ssh_credentials" for t in tokens_raw):
        tokens_raw.append({
            "token_id": f"ht-{uuid.uuid4().hex[:8]}",
            "type": "ssh_credentials",
            "username": "deploy",
            "password": "Pr0d-S3rv3r!#2026",
            "leak_path": "/backup/db_backup_2026-04.tar.gz",
            "leak_method": "backup_file",
            "leak_hint": "Hinted at by a Disallow line in /robots.txt",
        })
    for t in tokens_raw:
        t.setdefault("token_id", f"ht-{uuid.uuid4().hex[:8]}")
    tokens = [Honeytoken.model_validate(t) for t in tokens_raw]

    crumbs_raw = data.get("breadcrumbs") or _default_breadcrumbs(tokens)
    crumbs = [Breadcrumb.model_validate(c) for c in crumbs_raw]

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
