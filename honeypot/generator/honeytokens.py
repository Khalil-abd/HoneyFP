"""Persist honeytokens to disk so the SSH bridge and Cowrie can read them."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from honeypot.architect.schema import DeceptionBlueprint, Honeytoken
from honeypot.config import settings

logger = logging.getLogger(__name__)


def export_honeytokens(blueprint: DeceptionBlueprint) -> Path:
    payload = [t.model_dump() for t in blueprint.honeytokens]
    settings.honeytoken_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    ssh_creds = [t for t in blueprint.honeytokens if t.type == "ssh_credentials"]
    if ssh_creds:
        settings.cowrie_credentials_file.parent.mkdir(parents=True, exist_ok=True)
        settings.cowrie_credentials_file.write_text(
            json.dumps([{"username": c.username, "password": c.password,
                         "token_id": c.token_id} for c in ssh_creds], indent=2),
            encoding="utf-8",
        )
        logger.info("Exported %d SSH honeytoken(s) for Cowrie bridge", len(ssh_creds))
    return settings.honeytoken_path


def find_token_in_text(text: str, tokens: list[Honeytoken]) -> Honeytoken | None:
    """Detect if a generated response accidentally (or intentionally) leaks a honeytoken."""
    for t in tokens:
        needles = [t.token_id]
        if t.password:
            needles.append(t.password)
        if t.username and len(t.username) > 4:
            needles.append(t.username)
        for n in needles:
            if n and n in text:
                return t
    return None
