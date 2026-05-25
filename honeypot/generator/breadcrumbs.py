"""Materialise breadcrumb files (robots.txt, .env, /backup/, etc.) on disk.

The runtime serves them from `settings.DECOY_DIR`. Each breadcrumb may embed a
honeytoken so we wire that in here too.
"""
from __future__ import annotations

import logging
from pathlib import Path

from honeypot.architect.schema import Breadcrumb, DeceptionBlueprint, Honeytoken
from honeypot.config import DECOY_DIR

logger = logging.getLogger(__name__)


def _enrich_with_token(content: str, tokens: list[Honeytoken]) -> str:
    """Replace placeholders {SSH_USER}/{SSH_PASS}/{TOKEN_ID} when present."""
    ssh = next((t for t in tokens if t.type == "ssh_credentials"), None)
    if ssh:
        content = (
            content.replace("{SSH_USER}", ssh.username or "deploy")
            .replace("{SSH_PASS}", ssh.password or "ChangeMe!")
            .replace("{TOKEN_ID}", ssh.token_id)
        )
    aws = next((t for t in tokens if t.type == "aws_key"), None)
    if aws:
        content = content.replace("{AWS_KEY}", aws.extra.get("access_key", "AKIAFAKE"))
        content = content.replace("{AWS_SECRET}", aws.extra.get("secret_key", "SECRETFAKE"))
    return content


def _ensure_ssh_payload_inside(crumb: Breadcrumb, tokens: list[Honeytoken]) -> str:
    """For backup/env-like files, force the SSH creds to appear so the breadcrumb is exploitable."""
    ssh = next((t for t in tokens if t.type == "ssh_credentials"), None)
    if not ssh:
        return crumb.content
    if crumb.kind in {"env_file", "backup_archive"} and ssh.password not in crumb.content:
        return (
            crumb.content.rstrip()
            + f"\n# legacy deploy credentials, do NOT use\nSSH_USER={ssh.username}\nSSH_PASS={ssh.password}\nDEPLOY_TOKEN={ssh.token_id}\n"
        )
    return crumb.content


def materialise_breadcrumbs(blueprint: DeceptionBlueprint) -> list[Path]:
    """Write each breadcrumb's content under DECOY_DIR/<path>."""
    written: list[Path] = []
    for crumb in blueprint.breadcrumbs:
        content = _enrich_with_token(crumb.content, blueprint.honeytokens)
        content = _ensure_ssh_payload_inside(
            Breadcrumb(**{**crumb.model_dump(), "content": content}),
            blueprint.honeytokens,
        )
        rel_path = crumb.path.lstrip("/")
        if not rel_path:
            continue
        out = DECOY_DIR / rel_path
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(content, encoding="utf-8")
        written.append(out)
    logger.info("Materialised %d breadcrumb files under %s", len(written), DECOY_DIR)
    return written
