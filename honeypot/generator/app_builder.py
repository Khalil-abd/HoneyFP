"""Orchestrate generation: blueprint → fake DB + honeytokens + breadcrumbs."""
from __future__ import annotations

import logging

from honeypot.architect.architect import load_blueprint
from honeypot.generator.breadcrumbs import materialise_breadcrumbs
from honeypot.generator.fake_db import build_fake_db
from honeypot.generator.honeytokens import export_honeytokens

logger = logging.getLogger(__name__)


def build_all():
    bp = load_blueprint()
    logger.info("Building artifacts from blueprint '%s' (persona=%s)", bp.blueprint_id, bp.persona.name)
    build_fake_db(bp)
    export_honeytokens(bp)
    materialise_breadcrumbs(bp)
    logger.info("Generation complete.")
    return bp
