"""CLI: build the fake DB + honeytokens + breadcrumbs from the current blueprint.

Usage:
  python -m honeypot.run_generator
"""
from __future__ import annotations

import logging

from honeypot.generator.app_builder import build_all


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    bp = build_all()
    print(f"[+] Artifacts generated for blueprint {bp.blueprint_id} ({bp.persona.name})")


if __name__ == "__main__":
    main()
