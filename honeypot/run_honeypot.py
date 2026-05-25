"""CLI: start the Flask honeypot.

Usage:
  python -m honeypot.run_honeypot
"""
from __future__ import annotations

import logging

from honeypot.config import settings
from honeypot.runtime.app import create_app


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    app = create_app()
    print(f"[+] Honeypot ready on http://{settings.flask_host}:{settings.flask_port}")
    print(f"    interactions log : {settings.interactions_log}")
    print(f"    honeytoken leaks : {settings.leak_log}")
    app.run(host=settings.flask_host, port=settings.flask_port, debug=settings.flask_debug,
            use_reloader=False)


if __name__ == "__main__":
    main()
