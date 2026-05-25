"""CLI: generate the deception blueprint from ZAP fp_alerts.json.

Usage:
  python -m honeypot.run_architect                 # uses ZAP/fp_alerts.json
  python -m honeypot.run_architect --fp other.json
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from honeypot.architect.architect import generate_blueprint, load_fp_alerts, save_blueprint


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--fp", type=Path, default=None,
                        help="Path to fp_alerts.json (default: ZAP/fp_alerts.json)")
    parser.add_argument("--out", type=Path, default=None,
                        help="Output blueprint JSON path")
    args = parser.parse_args()

    alerts = load_fp_alerts(args.fp)
    if not alerts:
        print("No FP alerts to process. Run the ZAP classifier first.")
        sys.exit(1)

    print(f"[*] Loaded {len(alerts)} FP alerts. Asking the Architect LLM...")
    bp = generate_blueprint(alerts)
    out = save_blueprint(bp, args.out)
    print(f"[+] Blueprint generated: {out}")
    print(f"    persona={bp.persona.name}  traps={len(bp.traps)}  "
          f"honeytokens={len(bp.honeytokens)}  breadcrumbs={len(bp.breadcrumbs)}")


if __name__ == "__main__":
    main()
