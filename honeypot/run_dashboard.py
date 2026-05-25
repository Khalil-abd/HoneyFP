"""CLI: start the Streamlit dashboard.

Usage:
  python -m honeypot.run_dashboard
  # equivalent to: streamlit run honeypot/dashboard/app.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main():
    target = Path(__file__).resolve().parent / "dashboard" / "app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(target)]
    print(f"[+] Launching: {' '.join(cmd)}")
    subprocess.run(cmd, check=False)


if __name__ == "__main__":
    main()
