#!/usr/bin/env python3
"""
start_honeypot.py
─────────────────
Run this INSTEAD of starting Cowrie directly.

It reads your BETH pipeline's honeypot_config.json,
picks the highest-priority FP scenario, sets the
correct environment variables, then launches Cowrie.

Usage:
  python start_honeypot.py                  # auto-picks top scenario
  python start_honeypot.py --scenario 3     # pick scenario by index
"""

import json
import os
import sys
import subprocess
import argparse

CONFIG_PATH  = "./BETH/data/honeypot_config.json"
COWRIE_PATH  = "/home/cowrie"                         # path to your Cowrie install
OLLAMA_URL   = "http://172.28.160.1:11434/api/generate"   # your WSL host IP
OLLAMA_MODEL = "honeypot-terminal"
COWRIE_COMMAND = "/home/cowrie/cowrie/cowrie-env/bin/cowrie"

def load_config() -> list:
    if not os.path.exists(CONFIG_PATH):
        print(f"[!] Config not found at {CONFIG_PATH}")
        print("    Run: python BETH/main_pipeline.py first")
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return json.load(f)


def pick_scenario(scenarios: list, index: int = 0) -> dict:
    """
    Scenarios are already sorted by count (most common FP first).
    The top scenario is the most impactful one to simulate.
    """
    if index >= len(scenarios):
        print(f"[!] Scenario index {index} out of range ({len(scenarios)} available)")
        sys.exit(1)
    return scenarios[index]


def build_fp_context(scenario: dict) -> str:
    label   = scenario.get("fp_label",  "benign")
    event   = scenario.get("eventId",   0)
    sim     = scenario.get("simulate",  "")
    htype   = scenario.get("honeypot_type", "cowrie_ssh")
    return (
        f"a Ubuntu 22.04 server exhibiting FP pattern: "
        f"{label} — {sim} (eventId={event}, type={htype})"
    )


def start_cowrie(fp_context: str):
    # Path to your virtual environment's bin folder
    VENV_BIN = "/home/cowrie/cowrie/cowrie-env/bin"
    COWRIE_COMMAND = os.path.join(VENV_BIN, "cowrie")

    env = os.environ.copy()
    env["OLLAMA_URL"]   = OLLAMA_URL
    env["OLLAMA_MODEL"] = OLLAMA_MODEL
    env["FP_CONTEXT"]   = fp_context
    env["AI_LOG_PATH"]  = os.path.join(COWRIE_PATH, "var/log/cowrie/ai_interactions.jsonl")

    # 1. FIX: This allows Cowrie's internal logic to find the 'twistd' engine
    env["PATH"] = f"{VENV_BIN}:{env.get('PATH', '')}"

    # 2. FIX: This tells Python where your custom AI-modified source code is
    # Without this, twistd won't recognize 'cowrie' as a command.
    env["PYTHONPATH"] = os.path.join(COWRIE_PATH, "src")

    print("\n=== Starting AI Cowrie Honeypot ===")
    print(f"  Ollama URL   : {OLLAMA_URL}")
    print(f"  Model        : {OLLAMA_MODEL}")
    print(f"  FP Context   : {fp_context}")
    print("===================================\n")

    try:
        # We use 'start' and remove '-n' to let it run correctly as a background process
        subprocess.run([COWRIE_COMMAND, "start"], env=env, cwd=COWRIE_PATH)
        print("[+] Cowrie started successfully in the background.")
        print("[+] Run 'tail -f var/log/cowrie/cowrie.log' to see live attacks!")
    except KeyboardInterrupt:
        print("\n[!] Stopping Honeypot...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", type=int, default=0,
                        help="Index of scenario from honeypot_config.json (default: 0 = top FP)")
    parser.add_argument("--list", action="store_true",
                        help="List all available scenarios and exit")
    args = parser.parse_args()

    scenarios = load_config()

    if args.list:
        print(f"Available scenarios ({len(scenarios)} total):\n")
        for i, s in enumerate(scenarios):
            print(f"  [{i}] label={s['fp_label']:15s} eventId={s['eventId']:5d}  "
                  f"count={s['count']:5d}  type={s['honeypot_type']}")
        sys.exit(0)

    scenario   = pick_scenario(scenarios, args.list or args.scenario)
    fp_context = build_fp_context(scenario)
    start_cowrie(fp_context)
