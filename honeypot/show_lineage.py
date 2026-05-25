"""Print the FP -> Strategy lineage so you can see exactly which classified
False Positive produced which honeypot trap.

Usage: python -m honeypot.show_lineage
"""
from __future__ import annotations

import json
from pathlib import Path

from honeypot.config import settings


def main():
    bp = json.loads(settings.blueprint_path.read_text(encoding="utf-8"))
    fps = json.loads(settings.fp_alerts_path.read_text(encoding="utf-8"))
    fp_by_id = {a["alert_id"]: a for a in fps}

    bar = "=" * 92
    sep = "-" * 92
    print(bar)
    print(f"  PERSONA: {bp['persona']['name']} ({bp['persona']['industry']})")
    print(f"  Stack: {', '.join(bp['persona']['tech_stack'])}")
    print(bar)
    print(f"  {len(bp['traps'])} TRAPS  |  {len(bp['honeytokens'])} HONEYTOKENS  "
          f"|  {len(bp['breadcrumbs'])} BREADCRUMBS")
    print(bar)

    for idx, t in enumerate(bp["traps"], 1):
        src = fp_by_id.get(t["source_fp_alert_id"], {})
        print(f"\n[{idx}] Strategy '{t['vuln_family']}' on {t['method']} {t['path']}")
        print(f"    Source ZAP False Positive:")
        print(f"      alert_id    : {t['source_fp_alert_id']}")
        print(f"      alert_type  : {src.get('alert_type', '(not found in fp_alerts.json)')}")
        print(f"      endpoint    : {src.get('endpoint', '?')}")
        print(f"      parameter   : {src.get('parameter', '?')}")
        print(f"      evidence    : {src.get('evidence', '?')}")
        print(f"      risk/conf   : {src.get('risk_level', '?')} / {src.get('confidence_level', '?')}")
        print(f"      classifier  : {src.get('source', '?')} -> {src.get('classification', '?')}")
        print(f"    Deception designed by Architect LLM:")
        print(f"      vuln_family : {t['vuln_family']}")
        print(f"      triggers    : {t['trigger_keywords']}")
        print(f"      decoy fallback (used if LLM unreachable):")
        print(f"        {t['decoy_template']}")
        print(f"      runtime LLM mutation prompt:")
        print(f"        {t['llm_mutation_prompt']}")
        if t.get("leaks_honeytoken_id"):
            print(f"      leaks honeytoken: {t['leaks_honeytoken_id']}")
        print(sep)

    print(f"\n{bar}")
    print("  HONEYTOKENS")
    print(bar)
    for h in bp["honeytokens"]:
        print(f"\n  token_id : {h['token_id']}  type={h['type']}")
        print(f"    username   : {h.get('username')}")
        print(f"    password   : {h.get('password')}")
        print(f"    leak_path  : {h['leak_path']}")
        print(f"    leak_method: {h['leak_method']}")
        print(f"    leak_hint  : {h['leak_hint']}")

    print(f"\n{bar}")
    print("  BREADCRUMBS (discovery breadcrumbs served on disk)")
    print(bar)
    for c in bp["breadcrumbs"]:
        print(f"\n  {c['kind']:18s} -> {c['path']}")
        print(f"    discovery_hint: {c['discovery_hint']}")
        print(f"    content:")
        for line in c["content"].splitlines():
            print(f"      | {line}")


if __name__ == "__main__":
    main()
