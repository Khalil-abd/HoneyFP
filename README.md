# HoneyFP — DAST False Positives as Honeypot Fuel

HoneyFP turns the *False Positives* of a DAST scanner (OWASP ZAP) and a
kernel-level IDS (BETH) into an **adaptive, LLM-driven honeypot** that ships in
a DevSecOps pipeline.

Most teams discard FPs. We use them as *intent maps*: if the scanner thought
there was a vuln there, attackers will probably look there too. So we build
the trap exactly there.

```
┌──────────┐   ┌─────────────────┐   ┌──────────────┐   ┌──────────────────┐
│ OWASP    │──▶│ FP classifier   │──▶│ Architect    │──▶│ Deception        │
│ ZAP scan │   │ (parse_zap.py / │   │ LLM (Groq)   │   │ Blueprint (JSON) │
└──────────┘   │ Isolation Forest│   └──────────────┘   └─────────┬────────┘
               │  - rules engine)│                                │
               └─────────────────┘                                ▼
                                                        ┌──────────────────┐
                                                        │ Generator        │
                                                        │  • fake DB       │
                                                        │  • honeytokens   │
                                                        │  • breadcrumbs   │
                                                        └─────────┬────────┘
                                                                  ▼
                              ┌────────────────────────────────────────────┐
                              │ Flask Runtime                              │
                              │  • realistic UI (login/search/dashboard…)  │
                              │  • one trap route per FP                   │
                              │  • LLM responder (Ollama) mutates bodies   │
                              │  • per-attacker session/profile/tarpit     │
                              │  • SSH bridge → Cowrie honeypot            │
                              └────────────────────┬───────────────────────┘
                                                   ▼
                                      ┌─────────────────────────┐
                                      │ Streamlit Dashboard     │
                                      └─────────────────────────┘
```

## Repository layout

```
HoneyFP/
├── BETH/                 # Kernel-IDS pipeline → Cowrie SSH honeypot (unchanged)
├── ZAP/                  # ZAP report → fp_alerts.json classifier (unchanged)
├── honeypot/             # ⬅ new: web honeypot
│   ├── architect/        # FP → Blueprint (Groq)
│   ├── generator/        # Blueprint → SQLite + honeytokens + decoys + HTML
│   ├── runtime/          # Flask + responder + tarpit + profiler + SSH bridge
│   ├── dashboard/        # Streamlit analyst UI
│   ├── data/             # Generated artifacts + logs
│   ├── run_architect.py  # CLI: generate blueprint
│   ├── run_generator.py  # CLI: build artifacts
│   ├── run_honeypot.py   # CLI: serve honeypot
│   └── run_dashboard.py  # CLI: serve dashboard
├── .env.example
└── start_honeypot.py     # legacy Cowrie launcher (unchanged)
```

## Quick start

```bash
# 1) Install dependencies
pip install -r honeypot/requirements.txt

# 2) Copy and edit env file (put your GROQ_API_KEY)
cp .env.example .env

# 3) Make sure ZAP/fp_alerts.json exists (already classified)
ls ZAP/fp_alerts.json

# 4) Generate the deception blueprint (one LLM call)
python -m honeypot.run_architect

# 5) Materialise the artifacts (fake DB + honeytokens + breadcrumbs)
python -m honeypot.run_generator

# 6) Start the honeypot
python -m honeypot.run_honeypot

# 7) In another terminal, start the analyst dashboard
python -m honeypot.run_dashboard
```

Then browse `http://localhost:5000` and watch the dashboard at
`http://localhost:8501`.

## Deception strategies implemented

| # | Strategy                              | What it does                                                                 |
|---|---------------------------------------|------------------------------------------------------------------------------|
| 1 | Realistic app shell                   | Home/login/dashboard/search/profile/about render real HTML & fake data       |
| 2 | FP-driven trap routes                 | Every FP becomes a route that simulates the suspected vuln family            |
| 3 | LLM mutated responses                 | Ollama mutates the body per attacker payload, with LRU caching               |
| 4 | Multi-hop SSH credential leak         | `/robots.txt` → `/.git/` or `/backup/` → archive containing SSH user/pass    |
| 5 | Unique honeytoken IDs                 | Each token has an embedded id so we trace exfiltration                       |
| 6 | Decoy directory listing               | `/backup/` returns an Apache-style index                                     |
| 7 | Adaptive tarpit                       | Delay grows with `trap_hits + breadcrumb_hits`                               |
| 8 | Attacker profiling                    | UA fingerprinting + behavioural classifier (sqlmap, nuclei, manual, …)       |
| 9 | Session tracking                      | Per-fingerprint stream replayable in the dashboard                           |
| 10| SSH bridge to Cowrie                  | When a leak fires, append a JSONL record consumable by `start_honeypot.py`   |
| 11| Forensic JSONL log                    | Every request logged with payload, profile, status, latency, leak           |
| 12| Server header spoofing                | Apache/PHP banners injected in every response                                |

## Roadmap (next-iteration ideas)

- **Feedback loop**: re-train the FP classifier with traps that actually attracted humans.
- **Per-session canary**: derive a token per attacker so attribution survives leaks.
- **Network-level isolation**: run the Flask app in a read-only Docker container.
- **WAF emulation**: deceptive 403/406 responses to mimic Cloudflare/Akamai.
- **gRPC / GraphQL surface**: generate decoy schemas alongside REST.

## Security note

This is a honeypot. **Do not run it on a network where you don't control the
egress**. Even fake SQLi and reflected XSS responses can be misused against
other systems. Run inside a sandboxed VM or container.
