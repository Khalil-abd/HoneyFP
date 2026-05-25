# HoneyFP — DAST False Positives as Honeypot Fuel

HoneyFP turns the **False Positives** of a DAST scanner (OWASP ZAP) and a
kernel-level IDS (BETH dataset) into an **adaptive, LLM-driven honeypot** that
ships in a DevSecOps pipeline.

Most teams discard FPs. We use them as *intent maps*: if the scanner thought
there was a vuln at `/profile?url=`, attackers will probably look there too.
So we build the trap exactly there — with a believable web app around it, a
leakable SSH credential as bait, and an SSH honeypot (Cowrie) at the other
end of the leak.

---

## Table of contents

1. [Architecture](#architecture)
2. [Repository layout](#repository-layout)
3. [Quick start](#quick-start)
4. [Guided testing](#guided-testing) — step-by-step scenarios
5. [The three analyst views](#the-three-analyst-views)
6. [Deception strategies implemented](#deception-strategies-implemented)
7. [Configuration reference](#configuration-reference)
8. [Roadmap](#roadmap)
9. [Security note](#security-note)

---

## Architecture

Two parallel pipelines (web + SSH) converge through a credential bridge.

### How the two pipelines meet

The web honeypot writes `honeypot/data/ssh_credentials.json` whenever an SSH
honeytoken is generated. An attacker who fuzzes the web app discovers those
creds in `/backup/db.tar.gz`. When they later `ssh deploy@target` with the
same credentials, Cowrie (configured via `start_honeypot.py`) accepts the
login and the AI bash shell (`Modelfile.terminal`) takes over — giving us a
full behavioural recording on both surfaces.

---

## Repository layout

```
HoneyFP/
├── BETH/                       Kernel-IDS pipeline (existing) → Cowrie SSH
│   ├── main_pipeline.py        Runs the 7 steps end-to-end
│   ├── train_model.py          Isolation Forest on BETH dataset
│   ├── fp_identification.py    TP / FP / FN / TN labelling
│   ├── llm_analysis.py         Ollama analyst (honeypot-analyst model)
│   ├── honeypot_config.py      Produces honeypot_config.json
│   ├── Modelfile.terminal      Ollama model: AI bash shell for Cowrie
│   └── Modelfile.analyst       Ollama model: FP explainer
│
├── ZAP/                        DAST classifier (existing) → web pipeline
│   ├── parse_zap.py            ZAP report → rule-based FP/TP
│   ├── advanced_fp_classifier.py  Isolation Forest classifier
│   ├── fp_alerts.json          ← INPUT consumed by the web honeypot
│   └── (legacy strategy_generator.py + web_honeypot.py replaced by /honeypot)
│
├── honeypot/                   ★ Web honeypot (new)
│   ├── config.py               pydantic-settings, all secrets from .env
│   │
│   ├── architect/              Blueprint generation (offline)
│   │   ├── schema.py           Pydantic models: DeceptionBlueprint
│   │   ├── prompts.py          Architect LLM prompts (versioned)
│   │   └── architect.py        Groq call + defensive repair
│   │
│   ├── generator/              Blueprint → concrete artifacts
│   │   ├── fake_db.py          SQLite + Faker
│   │   ├── honeytokens.py      Export + leak-detection helper
│   │   ├── breadcrumbs.py      Materialise robots.txt, .env, /backup/...
│   │   ├── app_builder.py      Orchestrator
│   │   └── templates/          Jinja: base/home/login/dashboard/search/
│   │                            profile/about/swagger/error_404/admin_strategies
│   │
│   ├── runtime/                Flask app
│   │   ├── app.py              Factory + request instrumentation
│   │   ├── routes_app.py       Legit-looking pages (table-name tolerant)
│   │   ├── routes_traps.py     1 route per FP; benign fallback if no payload
│   │   ├── routes_decoys.py    Breadcrumbs + /backup/ directory listing
│   │   ├── routes_admin.py     /_internal/strategies (localhost only)
│   │   ├── responder.py        Ollama or Groq, LRU-cached
│   │   ├── session_tracker.py  In-memory fingerprint store
│   │   ├── attacker_profiler.py  sqlmap / nuclei / automated_fuzzer / …
│   │   ├── tarpit.py           Adaptive delay (hostile sessions only)
│   │   └── bridge_ssh.py       Signal leaks + export Cowrie creds
│   │
│   ├── dashboard/app.py        Streamlit (Live activity + Strategies tab)
│   ├── data/                   Generated artifacts (gitignored)
│   │   ├── blueprints/         current_blueprint.json
│   │   ├── decoys/             robots.txt · backup/db.tar.gz · .git/config
│   │   ├── logs/               interactions.jsonl · honeytoken_leaks.jsonl
│   │   ├── fake_app.sqlite     Generated DB
│   │   └── honeytokens.json    Generated tokens
│   │
│   ├── show_lineage.py         CLI: FP → trap mapping
│   ├── run_architect.py        CLI: generate blueprint
│   ├── run_generator.py        CLI: build artifacts
│   ├── run_honeypot.py         CLI: serve Flask
│   ├── run_dashboard.py        CLI: serve Streamlit
│   └── requirements.txt
│
├── start_honeypot.py           SSH honeypot launcher (existing, unchanged)
├── .env.example                Template (copy to .env, never commit)
├── .gitignore
└── README.md
```

---

## Quick start

```bash
# 1) Install dependencies
pip install -r honeypot/requirements.txt

# 2) Copy the env file and put your Groq API key
cp .env.example .env
# edit .env: set GROQ_API_KEY=gsk_...

# 3) Confirm the ZAP classifier has produced FP alerts
ls ZAP/fp_alerts.json     # should exist

# 4) Generate the deception blueprint (one Groq call, ~3-5 seconds)
python -m honeypot.run_architect

# 5) Materialise the artifacts (fake DB + honeytokens + breadcrumbs on disk)
python -m honeypot.run_generator

# 6) Start the honeypot (terminal A)
python -m honeypot.run_honeypot

# 7) Start the analyst dashboard (terminal B)
python -m honeypot.run_dashboard
```

Browse:

| URL                                              | What                          |
|--------------------------------------------------|-------------------------------|
| http://localhost:5000                            | Fake app (attacker side)      |
| http://localhost:5000/_internal/strategies        | Admin: FP → trap lineage      |
| http://localhost:8501                            | Streamlit analyst dashboard   |

---

## Guided testing

The whole point is to **see** the deception work. Run the four scenarios below
in order. Keep the dashboard open at http://localhost:8501 in a side tab to
watch metrics update live.

> Tip: on Windows PowerShell, use `curl.exe` to bypass the built-in
> `Invoke-WebRequest` alias. On macOS/Linux just use `curl`.

### Prerequisites for testing

```powershell
# Terminal A — honeypot
python -m honeypot.run_honeypot

# Terminal B — dashboard
python -m honeypot.run_dashboard

# Terminal C — for the scenarios below
```

You should also wipe previous logs if you want a clean run:

```powershell
Remove-Item honeypot/data/logs/*.jsonl -Force -ErrorAction SilentlyContinue
```

---

### Scenario 1 — The casual visitor (no tarpit, real pages)

A human with a normal browser should never feel anything weird.

**Test in browser:**

| Visit                                | Expected                                                 |
|--------------------------------------|----------------------------------------------------------|
| http://localhost:5000                | Home page with ~8 fake products (Power Bank, Mouse, …)   |
| http://localhost:5000/about          | Persona + tech stack                                     |
| http://localhost:5000/search         | 15 product rows                                          |
| http://localhost:5000/search?q=mouse | Filtered to products containing "mouse"                  |
| http://localhost:5000/login          | Login form (POST → "Invalid credentials")                |
| http://localhost:5000/dashboard      | KPIs + 8 fake orders                                     |
| http://localhost:5000/profile        | Profile page (full HTML, "guest" account)                |
| http://localhost:5000/api/docs       | Fake Swagger page                                        |
| http://localhost:5000/nope           | Apache-style 404 page                                    |

**Test in CLI:**

```powershell
curl.exe -A "Mozilla/5.0" http://127.0.0.1:5000/
curl.exe -o NUL -w "%{http_code} %{content_type} %{size_download}b`n" `
         -A "Mozilla/5.0" http://127.0.0.1:5000/profile
# expected: 200 text/html; charset=utf-8  ~2700b
```

**In the dashboard** (Live activity tab): your fingerprint appears under
*Recent attacker sessions* with `profile = casual` and zero tarpit delay.

---

### Scenario 2 — Recon → SSH credential leak (the headline scenario)

The attacker fuzzes the app, finds `/backup/`, downloads the archive, and
walks away with SSH creds. This is the multi-hop deception you want to
demo to investors / supervisors.

**Step-by-step in the browser:**

1. http://localhost:5000/robots.txt
   - You see `Disallow: /backup/` and `Disallow: /.git/`.
   - **Hop 1 successful**: attacker now knows `/backup/` exists.

2. http://localhost:5000/backup/
   - Apache-style directory listing with a link to `db.tar.gz`.
   - **Hop 2 successful**: attacker spots the bait file.

3. http://localhost:5000/backup/db.tar.gz
   - Server returns plain text containing
     `SSH_USER=deploy SSH_PASS=Strong!Pass#42 TOKEN=ht-1`.
   - **Exfiltration successful**: the honeytoken is leaked.

4. http://localhost:5000/.git/config
   - Bonus: fake git config exposes an internal GitLab URL — another
     plausible signal of misconfiguration.

**One-liner equivalent:**

```powershell
$ua = "Nuclei v3.1"
curl.exe -A $ua http://127.0.0.1:5000/robots.txt
curl.exe -A $ua http://127.0.0.1:5000/backup/
curl.exe -A $ua http://127.0.0.1:5000/backup/db.tar.gz
```

**Verify the leak was recorded:**

```powershell
Get-Content honeypot\data\logs\honeytoken_leaks.jsonl
# expected one line:
# {"ts":..., "token_id":"ht-1", "ip":"127.0.0.1",
#  "endpoint":"/backup/db.tar.gz",
#  "excerpt":"SSH_USER=deploy SSH_PASS=Strong!Pass#42 TOKEN=ht-1"}
```

**In the dashboard:**

- *Live activity* tab:
  - KPI *Honeytoken leaks* → 1
  - KPI *Breadcrumb hits* → 3
  - Section *Honeytoken leaks* shows the row.
  - Section *Session replay* — pick your fingerprint, see the 3-step chain.

---

### Scenario 3 — Trigger every trap with malicious payloads

The blueprint generated by Groq currently has 5 traps. Each one fires only
when the payload looks malicious (so casual visitors are not impacted).

| Trap                              | Browser URL                                                                                       | Expected body                          |
|-----------------------------------|---------------------------------------------------------------------------------------------------|----------------------------------------|
| Reflected XSS on `/profile`       | http://localhost:5000/profile?url=`<script>alert(1)</script>`                                     | Fake page reflecting the payload       |
| Info Disclosure on `/download`    | http://localhost:5000/download?q=`SQL%20syntax%20error`                                            | Fake debug stack trace                 |
| SQL Injection on `/download`      | http://localhost:5000/download?file=1'%20OR%201=1--                                                | MySQL-style error body                 |
| Private IP Disclosure on `/api/v1/users` | http://localhost:5000/api/v1/users?id=1                                                     | JSON with `"ip_address":"192.168.x.x"` |

For the SQL Injection on `/api/login` (POST only):

```powershell
curl.exe -X POST -d "id=1' OR 1=1--" http://127.0.0.1:5000/api/login
# expected: a fake "login successful" JSON — tricks the attacker into
# believing auth was bypassed
```

**Verify a benign call to the same paths returns a real page:**

```powershell
curl.exe -o NUL -w "%{http_code} %{content_type} %{size_download}b`n" `
         -A "Mozilla/5.0" http://127.0.0.1:5000/profile
# expected: 200 text/html; charset=utf-8  ~2700b  (legit page, not the trap)
```

**In the dashboard:**
- KPI *Trap hits* increments by 1 per malicious call.
- *Top hit endpoints* bar chart shows the trap paths climbing.

---

### Scenario 4 — Automated scanner profiling + adaptive tarpit

Simulate a `ffuf` / `nuclei` style scanner and watch the latency grow.

```powershell
for ($i=1; $i -le 20; $i++) {
  curl.exe -s -o NUL -w "$i  %{time_total}s`n" `
           -A "Nuclei v3.1" "http://127.0.0.1:5000/random-$i"
}
```

Expected output (timings approximate):

```
 1  0.064s
 2  0.087s
 3  0.121s
 5  0.169s
 8  0.467s
12  1.300s
16  2.612s
20  3.000s   (capped at TARPIT_MAX_DELAY_MS)
```

**In the dashboard:**
- *Attacker profiles* pie chart shows `nuclei` as a slice.
- Your session's *profile* column reads `nuclei`.
- *Activity over time* timeline shows the burst.

Re-run with no `-A` (default `curl` UA) → you become `automated_fuzzer`
after ~20 requests. Re-run as `Mozilla` with `-A "Mozilla/5.0"` → you stay
`casual` and there is **no** tarpit.

---

### Scenario 5 — Iterate: regenerate with a different blueprint

The Architect call is cheap (~5 seconds, Groq free tier). Regenerate to get
a different persona / strategies:

```powershell
python -m honeypot.run_architect    # new blueprint, persona may change
python -m honeypot.run_generator    # rebuilds fake DB + decoys
# restart honeypot to pick up the changes
python -m honeypot.run_honeypot
```

You can also feed it a different FP set (e.g. after a fresh ZAP scan):

```bash
python ZAP/parse_zap.py             # re-parse a new raw ZAP report
python ZAP/advanced_fp_classifier.py  # re-classify
python -m honeypot.run_architect    # new blueprint adapts
```

---

### Scenario 6 — (Optional) Bridge to the SSH honeypot

After Scenario 2, `honeypot/data/ssh_credentials.json` contains the leaked
creds with a tracking token. Hand them to the existing Cowrie launcher:

```bash
# In your Cowrie host (WSL/Kali)
python start_honeypot.py            # picks top FP scenario from BETH
# Then on the attacker side:
ssh deploy@<honeypot-ip>            # password: Strong!Pass#42
```

Cowrie accepts the login, the AI bash shell takes over, and the SSH session
is logged in `var/log/cowrie/` and `ai_interactions.jsonl` — closing the
loop between the web and SSH surfaces.

---

## The three analyst views

| View | Where | Best for |
|---|---|---|
| **CLI lineage** | `python -m honeypot.show_lineage` | Quick FP → trap dump in terminal |
| **Flask admin page** | http://localhost:5000/_internal/strategies | Inline, in-app, dark-themed grid with persona + per-trap source FP + linked honeytokens. Refuses non-localhost. |
| **Streamlit dashboard** | http://localhost:8501 | Live metrics (Activity, KPIs, profile pie, top endpoints, leaks, session replay) **plus** a dedicated "Strategies (FP → Trap lineage)" tab. |

---

## Deception strategies implemented

| # | Strategy                              | What it does                                                                              |
|---|---------------------------------------|-------------------------------------------------------------------------------------------|
| 1 | Realistic app shell                   | Home/login/dashboard/search/profile/about render real HTML & Faker data                   |
| 2 | FP-driven trap routes                 | Every classified FP becomes a route that simulates the suspected vuln family              |
| 3 | LLM-mutated responses                 | Ollama (or Groq fallback) mutates the body per attacker payload, LRU-cached               |
| 4 | Multi-hop SSH credential leak         | `/robots.txt` → `/backup/` listing → `db.tar.gz` containing `SSH_USER` / `SSH_PASS`       |
| 5 | Unique honeytoken tracking IDs        | Each token has a `token_id` so we know who exfiltrated what                               |
| 6 | Decoy directory listing               | `/backup/` returns an Apache-style index                                                  |
| 7 | Trap-vs-page disambiguation           | A trap path serves the legit page on benign requests and only fires on malicious payloads |
| 8 | Adaptive tarpit                       | Delay grows on hostile profiles + per trap/breadcrumb hit; never delays a `casual` UA     |
| 9 | Attacker profiling                    | UA fingerprinting + behavioural classifier (sqlmap, nuclei, ffuf, automated_fuzzer, …)    |
|10 | Session tracking                      | Per-fingerprint stream replayable in the dashboard                                        |
|11 | SSH bridge to Cowrie                  | Honeytoken leak writes `ssh_credentials.json` + `honeytoken_leaks.jsonl`                  |
|12 | Forensic JSONL log                    | Every request logged with payload, profile, status, latency, leak flag, tarpit delay      |
|13 | Server header spoofing                | Apache/PHP banners injected in every response, matching the persona's tech_stack          |
|14 | Localhost-only admin page             | `/_internal/strategies` is gated by `request.remote_addr` check                           |

---

## Configuration reference

All knobs live in `.env` (see `.env.example`). Key ones:

| Variable                  | Default              | Effect                                                  |
|---------------------------|----------------------|---------------------------------------------------------|
| `GROQ_API_KEY`            | _(required)_         | Architect LLM credentials                               |
| `ARCHITECT_PROVIDER`      | `groq`               | `groq` or `ollama`                                      |
| `RESPONDER_PROVIDER`      | `ollama`             | Runtime LLM for trap mutation; falls back to template   |
| `OLLAMA_MODEL`            | `llama3.2:3b`        | Small, fast, low-cost model                             |
| `FLASK_HOST`              | `0.0.0.0`            | Set to `127.0.0.1` for local-only testing               |
| `TARPIT_BASE_DELAY_MS`    | `80`                 | First-hit delay seed                                    |
| `TARPIT_MAX_DELAY_MS`     | `4000`               | Cap                                                     |
| `TARPIT_ENABLED`          | `true`               | Master switch                                           |
| `FAKE_DB_ROWS_PER_TABLE`  | `50`                 | Faker volume per table                                  |
| `SSH_BRIDGE_ENABLED`      | `true`               | Export `ssh_credentials.json` + write leak log          |

---

## Roadmap

- **Feedback loop**: re-train the FP classifier with the traps that actually
  attracted humans (the more an FP gets attacked, the less "false" it is).
- **Per-session canary**: derive a unique token per attacker so attribution
  survives even if creds are shared on a forum.
- **Network-level isolation**: ship the Flask app in a read-only Docker
  container with no egress.
- **WAF emulation**: deceptive `403`/`406` responses mimicking
  Cloudflare/Akamai to mislead reconnaissance.
- **gRPC / GraphQL surface**: generate decoy schemas alongside REST.
- **Auto-deploy in CI**: GitHub Action that spins up the honeypot, runs a
  ZAP scan against it, and asserts that all FP-derived traps responded
  convincingly.

---

## Security note

This is a honeypot. **Do not run it on a network where you don't control
the egress.** Even fake SQLi and reflected XSS responses can be misused
against other systems. Run inside a sandboxed VM, a Docker container, or
a dedicated DMZ host with strict outbound rules.

Generated honeytoken credentials (`deploy / Strong!Pass#42`, etc.) are
**meant to leak** — they are bait. The real concern is making sure your
**actual** credentials never end up in this repository: keep `.env` out of
git (the included `.gitignore` covers it).
