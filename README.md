# Cyber Defense Multi-Agent SOC Platform

An AI-powered autonomous Security Operations Center built with LangGraph, FastAPI, and Google Gemini. Seven specialized agents collaborate in real time to detect threats, analyse logs, hunt vulnerabilities, respond to incidents, enforce compliance, and generate reports — all coordinated by a Supervisor Agent.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Supervisor Agent                        │
│        (LLM-driven router + parallel dispatch)              │
└──────┬──────┬──────┬──────┬──────┬──────┬───────────────────┘
       │      │      │      │      │      │
   Threat   Log    Vuln  Incident Comp  Report
   Detect  Anlys  Intel  Response liance  ing
```

Each agent is a **LangGraph state machine** that uses:
- **Gemini 2.5 Flash** (Google AI Studio) for reasoning — `GEMINI_MODEL`
- **ChromaDB + Gemini embeddings** for retrieval (threat intel, CVE KB, compliance policies) — `GEMINI_EMBEDDING_MODEL`
- **Redis** for agent status, the shared blackboard, the live pub/sub feed and the durable escalation stream
- **PostgreSQL** for persistent incident/threat/compliance records (schema managed by Alembic)

```
Browser Dashboard (React)
        │  WebSocket
FastAPI Backend
        │  Redis pub/sub
Agent Mesh (7 LangGraph agents)
        │
┌───────┴────────────────────────────────┐
│  PostgreSQL  Redis  ChromaDB  NVD API  │
└────────────────────────────────────────┘
```

---

## Agents

| Agent | Role |
|---|---|
| **Threat Detection** | Classifies events, enriches IOCs (WHOIS/heuristics), maps MITRE ATT&CK |
| **Log Analysis** | Deterministic signature detection (escalates on its own) + LLM anomaly detection on log batches |
| **Vulnerability Intel** | CVE lookup via NVD (throttled, cached), TCP port exposure scan, risk prioritisation |
| **Incident Response** | Playbook selection; containment actions queued for admin approval, executed via a webhook or recorded as simulated |
| **Compliance** | Control-by-control evaluation for SOC 2, NIST CSF, ISO 27001 against evidence collected from the platform |
| **Reporting** | Executive summaries and threat intel briefs; headline metrics computed from the database |
| **Supervisor** | LLM-driven router (rule-based fallback) → per-agent task shaping → dispatch → synthesis |

---

## Tech Stack

| Layer | Technology |
|---|---|
| LLM | Google Gemini 2.5 Flash (AI Studio) |
| Agent framework | LangGraph + LangChain |
| API | FastAPI + WebSockets |
| Frontend | React 18 + Tailwind CSS + Recharts |
| Primary DB | PostgreSQL 16 (SQLAlchemy async) |
| Cache / bus | Redis 7 |
| Vector DB | ChromaDB |
| Log storage | Elasticsearch 8 |
| Monitoring | Prometheus + Grafana |
| Containers | Docker + Docker Compose |
| Threat intel | NIST NVD (free), ipwhois RDAP (free), local heuristics |

---

## Quick Start

### 1. Prerequisites

- Docker Desktop
- Python 3.12+
- Node.js 20+
- A [Google AI Studio](https://aistudio.google.com) API key (free tier works)

### 2. Clone and configure

```bash
git clone <repo-url>
cd cyber-defense-multi-agent

cp .env.example .env
```

Edit `.env` and set at least:

| Variable | Why |
|---|---|
| `GOOGLE_API_KEY` | Gemini access |
| `ADMIN_PASSWORD`, `ANALYST_PASSWORD` | **Required.** Accounts with an empty, short (<8) or demo password are disabled |
| `API_SECRET_KEY` | 32+ chars: `python -c "import secrets; print(secrets.token_urlsafe(48))"`. Without it tokens die on every restart |

For a throwaway local demo, `ALLOW_INSECURE_DEFAULTS=true` restores the old
`admin/admin123`, `analyst/analyst123` logins instead.

### 3. Start all services

```bash
docker compose up -d
```

The API applies the Alembic migrations on startup. To run them yourself (for example
against a database the API does not start against): `alembic upgrade head`.

### 4. Seed the vector store (RAG knowledge base)

```bash
python scripts/seed_vector_store.py
```

Services started:

| Service | URL |
|---|---|
| API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Dashboard | http://localhost:3000 |
| Grafana | http://localhost:3001 (admin/admin) |
| Prometheus | http://localhost:9090 |
| Elasticsearch | http://localhost:9200 |

### 5. Sign in

The dashboard opens on a login screen. Use the credentials from your `.env`
(`ADMIN_USERNAME` / `ADMIN_PASSWORD`). The JWT it returns authorises both the REST
calls and the live WebSocket feed; an expired token drops you back to the login
screen automatically, and an open socket is closed when its token expires. Five failed
attempts for a username from one address lock that pair out for 15 minutes.

### 6. Run in dev mode (no Docker)

```bash
# Backend
pip install -r requirements.txt
uvicorn api.main:app --reload

# Dashboard
cd dashboard
npm install
npm start

# Simulation engine (generates fake attack traffic)
python -m simulation.engine
```

### Gemini quotas

Free-tier quotas are small (single-digit to low-double-digit requests per minute and a
limited daily allowance — check your project's limits in AI Studio). The platform keeps
its usage bounded:

* every Gemini call in the process shares one rate limiter (`LLM_REQUESTS_PER_MINUTE`);
* retrieval returns knowledge-base passages directly instead of spending a second LLM
  call per lookup;
* the simulator feed is analysed at most once per `SIMULATION_ANALYSIS_INTERVAL_SECONDS`
  (default 60s, so ~1,440 log-analysis calls a day plus escalations). On a tight daily
  quota, raise the interval, set `LOG_ANALYSIS_LLM_MODE=on_hits` (LLM only for batches
  with suspicious signatures) or `SIMULATION_CONSUMER_ENABLED=false`.

The dashboard reads `REACT_APP_API_URL` and `REACT_APP_WS_URL` — copy
`dashboard/.env.example` to `dashboard/.env.local` if the API is not on
`localhost:8000`.

---

## Dashboard

A React 18 + Tailwind SPA served on port 3000.

| View | What it shows |
|---|---|
| Threat level banner | Current blackboard threat level, pushed live over the socket |
| Metrics row | Incident, threat and agent counters |
| Alert chart | Alert volume over time, bucketed by minute |
| Threat severity | Persisted detections by severity over 24h / 7d / 30d |
| Agent status grid | Per-agent idle / running / error / paused state, with pause & resume controls for admins |
| Alert feed | Streaming `agent_events` and `escalations` |
| Incident panel | Incident list; admins change status (contain / resolve / false positive) and approve or reject queued containment actions |
| Compliance view | Framework evaluation results |
| Vulnerabilities | Stored CVEs by CVSS, CVE lookup, admin scan form |
| Reports | Stored executive / threat reports, admin generation |
| Log search | Full-text search over analysed logs in Elasticsearch |

Snapshot data is polled from the REST API so counters survive a reload; everything
that happens while the page is open arrives over the WebSocket. Every control that
changes state is admin-only and is shown disabled for an `analyst` session — the
server refuses those calls for an analyst token regardless.

```bash
cd dashboard
npm run typecheck        # tsc --noEmit
CI=true npm test         # jest suite (session expiry, socket reconnect)
npm run build            # production bundle into dashboard/build
```

---

## Project Structure

```
.
├── agents/
│   ├── base_agent.py               # Shared base class with telemetry
│   ├── threat_detection/agent.py   # LangGraph threat classification
│   ├── log_analysis/agent.py       # Batch log anomaly detection
│   ├── vulnerability_intel/agent.py# CVE + port exposure analysis
│   ├── incident_response/agent.py  # Playbook execution
│   ├── compliance/agent.py         # Framework control evaluation
│   ├── reporting/agent.py          # Report generation
│   └── supervisor/agent.py         # Orchestrator
├── api/
│   ├── main.py                     # FastAPI app + lifespan
│   ├── routes/                     # REST endpoints
│   └── websocket/manager.py        # Redis → WebSocket bridge
├── core/
│   ├── config.py                   # Pydantic settings
│   ├── database/                   # SQLAlchemy models, repository, Redis + ES clients
│   ├── memory/agent_memory.py      # Agent history + shared blackboard
│   ├── threat_level.py             # Raise-fast / lower-slow threat level policy
│   ├── containment.py              # Simulated or webhook containment executor
│   ├── rag/                        # ChromaDB vector store + RAG chains
│   └── tools/threat_tools.py       # LangChain tools (NVD, ipwhois, heuristics)
├── dashboard/                      # React frontend
├── simulation/                     # SIEM log + attack scenario generator
├── tests/
│   ├── unit/                       # Agent + config unit tests
│   ├── integration/                # API endpoint tests
│   └── stress/                     # Concurrency + failure injection tests
├── infra/
│   ├── docker/                     # Dockerfiles + init.sql
│   ├── nginx/                      # Reverse proxy config
│   └── monitoring/                 # Prometheus + Grafana configs
├── docker-compose.yml
├── requirements.txt
└── pytest.ini
```

---

## API Reference

### Authentication

All `/api/v1/*` routes require a JWT bearer token. Get one first:

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "<ADMIN_PASSWORD>"}'
# Returns: {"access_token": "...", "token_type": "bearer"}
```

Then include it in all requests:
```bash
curl http://localhost:8000/api/v1/agents/status \
  -H "Authorization: Bearer <token>"
```

Credentials come from `ADMIN_USERNAME` / `ADMIN_PASSWORD` and `ANALYST_USERNAME` /
`ANALYST_PASSWORD` in `.env`. The token carries a role:

* `admin` — everything, including every state-changing request (any non-GET under
  `/api/v1`) and every WebSocket override;
* `analyst` — read-only; any write returns 403.

State-changing requests are rate limited per user (`API_WRITE_RATE_LIMIT_PER_MINUTE`,
429 when exceeded). Every list endpoint takes `?limit=`, which must be a positive
integer within the documented ceiling; anything else is rejected with 422.

`/health`, `/metrics`, `/docs` and `/api/v1/auth/*` are the only unauthenticated paths.

### Agents
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/agents/status` | Status of all 7 agents |
| GET | `/api/v1/agents/registry` | Agent names and descriptions |
| GET | `/api/v1/agents/blackboard` | Shared agent blackboard state |
| POST | `/api/v1/agents/run` | Run any agent with a payload (admin) |
| POST | `/api/v1/agents/supervisor/run` | Route a task through the Supervisor (admin) |
| POST | `/api/v1/agents/{name}/pause` | Pause an agent (admin) |
| POST | `/api/v1/agents/{name}/resume` | Resume an agent (admin) |
| GET | `/api/v1/agents/{name}/status` | Status of one agent |
| GET | `/api/v1/agents/{name}/history` | Agent event history (`?limit=1..200`) |

### Threats
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/threats/analyze` | Analyze a single security event |
| POST | `/api/v1/threats/batch-analyze` | Analyze up to 20 events |
| GET | `/api/v1/threats/recent` | Recent threat detections |
| GET | `/api/v1/threats/stats` | Severity breakdown over a trailing window |

### Incidents
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/incidents/respond` | Trigger response playbook |
| GET | `/api/v1/incidents/` | List recent incidents |
| GET | `/api/v1/incidents/{id}` | Get incident details |
| POST | `/api/v1/incidents/{id}/update` | Update incident status |
| POST | `/api/v1/incidents/{id}/actions/{index}/approve` | Execute a queued containment action |
| POST | `/api/v1/incidents/{id}/actions/{index}/reject` | Decline a queued containment action |

### Vulnerabilities
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/vulnerabilities/scan` | Scan CVEs + asset ports |
| GET | `/api/v1/vulnerabilities/` | List stored risk reports |
| GET | `/api/v1/vulnerabilities/cve/{id}` | Lookup a CVE from NVD |

### Compliance
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/compliance/evaluate` | Evaluate a framework (SOC2 / NIST CSF / ISO 27001) |
| GET | `/api/v1/compliance/frameworks` | List supported frameworks |
| GET | `/api/v1/compliance/frameworks/{framework}` | Controls for one framework |
| GET | `/api/v1/compliance/history` | Past evaluations |

### Reports
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/reports/generate` | Generate executive or threat report |
| GET | `/api/v1/reports/` | List stored reports |
| GET | `/api/v1/reports/{key}` | Fetch one stored report |

### Logs
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/logs/search` | Search analysed logs (`?q=&anomalous_only=&limit=`); `source: "unavailable"` when Elasticsearch is off |

### Operations
| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/health/ready` | Readiness — per-dependency status |
| GET | `/metrics` | Prometheus exposition |

### WebSocket
Connect to `ws://localhost:8000/ws?token=<jwt>` to receive live events from all
agents. The token rides as a query parameter because browsers cannot set headers on
a WebSocket handshake; a CLI client may send `Authorization: Bearer <jwt>` instead.
An unauthenticated handshake is closed with code 1008.

Channels: `agent_events`, `escalations`, `incident_updates`.

Send a human override (all commands — `pause_agent`, `resume_agent`, `run_agent`,
`set_threat_level` — require the `admin` role):
```json
{ "type": "human_override", "command": "pause_agent", "payload": { "agent": "threat_detection" } }
```

A pause lasts until it is resumed. Pausing the `supervisor` also stops automated
escalation response.

---

## Response pipeline

* **Escalations are durable.** Agents write each escalation to the Redis stream
  `escalations:stream` (and publish it on the `escalations` channel for the dashboard).
  The API consumes the stream with a consumer group and acknowledges an entry only after
  the supervisor has handled it, so escalations raised while the API is down are
  processed when it returns. Repeats for the same attack type and source within
  `ESCALATION_COOLDOWN_SECONDS` collapse into one response, whichever agent raised them.
* **Incidents link to their evidence.** The threat event behind an escalation, and
  unlinked events from the same source IPs in the last day, are attached to the incident.
* **Containment needs approval.** Automated playbook actions are queued as
  `pending_approval`; an admin approves or rejects each one. With `CONTAINMENT_MODE=simulate`
  (default) an approved action is recorded as `simulated` — nothing is executed. With
  `CONTAINMENT_MODE=webhook` it is POSTed to `CONTAINMENT_WEBHOOK_URL`
  (`{"action": ..., "incident": {...}}`) and marked `completed` on a 2xx reply, `failed`
  otherwise. Set `CONTAINMENT_REQUIRE_APPROVAL=false` to execute without approval.
* **Threat level.** Raising it applies immediately; an automated assessment may only
  lower it after the current level has stood for `THREAT_LEVEL_HOLD_SECONDS`. An admin
  override sets it outright. It decays to `low` after an hour without reaffirmation.

---

## Running Tests

The suite runs with **no external services**: `tests/conftest.py` swaps Redis for an
in-memory fake, stubs Gemini with deterministic canned responses, and switches off
PostgreSQL persistence, Elasticsearch and ChromaDB.

```bash
pip install -r requirements.txt

pytest                      # everything (unit + integration + stress)
pytest tests/unit/ -v       # agents, parsing, config
pytest tests/integration/   # API routes and WebSocket, over an ASGI transport
pytest tests/stress/ -v     # concurrency, throughput, failure injection

pytest --cov=. --cov-report=term-missing
```

`tests/integration/test_postgres.py` runs the real migrations and repository against a
PostgreSQL you point it at (it drops and recreates the `public` schema):

```bash
TEST_POSTGRES_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/cd_test pytest tests/integration/test_postgres.py
```

Detection quality against the simulator's ground-truth labels:

```bash
python scripts/evaluate_detection.py            # per-type recall + false-positive rate
python scripts/evaluate_detection.py --llm      # also the full agent (needs GOOGLE_API_KEY)
```

CI (`.github/workflows/ci.yml`) runs all of the above with a PostgreSQL service, the
dashboard typecheck/tests/build, and builds the Docker images.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GOOGLE_API_KEY` | **Yes** | Google AI Studio API key |
| `ADMIN_PASSWORD` / `ANALYST_PASSWORD` | **Yes** | 8+ chars, not a demo value — otherwise the account is disabled |
| `API_SECRET_KEY` | Recommended | 32+ char JWT key; otherwise a random per-process key is used |
| `GEMINI_MODEL` / `GEMINI_EMBEDDING_MODEL` | No | Chat and embedding models |
| `LLM_REQUESTS_PER_MINUTE` | No | Shared Gemini rate limit (default `10`) |
| `ALLOW_INSECURE_DEFAULTS` | No | Restore demo logins and key — local only (default `false`) |
| `ENABLE_PERSISTENCE` | No | Write to PostgreSQL; `false` runs Redis-only (default: `true`) |
| `RAG_ENABLED` | No | Use ChromaDB retrieval (default: `true`) |
| `CONTAINMENT_MODE` / `CONTAINMENT_WEBHOOK_URL` / `CONTAINMENT_REQUIRE_APPROVAL` | No | How approved containment actions run |
| `SCAN_ALLOWED_NETWORKS` / `NVD_API_KEY` | No | Port-scan allow-list, higher NVD rate limit |
| `VULN_SCAN_TARGETS` / `VULN_WATCHLIST_CVES` / `VULN_SCAN_INTERVAL` | No | Scheduled vulnerability scans |
| `SIMULATION_MODE` | No | Enable fake log generation (default: `true`) |
| `SIMULATION_ANALYSIS_INTERVAL_SECONDS` | No | Pace of simulator-feed analysis (default `60`) |

See [.env.example](.env.example) for the full list.

---

## Threat Intelligence Sources

All sources are **free and require no API keys**:

| Source | Tool | Data |
|---|---|---|
| NIST NVD | `get_nvd_cve` | CVE descriptions, CVSS scores, severity |
| ipwhois RDAP | `enrich_ip` | ASN, org, country, network range |
| Local heuristics | `score_ioc` | Domain/IP/hash risk scoring |
| TCP port probe | `scan_asset_ports` | Open ports and exposed services |

---

## Simulation

The simulation engine generates realistic security events without needing real infrastructure:

```bash
python -m simulation.engine
```

It continuously produces:
- Normal auth, web, and system logs
- Randomised attack events (brute force, SQLi, port scans, C2 beacons, data exfil)
- Full multi-stage APT scenarios (recon → exploit → C2 → exfiltration)

Injected scenarios are only queued as logs: incidents appear when log analysis
actually detects them (set `SIMULATION_INJECT_ESCALATIONS=true` to also publish a
direct escalation, as older versions did). Queued logs older than
`SIMULATION_MAX_LAG_SECONDS` are dropped and counted in `simulation_logs_dropped_total`
rather than analysed late.

Tune with env vars: `SIMULATION_LOG_RATE`, `SIMULATION_ATTACK_PROBABILITY`,
`SIMULATION_BATCH_SIZE`, `SIMULATION_ANALYSIS_INTERVAL_SECONDS`.
