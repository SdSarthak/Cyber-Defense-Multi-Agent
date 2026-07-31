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
- **Gemini 2.5 Flash** (Google AI Studio) for reasoning
- **ChromaDB + Google text-embedding-004** for RAG (threat intel, CVE KB, compliance policies)
- **Redis** for short-term memory, blackboard state, and pub/sub event bus
- **PostgreSQL** for persistent incident/threat/compliance records

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
| **Log Analysis** | Regex pattern scan + LLM anomaly detection on log batches |
| **Vulnerability Intel** | CVE lookup via NVD, TCP port exposure scan, risk prioritisation |
| **Incident Response** | Playbook selection and automated containment for 5 attack types |
| **Compliance** | Control-by-control evaluation for SOC 2, NIST CSF, ISO 27001 |
| **Reporting** | Executive summaries and threat intel briefs as structured JSON |
| **Supervisor** | LLM-driven router → parallel/sequential agent dispatch → synthesis |

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
# Edit .env — set GOOGLE_API_KEY=your_key_here
```

### 3. Start all services

```bash
docker-compose up -d
```

### 4. Run database migrations

```bash
alembic upgrade head
```

### 5. Seed the vector store (RAG knowledge base)

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

### 6. Sign in

The dashboard opens on a login screen. Use the credentials from your `.env`
(`ADMIN_USERNAME` / `ADMIN_PASSWORD`, default `admin` / `admin123`). The JWT it
returns authorises both the REST calls and the live WebSocket feed; an expired token
drops you back to the login screen automatically.

### 7. Run in dev mode (no Docker)

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
| Incident panel | Open incidents with playbook and containment status |
| Compliance view | Latest framework scores |

Snapshot data is polled from the REST API every 15s so counters survive a reload;
everything that happens while the page is open arrives over the WebSocket. Signing in
as `admin` also enables the pause/resume buttons on the agent grid — those travel as
`human_override` frames on the same socket, and the server refuses them for an
`analyst` token.

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
│   ├── database/                   # SQLAlchemy models + Redis client
│   ├── memory/agent_memory.py      # Short-term + blackboard memory
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
  -d '{"username": "admin", "password": "admin123"}'
# Returns: {"access_token": "...", "token_type": "bearer"}
```

Then include it in all requests:
```bash
curl http://localhost:8000/api/v1/agents/status \
  -H "Authorization: Bearer <token>"
```

Credentials come from `ADMIN_USERNAME` / `ADMIN_PASSWORD` and `ANALYST_USERNAME` /
`ANALYST_PASSWORD` in `.env` (defaults: `admin / admin123`, `analyst / analyst123`).
The token carries a role: `admin` may issue agent overrides (pause, resume, run —
over both REST and the WebSocket), `analyst` is read-only and gets 403 on those
routes. Every list endpoint takes `?limit=`, which must be a positive integer
within the documented ceiling; anything else is rejected with 422.

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

Send a human override (`pause_agent`, `resume_agent`, `run_agent` require the
`admin` role; `set_threat_level` is open to any authenticated operator):
```json
{ "type": "human_override", "command": "pause_agent", "payload": { "agent": "threat_detection" } }
```

---

## Running Tests

The whole suite runs with **no external services**: `tests/conftest.py` swaps Redis for
an in-memory fake, stubs Gemini with deterministic canned responses, and switches off
PostgreSQL persistence, Elasticsearch and ChromaDB.

```bash
pip install -r requirements.txt

pytest                      # everything (unit + integration + stress)
pytest tests/unit/ -v       # agents, parsing, config
pytest tests/integration/   # API routes and WebSocket, over an ASGI transport
pytest tests/stress/ -v     # concurrency, throughput, failure injection

pytest --cov=. --cov-report=term-missing
```

---

## Environment Variables

Only two are required to get started:

| Variable | Required | Description |
|---|---|---|
| `GOOGLE_API_KEY` | **Yes** | Google AI Studio API key |
| `GEMINI_MODEL` | No | Model name (default: `gemini-2.5-flash`) |
| `API_SECRET_KEY` | No | JWT signing key — **change this before deploying** |
| `ADMIN_PASSWORD` | No | Dashboard admin password (default: `admin123`) |
| `POSTGRES_PASSWORD` | No | DB password (default: `strongpassword123`) |
| `ENABLE_PERSISTENCE` | No | Write to PostgreSQL; `false` runs Redis-only (default: `true`) |
| `RAG_ENABLED` | No | Use ChromaDB retrieval (default: `true`) |
| `WEBSOCKET_AUTH_REQUIRED` | No | Require a JWT on `/ws` (default: `true`) |
| `SIMULATION_MODE` | No | Enable fake log generation (default: `true`) |
| `SIMULATION_ATTACK_PROBABILITY` | No | 0.0–1.0 attack ratio (default: `0.05`) |

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

Tune with env vars: `SIMULATION_LOG_RATE`, `SIMULATION_ATTACK_PROBABILITY`.
