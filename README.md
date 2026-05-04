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

Services started:

| Service | URL |
|---|---|
| API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Dashboard | http://localhost:3000 |
| Grafana | http://localhost:3001 (admin/admin) |
| Prometheus | http://localhost:9090 |
| Elasticsearch | http://localhost:9200 |

### 4. Run in dev mode (no Docker)

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

### Agents
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/agents/status` | Status of all 7 agents |
| GET | `/api/v1/agents/{name}/history` | Agent event history |
| POST | `/api/v1/agents/run` | Run any agent with a payload |
| GET | `/api/v1/agents/blackboard` | Shared agent blackboard state |

### Threats
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/threats/analyze` | Analyze a single security event |
| POST | `/api/v1/threats/batch-analyze` | Analyze up to 20 events |
| GET | `/api/v1/threats/recent` | Recent threat detections |

### Incidents
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/incidents/respond` | Trigger response playbook |
| GET | `/api/v1/incidents/{id}` | Get incident details |
| POST | `/api/v1/incidents/{id}/update` | Update incident status |

### Vulnerabilities
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/vulnerabilities/scan` | Scan CVEs + asset ports |
| GET | `/api/v1/vulnerabilities/cve/{id}` | Lookup a CVE from NVD |

### Compliance
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/compliance/evaluate` | Evaluate a framework (SOC2 / NIST CSF / ISO 27001) |
| GET | `/api/v1/compliance/frameworks` | List supported frameworks |

### Reports
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/reports/generate` | Generate executive or threat report |
| GET | `/api/v1/reports/` | List stored reports |

### WebSocket
Connect to `ws://localhost:8000/ws` to receive live events from all agents. Channels: `agent_events`, `escalations`, `incident_updates`.

Send a human override:
```json
{ "type": "human_override", "command": "pause_agent", "payload": { "agent": "threat_detection" } }
```

---

## Running Tests

```bash
# Unit tests only
pytest tests/unit/ -v

# Integration tests (requires running API)
pytest tests/integration/ -v

# Full stress suite
pytest tests/stress/ -v --timeout=120

# All tests with coverage
pytest --cov=. --cov-report=term-missing
```

---

## Environment Variables

Only two are required to get started:

| Variable | Required | Description |
|---|---|---|
| `GOOGLE_API_KEY` | **Yes** | Google AI Studio API key |
| `GEMINI_MODEL` | No | Model name (default: `gemini-2.5-flash`) |
| `POSTGRES_PASSWORD` | No | DB password (default: `strongpassword123`) |
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
