import asyncio
import contextlib
from datetime import datetime, timezone

import structlog
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from core import metrics
from core.config import settings
from core.database.base import init_db
from core.database import es_client, redis_client
from core.metrics import PrometheusMiddleware
from api.routes import agents, incidents, threats, vulnerabilities, compliance, reports, health, auth, logs
from api.websocket.manager import ws_router, redis_listener, escalation_listener
from api.middleware.auth import AuthMiddleware, _users

log = structlog.get_logger()

SIM_QUEUE_KEY = "sim:log_queue"


def _age_seconds(entry: dict, now: datetime) -> float | None:
    raw = entry.get("timestamp")
    if not isinstance(raw, str):
        return None
    try:
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).total_seconds()


async def drain_sim_queue(batch_size: int, max_lag_seconds: float, max_pops: int | None = None) -> tuple[list[dict], int]:
    """
    Pop up to ``batch_size`` fresh entries (oldest first), discarding ones older than
    ``max_lag_seconds``. Returns (fresh entries, number dropped).

    The consumer used to fall behind the producer and silently analyse logs a quarter
    of an hour old while the queue sat at its cap. Stale entries are now dropped and
    counted (``simulation_logs_dropped_total``) so the lag is visible, not hidden.
    """
    fresh: list[dict] = []
    dropped = 0
    now = datetime.now(timezone.utc)
    pops = max_pops if max_pops is not None else batch_size * 10
    for _ in range(pops):
        if len(fresh) >= batch_size:
            break
        item = await redis_client.cache.rpop(SIM_QUEUE_KEY)
        if item is None:
            break
        if not isinstance(item, dict):
            continue
        age = _age_seconds(item, now)
        if age is not None and max_lag_seconds > 0 and age > max_lag_seconds:
            dropped += 1
            continue
        fresh.append(item)
    if dropped:
        metrics.simulation_logs_dropped_total.inc(dropped)
        log.warning("sim_consumer.dropped_stale_logs", dropped=dropped, max_lag_s=max_lag_seconds)
    return fresh, dropped


async def _sim_queue_consumer():
    """
    Background task: analyse simulated logs at a fixed pace.

    One log-analysis run (one LLM call at most) per SIMULATION_ANALYSIS_INTERVAL_SECONDS
    keeps a free-tier quota predictable instead of draining it as fast as logs arrive.
    """
    from agents.log_analysis.agent import LogAnalysisAgent
    log_agent = LogAnalysisAgent()
    batch_size = max(settings.simulation_batch_size, 1)
    interval = max(settings.simulation_analysis_interval_seconds, 1)

    while True:
        try:
            batch, _ = await drain_sim_queue(batch_size, settings.simulation_max_lag_seconds)
            if batch:
                await log_agent._run_with_telemetry({"logs": batch, "source": "simulation"})
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("sim_consumer.error", error=str(exc))
            await asyncio.sleep(min(interval, 5.0))


async def _vuln_scan_scheduler(supervisor):
    """Run the vulnerability agent over the configured targets every VULN_SCAN_INTERVAL."""
    targets = settings.split_csv(settings.vuln_scan_targets)
    cves = [c.upper() for c in settings.split_csv(settings.vuln_watchlist_cves)]
    if not targets and not cves:
        return
    interval = max(settings.vuln_scan_interval, 60)
    while True:
        try:
            await supervisor._run_agent("vulnerability_intel", {"cve_ids": cves, "asset_ips": targets})
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("vuln_scheduler.error", error=str(exc))
        await asyncio.sleep(interval)


def _create_supervisor():
    from agents.supervisor.agent import SupervisorAgent
    return SupervisorAgent()


async def _cancel(*tasks: asyncio.Task) -> None:
    for task in tasks:
        task.cancel()
    with contextlib.suppress(Exception):
        await asyncio.gather(*tasks, return_exceptions=True)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # A missing database or Redis must not stop the API from serving /health and
    # /metrics — operators need those most precisely when a dependency is down.
    try:
        await init_db()
    except Exception as exc:
        log.warning("startup.migrations_failed", error=str(exc))

    try:
        await redis_client.get_redis().ping()
    except Exception as exc:
        log.warning("startup.redis_unavailable", error=str(exc))

    # Hash the accounts now so a disabled (default-password) account is reported at
    # startup rather than on the first failed login.
    await asyncio.to_thread(_users)

    app.state.supervisor = _create_supervisor()

    tasks = [
        asyncio.create_task(redis_listener()),
        asyncio.create_task(escalation_listener(app.state.supervisor)),
        asyncio.create_task(_vuln_scan_scheduler(app.state.supervisor)),
    ]
    if settings.simulation_mode and settings.simulation_consumer_enabled:
        tasks.append(asyncio.create_task(_sim_queue_consumer()))
    app.state.background_tasks = tasks

    try:
        yield
    finally:
        await _cancel(*tasks)
        await es_client.close_es_client()
        await redis_client.close_pools()


app = FastAPI(
    title="Cyber Defense Multi-Agent SOC Platform",
    description="AI-powered autonomous Security Operations Center",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(BaseHTTPMiddleware, dispatch=AuthMiddleware())
# Outermost so it observes the real status code and latency of every request,
# including those short-circuited by the auth middleware.
app.add_middleware(PrometheusMiddleware)

# Prometheus metrics endpoint. Served as a route rather than a sub-app mount so that
# `GET /metrics` answers directly — a mount replies 307 to /metrics/, and that is the
# exact path infra/monitoring/prometheus.yml scrapes.
@app.get("/metrics", include_in_schema=False)
async def metrics_endpoint() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

# Routers
app.include_router(health.router, tags=["health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(agents.router, prefix="/api/v1/agents", tags=["agents"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["incidents"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["threats"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])
app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["compliance"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(logs.router, prefix="/api/v1/logs", tags=["logs"])
app.include_router(ws_router)
