import asyncio
import contextlib

import structlog
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from core.config import settings
from core.database.base import init_db
from core.database import es_client, redis_client
from core.metrics import PrometheusMiddleware
from api.routes import agents, incidents, threats, vulnerabilities, compliance, reports, health, auth
from api.websocket.manager import ws_router, redis_listener, escalation_listener
from api.middleware.auth import AuthMiddleware

log = structlog.get_logger()


async def _sim_queue_consumer():
    """Background task: drain sim:log_queue and feed batches to the log-analysis agent."""
    from agents.log_analysis.agent import LogAnalysisAgent
    log_agent = LogAnalysisAgent()
    batch_size = max(settings.simulation_batch_size, 1)

    while True:
        try:
            raw = await redis_client.cache.rpop("sim:log_queue")
            if raw is None:
                await asyncio.sleep(0.5)
                continue

            # Accumulate up to `batch_size` entries per run without blocking.
            entries = [raw]
            for _ in range(batch_size - 1):
                item = await redis_client.cache.rpop("sim:log_queue")
                if item is None:
                    break
                entries.append(item)

            logs = [e for e in entries if isinstance(e, dict)]
            if logs:
                await log_agent._run_with_telemetry({"logs": logs, "source": "simulation"})
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("sim_consumer.error", error=str(exc))
            await asyncio.sleep(1.0)


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
        log.warning("startup.init_db_failed", error=str(exc))

    try:
        await redis_client.get_redis().ping()
    except Exception as exc:
        log.warning("startup.redis_unavailable", error=str(exc))

    app.state.supervisor = _create_supervisor()

    tasks = [
        asyncio.create_task(redis_listener()),
        asyncio.create_task(escalation_listener(app.state.supervisor)),
    ]
    if settings.simulation_mode and settings.simulation_consumer_enabled:
        tasks.append(asyncio.create_task(_sim_queue_consumer()))
    app.state.background_tasks = tasks

    try:
        yield
    finally:
        await _cancel(*tasks)
        await es_client.close_es_client()
        with contextlib.suppress(Exception):
            await redis_client.get_redis().aclose()


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
app.include_router(ws_router)
