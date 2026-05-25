import asyncio
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from prometheus_client import make_asgi_app

from core.config import settings
from core.database.base import init_db
from core.database.redis_client import get_redis, cache
from api.routes import agents, incidents, threats, vulnerabilities, compliance, reports, health, auth
from api.websocket.manager import ws_router, redis_listener
from api.middleware.auth import AuthMiddleware


async def _sim_queue_consumer():
    """Background task: drain sim:log_queue and feed batches to the log-analysis agent."""
    from agents.log_analysis.agent import LogAnalysisAgent
    log_agent = LogAnalysisAgent()

    while True:
        try:
            raw = await cache.rpop("sim:log_queue")
            if raw is None:
                await asyncio.sleep(0.5)
                continue
            # Accumulate up to 20 entries per batch without blocking
            entries = [raw]
            for _ in range(19):
                item = await cache.rpop("sim:log_queue")
                if item is None:
                    break
                entries.append(item)

            logs = []
            for e in entries:
                if isinstance(e, dict):
                    logs.append(e)
                else:
                    try:
                        logs.append(json.loads(e))
                    except Exception:
                        pass

            if logs:
                await log_agent.run({"logs": logs, "source": "simulation"})
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(1.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    redis = get_redis()
    await redis.ping()
    app.state.supervisor = _create_supervisor()

    # Start background tasks — these replace the deprecated @on_event("startup") pattern
    listener_task = asyncio.create_task(redis_listener())
    consumer_task = asyncio.create_task(_sim_queue_consumer())

    yield

    listener_task.cancel()
    consumer_task.cancel()
    try:
        await asyncio.gather(listener_task, consumer_task, return_exceptions=True)
    except Exception:
        pass
    await redis.aclose()


def _create_supervisor():
    from agents.supervisor.agent import SupervisorAgent
    return SupervisorAgent()


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

# Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

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
