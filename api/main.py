from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from prometheus_client import make_asgi_app

from core.config import settings
from core.database.base import init_db
from core.database.redis_client import get_redis
from api.routes import agents, incidents, threats, vulnerabilities, compliance, reports, health
from api.websocket.manager import ws_router
from api.middleware.auth import AuthMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    redis = get_redis()
    await redis.ping()
    app.state.supervisor = _create_supervisor()
    yield
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

# Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Routers
app.include_router(health.router, tags=["health"])
app.include_router(agents.router, prefix="/api/v1/agents", tags=["agents"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["incidents"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["threats"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])
app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["compliance"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
app.include_router(ws_router)
