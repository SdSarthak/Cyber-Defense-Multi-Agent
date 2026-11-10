"""
Prometheus instrumentation.

The metric names here are the ones the provisioned Grafana dashboard
(`infra/monitoring/grafana/dashboards/soc_overview.json`) queries:
  - http_requests_total{method,handler,status}
  - http_request_duration_seconds_bucket{method,handler}
  - websocket_connections_active

plus SOC-specific series used for agent observability.
"""
from __future__ import annotations
import time
from prometheus_client import Counter, Gauge, Histogram
from starlette.types import ASGIApp, Receive, Scope, Send

# ── HTTP ──────────────────────────────────────────────────────────────────────

http_requests_total = Counter(
    "http_requests_total",
    "Total HTTP requests processed by the API",
    ["method", "handler", "status"],
)

http_request_duration_seconds = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "handler"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

# ── WebSocket ─────────────────────────────────────────────────────────────────

websocket_connections_active = Gauge(
    "websocket_connections_active",
    "Currently connected dashboard WebSocket clients",
)

# ── Agents ────────────────────────────────────────────────────────────────────

agent_runs_total = Counter(
    "agent_runs_total",
    "Agent task executions",
    ["agent", "outcome"],
)

agent_run_duration_seconds = Histogram(
    "agent_run_duration_seconds",
    "Agent task duration in seconds",
    ["agent"],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0),
)

# ── SOC domain ────────────────────────────────────────────────────────────────

threat_events_total = Counter(
    "threat_events_total",
    "Threat events classified by the detection agent",
    ["severity", "threat_type"],
)

escalations_total = Counter(
    "escalations_total",
    "Escalations raised by agents",
    ["agent"],
)

incidents_total = Counter(
    "incidents_total",
    "Incidents opened by the incident response agent",
    ["playbook"],
)

simulation_logs_dropped_total = Counter(
    "simulation_logs_dropped_total",
    "Queued simulation logs discarded because they were older than SIMULATION_MAX_LAG_SECONDS",
)

# ── Label hygiene ─────────────────────────────────────────────────────────────
# Several labels used to take free text straight from LLM output, so every novel
# phrasing ("Brute-Force (SSH)") minted a new time series. Clamp them to known sets.

KNOWN_SEVERITIES = ("critical", "high", "medium", "low", "info")
KNOWN_THREAT_TYPES = (
    "port_scan", "brute_force", "sql_injection", "xss", "path_traversal",
    "command_injection", "c2_beacon", "data_exfiltration", "ransomware", "malware",
    "phishing", "privilege_escalation", "lateral_movement", "dos", "none", "unknown",
)


def severity_label(value) -> str:
    text = str(value or "").strip().lower()
    return text if text in KNOWN_SEVERITIES else "unknown"


def threat_type_label(value) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if text in KNOWN_THREAT_TYPES:
        return text
    for known in KNOWN_THREAT_TYPES:
        if known not in ("none", "unknown") and known in text:
            return known
    return "other"


_THREAT_LEVELS = {"low": 1, "medium": 2, "high": 3, "critical": 4}

soc_threat_level = Gauge(
    "soc_threat_level",
    "Current SOC threat level (1=low, 2=medium, 3=high, 4=critical)",
)
soc_threat_level.set(_THREAT_LEVELS["low"])


def set_threat_level(level: str) -> None:
    """Record the blackboard threat level as a numeric gauge."""
    soc_threat_level.set(_THREAT_LEVELS.get(str(level).lower(), 1))


# ── ASGI middleware ───────────────────────────────────────────────────────────

UNMATCHED_HANDLER = "<unmatched>"


def _route_template(route) -> str | None:
    return getattr(route, "path_format", None) or getattr(route, "path", None)


def _handler_label(scope: Scope) -> str:
    """
    The matched route template (``/api/v1/incidents/{incident_id}``), never the raw path.

    ``scope["route"]`` is only set when routing ran. A request the auth middleware
    rejected never reaches the router, and a 404 matches nothing — both used to fall
    back to the raw path, so anonymous junk requests minted one series per URL.
    Resolve the template against the app's routes instead, and give anything that
    matches no route a single shared label.
    """
    template = _route_template(scope.get("route"))
    if template:
        return template

    app = scope.get("app")
    router = getattr(app, "router", None)
    if router is not None:
        from starlette.routing import Match
        for route in getattr(router, "routes", []):
            try:
                match, _ = route.matches(scope)
            except Exception:
                continue
            if match == Match.FULL:
                template = _route_template(route)
                if template:
                    return template
    return UNMATCHED_HANDLER


class PrometheusMiddleware:
    """Pure-ASGI middleware recording request counts and latency."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        started = time.perf_counter()
        status_holder = {"code": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            # `scope["route"]` is only populated once routing has run, so the label
            # must be resolved after the downstream app has been called.
            handler = _handler_label(scope)
            elapsed = time.perf_counter() - started
            http_requests_total.labels(
                method=method, handler=handler, status=str(status_holder["code"])
            ).inc()
            http_request_duration_seconds.labels(method=method, handler=handler).observe(elapsed)
