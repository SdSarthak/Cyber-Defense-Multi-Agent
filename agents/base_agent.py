"""Shared base class for all security agents."""
from __future__ import annotations
import asyncio
import threading
import time
import uuid
from abc import ABC, abstractmethod

import structlog

from core import metrics
from core.config import settings
from core.database import redis_client, repository
from core.memory.agent_memory import AgentMemory

log = structlog.get_logger()

PAUSE_KEY_PREFIX = "agent_paused:"
ESCALATION_STREAM = "escalations:stream"

_rate_limiter = None
_rate_limiter_lock = threading.Lock()


def shared_rate_limiter():
    """
    One token bucket for every Gemini call in the process.

    Each agent used to call the API as fast as its graph ran, so a burst (a scenario
    injection, a compliance run, the simulator backlog) turned straight into 429s.
    """
    global _rate_limiter
    rpm = float(settings.llm_requests_per_minute or 0)
    if rpm <= 0:
        return None
    with _rate_limiter_lock:
        if _rate_limiter is None:
            import warnings
            from langchain_core.rate_limiters import InMemoryRateLimiter
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # LangChainBetaWarning on construction
                _rate_limiter = InMemoryRateLimiter(
                    requests_per_second=rpm / 60.0,
                    check_every_n_seconds=0.1,
                    max_bucket_size=max(1.0, rpm / 10.0),
                )
    return _rate_limiter


class AgentPausedError(RuntimeError):
    """Raised when a task is dispatched to an agent a human operator has paused."""


class BaseSecurityAgent(ABC):
    name: str = "base_agent"
    description: str = "Base security agent"

    def __init__(self):
        self.memory = AgentMemory(self.name)
        self._llm = None

    @property
    def llm(self):
        """
        The Gemini chat model, built on first use.

        Constructing it lazily means an agent can be instantiated (and its LangGraph
        compiled) without a GOOGLE_API_KEY present — which keeps imports, tests and
        `--help`-style startup paths working on a machine with no credentials.
        """
        if self._llm is None:
            from langchain_google_genai import ChatGoogleGenerativeAI
            self._llm = ChatGoogleGenerativeAI(
                model=settings.gemini_model,
                google_api_key=settings.google_api_key,
                temperature=0.1,
                max_retries=settings.llm_max_retries,
                rate_limiter=shared_rate_limiter(),
            )
        return self._llm

    @property
    def timeout_seconds(self) -> int:
        return settings.agent_timeout_seconds

    @abstractmethod
    async def run(self, input_data: dict) -> dict:
        """Execute the agent's primary task."""
        ...

    # ── Human-in-the-loop controls ───────────────────────────────────────────

    async def is_paused(self) -> bool:
        try:
            return bool(await redis_client.cache.exists(f"{PAUSE_KEY_PREFIX}{self.name}"))
        except Exception:
            return False

    @classmethod
    async def pause(cls, agent_name: str, ttl: int | None = None) -> None:
        """
        Pause until resumed. A pause is a security control, so by default it does not
        expire: the old one-hour TTL silently resumed the agent while the status hash
        (which had no TTL) kept reporting it as paused.
        """
        await redis_client.cache.set(f"{PAUSE_KEY_PREFIX}{agent_name}", {"paused": True}, ttl=ttl)
        await redis_client.cache.hset(f"agent_status:{agent_name}", {"status": "disabled", "task_id": ""})

    @classmethod
    async def resume(cls, agent_name: str) -> None:
        await redis_client.cache.delete(f"{PAUSE_KEY_PREFIX}{agent_name}")
        await redis_client.cache.hset(f"agent_status:{agent_name}", {"status": "idle", "task_id": ""})

    # ── Telemetry wrapper ────────────────────────────────────────────────────

    async def _record_failure(
        self, task_id: str, input_data: dict, started: float, outcome: str, error: str
    ) -> None:
        duration_ms = int((time.time() - started) * 1000)
        metrics.agent_runs_total.labels(agent=self.name, outcome=outcome).inc()
        await self._safe_hset({"status": "error" if outcome != "cancelled" else "idle", "task_id": ""})
        await self.memory.log_event({"type": "task_error", "task_id": task_id, "error": error})
        await repository.record_agent_heartbeat(
            self.name, "error" if outcome != "cancelled" else "idle", failed=True
        )
        await repository.save_agent_action(
            self.name, "run", description=error, input_data=input_data,
            success=False, duration_ms=duration_ms,
        )
        await self._safe_publish("agent_events", {
            "agent": self.name, "event": "task_error", "task_id": task_id,
            "outcome": outcome, "error": error[:500],
        })

    async def _run_with_telemetry(self, input_data: dict) -> dict:
        task_id = str(uuid.uuid4())
        started = time.time()

        if await self.is_paused():
            metrics.agent_runs_total.labels(agent=self.name, outcome="skipped").inc()
            summary = f"Agent {self.name} is paused by operator override — task skipped"
            log.info("agent.paused_skip", agent=self.name, task_id=task_id)
            return {"summary": summary, "skipped": True, "paused": True, "task_id": task_id}

        await self.memory.log_event({"type": "task_start", "task_id": task_id, "input": input_data})
        await self._safe_hset({"status": "running", "task_id": task_id})
        await repository.record_agent_heartbeat(self.name, "running", current_task=task_id)
        await self._safe_publish("agent_events", {
            "agent": self.name, "event": "task_start", "task_id": task_id,
        })

        try:
            result = await asyncio.wait_for(self.run(input_data), timeout=self.timeout_seconds)
        except asyncio.TimeoutError:
            await self._record_failure(
                task_id, input_data, started, "timeout", f"timed out after {self.timeout_seconds}s"
            )
            log.warning("agent.timeout", agent=self.name, task_id=task_id)
            raise
        except asyncio.CancelledError:
            # A parent timeout (the supervisor's) or shutdown cancels us. CancelledError
            # is a BaseException, so without this branch the status stayed "running"
            # forever. Record it, then let the cancellation propagate.
            await asyncio.shield(self._record_failure(
                task_id, input_data, started, "cancelled", "cancelled before completion"
            ))
            log.warning("agent.cancelled", agent=self.name, task_id=task_id)
            raise
        except Exception as exc:
            await self._record_failure(task_id, input_data, started, "error", str(exc))
            log.warning("agent.error", agent=self.name, task_id=task_id, error=str(exc))
            raise

        duration_ms = int((time.time() - started) * 1000)
        metrics.agent_runs_total.labels(agent=self.name, outcome="success").inc()
        metrics.agent_run_duration_seconds.labels(agent=self.name).observe(duration_ms / 1000)

        summary = result.get("summary", "") if isinstance(result, dict) else ""
        await self.memory.log_event({
            "type": "task_complete", "task_id": task_id, "duration_ms": duration_ms,
            "summary": summary,
        })
        await self._safe_hset({"status": "idle", "task_id": ""})
        await repository.record_agent_heartbeat(self.name, "idle", completed=True)
        await repository.save_agent_action(
            self.name, "run",
            description=summary,
            input_data=input_data, output_data=result if isinstance(result, dict) else None,
            success=True, duration_ms=duration_ms,
            incident_id=result.get("incident_id") if isinstance(result, dict) else None,
        )

        # Broadcast to dashboard via Redis pub/sub
        await self._safe_publish("agent_events", {
            "agent": self.name,
            "event": "task_complete",
            "task_id": task_id,
            "duration_ms": duration_ms,
            "result_summary": summary,
        })
        return result

    # ── Redis helpers that never bring down an analysis run ──────────────────

    async def _safe_hset(self, mapping: dict) -> None:
        try:
            await redis_client.cache.hset(f"agent_status:{self.name}", mapping)
        except Exception as exc:
            log.warning("agent.status_write_failed", agent=self.name, error=str(exc))

    async def _safe_publish(self, channel: str, message: dict) -> None:
        try:
            await redis_client.cache.publish(channel, message)
        except Exception as exc:
            log.warning("agent.publish_failed", agent=self.name, channel=channel, error=str(exc))

    async def escalate(self, payload: dict) -> None:
        """
        Raise an escalation. Never raises.

        The stream entry is the durable copy the supervisor consumes (it survives the
        API being down and is acknowledged only once handled); the pub/sub message
        feeds the live dashboard.
        """
        metrics.escalations_total.labels(agent=self.name).inc()
        message = {"agent": self.name, **payload}
        try:
            await redis_client.cache.xadd(ESCALATION_STREAM, message)
        except Exception as exc:
            log.warning("agent.escalation_enqueue_failed", agent=self.name, error=str(exc))
        await self._safe_publish("escalations", message)
