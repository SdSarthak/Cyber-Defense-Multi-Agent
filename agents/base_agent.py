"""Shared base class for all security agents."""
from __future__ import annotations
import asyncio
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
            )
        return self._llm

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
    async def pause(cls, agent_name: str, ttl: int = 3600) -> None:
        await redis_client.cache.set(f"{PAUSE_KEY_PREFIX}{agent_name}", {"paused": True}, ttl=ttl)
        await redis_client.cache.hset(f"agent_status:{agent_name}", {"status": "disabled", "task_id": ""})

    @classmethod
    async def resume(cls, agent_name: str) -> None:
        await redis_client.cache.delete(f"{PAUSE_KEY_PREFIX}{agent_name}")
        await redis_client.cache.hset(f"agent_status:{agent_name}", {"status": "idle", "task_id": ""})

    # ── Telemetry wrapper ────────────────────────────────────────────────────

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
        await repository.record_agent_heartbeat(
            self.name, "running", current_task=task_id
        )

        try:
            result = await asyncio.wait_for(
                self.run(input_data), timeout=settings.agent_timeout_seconds
            )
        except asyncio.TimeoutError:
            duration_ms = int((time.time() - started) * 1000)
            metrics.agent_runs_total.labels(agent=self.name, outcome="timeout").inc()
            await self._safe_hset({"status": "error", "task_id": task_id})
            await self.memory.log_event({
                "type": "task_error", "task_id": task_id,
                "error": f"timed out after {settings.agent_timeout_seconds}s",
            })
            await repository.record_agent_heartbeat(self.name, "error", failed=True)
            await repository.save_agent_action(
                self.name, "run", description="timeout", input_data=input_data,
                success=False, duration_ms=duration_ms,
            )
            log.warning("agent.timeout", agent=self.name, task_id=task_id)
            raise
        except Exception as exc:
            duration_ms = int((time.time() - started) * 1000)
            metrics.agent_runs_total.labels(agent=self.name, outcome="error").inc()
            await self._safe_hset({"status": "error", "task_id": task_id})
            await self.memory.log_event({"type": "task_error", "task_id": task_id, "error": str(exc)})
            await repository.record_agent_heartbeat(self.name, "error", failed=True)
            await repository.save_agent_action(
                self.name, "run", description=str(exc), input_data=input_data,
                success=False, duration_ms=duration_ms,
            )
            log.warning("agent.error", agent=self.name, task_id=task_id, error=str(exc))
            raise

        duration_ms = int((time.time() - started) * 1000)
        metrics.agent_runs_total.labels(agent=self.name, outcome="success").inc()
        metrics.agent_run_duration_seconds.labels(agent=self.name).observe(duration_ms / 1000)

        await self.memory.log_event({
            "type": "task_complete", "task_id": task_id, "duration_ms": duration_ms,
            "summary": result.get("summary", "") if isinstance(result, dict) else "",
        })
        await self._safe_hset({"status": "idle", "task_id": ""})
        await repository.record_agent_heartbeat(self.name, "idle", completed=True)
        await repository.save_agent_action(
            self.name, "run",
            description=result.get("summary", "") if isinstance(result, dict) else "",
            input_data=input_data, output_data=result if isinstance(result, dict) else None,
            success=True, duration_ms=duration_ms,
        )

        # Broadcast to dashboard via Redis pub/sub
        await self._safe_publish("agent_events", {
            "agent": self.name,
            "event": "task_complete",
            "task_id": task_id,
            "duration_ms": duration_ms,
            "result_summary": result.get("summary", "") if isinstance(result, dict) else "",
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
        """Publish an escalation and count it. Never raises."""
        metrics.escalations_total.labels(agent=self.name).inc()
        await self._safe_publish("escalations", {"agent": self.name, **payload})
