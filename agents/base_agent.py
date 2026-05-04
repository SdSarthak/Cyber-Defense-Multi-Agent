"""Shared base class for all security agents."""
from __future__ import annotations
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any
from langchain_google_genai import ChatGoogleGenerativeAI
from core.config import settings
from core.memory.agent_memory import AgentMemory
from core.database.redis_client import cache


class BaseSecurityAgent(ABC):
    name: str = "base_agent"
    description: str = "Base security agent"

    def __init__(self):
        self.memory = AgentMemory(self.name)
        self._llm = ChatGoogleGenerativeAI(
            model=settings.gemini_model,
            google_api_key=settings.google_api_key,
            temperature=0.1,
        )

    @property
    def llm(self) -> ChatGoogleGenerativeAI:
        return self._llm

    @abstractmethod
    async def run(self, input_data: dict) -> dict:
        """Execute the agent's primary task."""
        ...

    async def _run_with_telemetry(self, input_data: dict) -> dict:
        task_id = str(uuid.uuid4())
        started = time.time()
        await self.memory.log_event({"type": "task_start", "task_id": task_id, "input": input_data})
        await cache.hset(f"agent_status:{self.name}", {"status": "running", "task_id": task_id})
        try:
            result = await self.run(input_data)
            duration_ms = int((time.time() - started) * 1000)
            await self.memory.log_event({"type": "task_complete", "task_id": task_id, "duration_ms": duration_ms})
            await cache.hset(f"agent_status:{self.name}", {"status": "idle", "task_id": ""})
            # Broadcast to dashboard via Redis pub/sub
            await cache.publish("agent_events", {
                "agent": self.name,
                "event": "task_complete",
                "task_id": task_id,
                "duration_ms": duration_ms,
                "result_summary": result.get("summary", ""),
            })
            return result
        except Exception as e:
            await cache.hset(f"agent_status:{self.name}", {"status": "error", "task_id": task_id})
            await self.memory.log_event({"type": "task_error", "task_id": task_id, "error": str(e)})
            raise
