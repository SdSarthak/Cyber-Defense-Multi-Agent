"""
The SOC-wide threat level, shared through the blackboard.

It used to be last-writer-wins: every supervisor run wrote whatever level it computed
(usually "low"), so a benign run seconds after a critical escalation reset the banner
to LOW, and a human override lasted only until the next run.

Policy here:
  * automated proposals may always *raise* the level;
  * they may only *lower* it once the current level has stood for
    ``threat_level_hold_seconds`` (the condition has to actually go quiet);
  * a human override sets the level outright — up or down — and restarts the hold;
  * the keys expire after an hour without reaffirmation, which decays to "low".
"""
from __future__ import annotations

import time

from core import metrics
from core.config import settings
from core.memory.agent_memory import AgentMemory

LEVELS = ("low", "medium", "high", "critical")
RANK = {level: i for i, level in enumerate(LEVELS)}
_ALIASES = {"info": "low", "informational": "low", "none": "low", "normal": "low"}

LEVEL_KEY = "threat_level"
META_KEY = "threat_level_meta"
TTL_SECONDS = 3600


def normalize(level) -> str | None:
    """Map free-form severity text onto a threat level, or None when it is not one."""
    text = str(level or "").strip().lower()
    text = _ALIASES.get(text, text)
    return text if text in RANK else None


async def current() -> tuple[str, dict]:
    meta = await AgentMemory.blackboard_get(META_KEY)
    if not isinstance(meta, dict):
        meta = {}
    level = normalize(meta.get("level")) or normalize(await AgentMemory.blackboard_get(LEVEL_KEY)) or "low"
    return level, meta


async def _store(level: str, source: str) -> None:
    meta = {"level": level, "set_at": time.time(), "source": source}
    await AgentMemory.blackboard_set(META_KEY, meta, ttl=TTL_SECONDS)
    await AgentMemory.blackboard_set(LEVEL_KEY, level, ttl=TTL_SECONDS)
    metrics.set_threat_level(level)


async def propose(level, source: str) -> str:
    """
    Apply an automated assessment and return the level now in force.

    Unknown values are treated as "low" (an assessment that found nothing actionable).
    """
    proposed = normalize(level) or "low"
    existing, meta = await current()
    if RANK[proposed] >= RANK[existing]:
        await _store(proposed, source)
        return proposed

    held_for = time.time() - float(meta.get("set_at") or 0)
    if held_for >= settings.threat_level_hold_seconds:
        await _store(proposed, source)
        return proposed
    return existing


async def override(level, user: str) -> str:
    """Operator override. Raises ValueError for anything that is not a threat level."""
    normalized = normalize(level)
    if normalized is None:
        raise ValueError(f"threat_level must be one of {list(LEVELS)}")
    await _store(normalized, f"human:{user}")
    return normalized
