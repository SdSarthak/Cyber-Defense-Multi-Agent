"""
Containment execution.

The incident-response agent used to "run" automated actions through a stub that
always returned success, so the dashboard showed firewall blocks and host isolations
as completed when nothing had happened. Actions now go through one of two executors:

* ``simulate`` (default): records the action as ``simulated`` — explicitly *not*
  completed — so nobody mistakes a plan for an executed response.
* ``webhook``: POSTs the action to ``CONTAINMENT_WEBHOOK_URL`` (a SOAR playbook,
  firewall automation, or any HTTP endpoint you control). A 2xx reply marks it
  ``completed``; anything else ``failed``.

With ``CONTAINMENT_REQUIRE_APPROVAL`` (default on) automated actions wait in
``pending_approval`` until an admin approves them through the API.
"""
from __future__ import annotations

import asyncio

import aiohttp
import structlog

from core.config import settings

log = structlog.get_logger()

PENDING_APPROVAL = "pending_approval"
APPROVABLE_STATUSES = (PENDING_APPROVAL, "pending")


async def execute(action: str, incident: dict) -> dict:
    """Run one containment action. Never raises; the result says what happened."""
    mode = str(settings.containment_mode or "simulate").lower()
    if mode == "webhook" and settings.containment_webhook_url:
        return await _webhook(action, incident)
    return {
        "success": True,
        "status": "simulated",
        "executor": "simulate",
        "action": action,
        "note": "No containment integration configured (CONTAINMENT_MODE=simulate); nothing was executed.",
    }


async def _webhook(action: str, incident: dict) -> dict:
    payload = {
        "action": action,
        "incident": {
            k: incident.get(k)
            for k in ("id", "incident_id", "title", "type", "severity", "affected_assets")
            if incident.get(k) is not None
        },
    }
    try:
        timeout = aiohttp.ClientTimeout(total=settings.containment_webhook_timeout_seconds)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(settings.containment_webhook_url, json=payload) as resp:
                body = (await resp.text())[:500]
                ok = 200 <= resp.status < 300
                return {
                    "success": ok,
                    "status": "completed" if ok else "failed",
                    "executor": "webhook",
                    "action": action,
                    "http_status": resp.status,
                    "response": body,
                }
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        log.warning("containment.webhook_failed", action=action, error=str(exc))
        return {"success": False, "status": "failed", "executor": "webhook", "action": action,
                "error": str(exc) or exc.__class__.__name__}
