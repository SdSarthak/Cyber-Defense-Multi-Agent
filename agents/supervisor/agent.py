"""Supervisor Agent — LangGraph orchestrator that routes tasks to specialist agents."""
from __future__ import annotations
import asyncio
import hashlib
import json
import re
from typing import TypedDict, Annotated, Literal
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from agents.threat_detection.agent import ThreatDetectionAgent
from agents.log_analysis.agent import LogAnalysisAgent
from agents.vulnerability_intel.agent import VulnerabilityIntelAgent
from agents.incident_response.agent import IncidentResponseAgent
from agents.compliance.agent import ComplianceAgent, FRAMEWORKS
from agents.reporting.agent import ReportingAgent
from core import metrics, threat_level as threat_levels
from core.config import settings
from core.database import redis_client
from core.memory.agent_memory import AgentMemory
from core.parsing import parse_json_response

ROUTER_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are the SOC Supervisor Agent. Analyse the incoming task and decide which specialist agents to invoke.

Available agents:
- threat_detection: Analyse a specific security event for threats and IOCs
- log_analysis: Process a batch of log entries for anomalies
- vulnerability_intel: Look up CVEs and assess asset exposure
- incident_response: Execute response playbook for a confirmed incident
- compliance: Evaluate compliance posture for a framework
- reporting: Generate executive or threat intelligence report
- all: Invoke all agents (for full security assessment)

Return JSON:
{{
  "agents": ["agent1", "agent2"],
  "reasoning": str,
  "priority": "immediate|high|normal|low",
  "parallel": bool
}}
Return ONLY valid JSON."""),
    ("human", "Task:\n{task}\n\nCurrent threat level from blackboard:\n{threat_level}"),
])

AgentName = Literal[
    "threat_detection", "log_analysis", "vulnerability_intel",
    "incident_response", "compliance", "reporting"
]


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
REPORT_TYPES = ("executive", "threat")


def _as_bool(value, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "y")
    if value is None:
        return default
    return bool(value)


def _ip_candidates(*values) -> list[str]:
    import ipaddress
    out: list[str] = []
    for v in values:
        try:
            ipaddress.ip_address(str(v))
        except ValueError:
            continue
        if str(v) not in out:
            out.append(str(v))
    return out


def _as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class SupervisorState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    task: dict
    routing_decision: dict
    agent_results: dict
    final_report: dict
    summary: str


class SupervisorAgent(BaseSecurityAgent):
    name = "supervisor"
    description = "Orchestrates all security agents and coordinates the SOC mesh"

    def __init__(self):
        super().__init__()
        self._agents: dict[str, BaseSecurityAgent] = {
            "threat_detection": ThreatDetectionAgent(),
            "log_analysis": LogAnalysisAgent(),
            "vulnerability_intel": VulnerabilityIntelAgent(),
            "incident_response": IncidentResponseAgent(),
            "compliance": ComplianceAgent(),
            "reporting": ReportingAgent(),
        }
        self._graph = self._build_graph()

    @property
    def timeout_seconds(self) -> int:
        # The supervisor waits on routing, every dispatched agent (each with its own
        # agent_timeout_seconds) and a follow-up report. Sharing the per-agent budget
        # meant it routinely timed out and cancelled its children mid-run.
        return settings.supervisor_timeout_seconds

    # ── Per-agent task shaping ───────────────────────────────────────────────

    @staticmethod
    def _heuristic_agents(task: dict) -> list[str]:
        """Route on the task's shape when the LLM router is unavailable."""
        agents = []
        if isinstance(task.get("logs"), list) and task["logs"]:
            agents.append("log_analysis")
        if task.get("cve_ids") or task.get("asset_ips") or _CVE_RE.search(json.dumps(task, default=str)):
            agents.append("vulnerability_intel")
        if isinstance(task.get("incident"), dict):
            agents.append("incident_response")
        if task.get("framework") in FRAMEWORKS:
            agents.append("compliance")
        if task.get("report_type") in REPORT_TYPES:
            agents.append("reporting")
        return agents or ["threat_detection"]

    def _task_for(self, name: str, task: dict) -> dict | None:
        """
        Build the input a specialist actually understands, or None when the task holds
        nothing for it.

        Every agent used to receive the same task dict, but each expects a different
        shape (an event, a log batch, CVE ids, an incident, a framework…), so an
        "all" run was mostly agents reporting "No logs provided" after spending a turn.
        """
        if name == "threat_detection":
            event = task.get("event")
            return event if isinstance(event, dict) else task
        if name == "log_analysis":
            logs = task.get("logs")
            return {"logs": logs, "source": task.get("source", "supervisor")} if isinstance(logs, list) and logs else None
        if name == "vulnerability_intel":
            cves = [c for c in (task.get("cve_ids") or []) if isinstance(c, str)]
            if not cves:
                cves = sorted({m.upper() for m in _CVE_RE.findall(json.dumps(task, default=str))})
            ips = [i for i in (task.get("asset_ips") or []) if isinstance(i, str)]
            return {"cve_ids": cves, "asset_ips": ips} if cves or ips else None
        if name == "incident_response":
            incident = task.get("incident")
            if not isinstance(incident, dict):
                incident = {
                    "title": str(task.get("title") or task.get("description") or "Supervisor-routed incident")[:255],
                    "type": task.get("threat_type") or task.get("type") or "unknown",
                    "severity": task.get("severity") or "medium",
                    "description": json.dumps(task, default=str)[:1000],
                    "affected_assets": _ip_candidates(task.get("source_ip"), task.get("destination_ip")),
                }
            return {"incident": incident, "threat_assessment": task.get("threat_assessment") or {}}
        if name == "compliance":
            framework = task.get("framework") if task.get("framework") in FRAMEWORKS else "SOC2"
            return {"framework": framework, "evidence": task.get("evidence") or {}}
        if name == "reporting":
            report_type = task.get("report_type") if task.get("report_type") in REPORT_TYPES else "executive"
            return {**task, "report_type": report_type}
        return task

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(SupervisorState)
        graph.add_node("route", self._route)
        graph.add_node("dispatch", self._dispatch)
        graph.add_node("synthesise", self._synthesise)
        graph.set_entry_point("route")
        graph.add_edge("route", "dispatch")
        graph.add_edge("dispatch", "synthesise")
        graph.add_edge("synthesise", END)
        return graph.compile()

    async def _route(self, state: SupervisorState) -> dict:
        current_level, _ = await threat_levels.current()
        decision = None
        try:
            chain = ROUTER_PROMPT | self.llm
            resp = await chain.ainvoke({
                "task": json.dumps(state["task"], default=str)[:6000],
                "threat_level": current_level,
            })
            decision = parse_json_response(resp.content)
            reason = "parse error fallback"
        except Exception as exc:
            # A quota error or outage must not stop the mesh: route on the task's shape.
            reason = f"router unavailable ({exc.__class__.__name__}); routed on task shape"
        if decision is None:
            decision = {
                "agents": self._heuristic_agents(state["task"]), "reasoning": reason,
                "priority": "normal", "parallel": True,
            }

        agents = decision.get("agents") or []
        if not isinstance(agents, list):
            agents = [str(agents)]
        if "all" in agents:
            agents = list(self._agents.keys())

        # Drop hallucinated agent names before dispatch so a bad routing decision
        # degrades to "nothing to do" instead of a KeyError mid-run.
        known = [a for a in agents if a in self._agents]
        if not known:
            known = ["threat_detection"]
            decision["reasoning"] = (
                f"{decision.get('reasoning', '')} | no known agents in routing decision, "
                f"defaulted to threat_detection"
            ).strip(" |")
        decision["agents"] = known

        await self._safe_publish("agent_events", {
            "agent": self.name,
            "event": "routing_decision",
            "decision": decision,
        })
        return {
            "routing_decision": decision,
            "messages": [AIMessage(content=f"Routing to: {decision.get('agents')} | Priority: {decision.get('priority')}")],
        }

    async def _dispatch(self, state: SupervisorState) -> dict:
        decision = state["routing_decision"]
        agents_to_run = [n for n in decision.get("agents", []) if n in self._agents]
        parallel = _as_bool(decision.get("parallel"), default=True)
        results: dict[str, dict] = {}

        runnable: list[tuple[str, dict]] = []
        for name in agents_to_run:
            sub_task = self._task_for(name, state["task"])
            if sub_task is None:
                results[name] = {"skipped": True, "summary": f"{name}: nothing in the task for this agent"}
            else:
                runnable.append((name, sub_task))

        if parallel:
            gathered = await asyncio.gather(
                *(self._run_agent(name, sub_task) for name, sub_task in runnable),
                return_exceptions=True,
            )
            for (name, _), outcome in zip(runnable, gathered):
                if isinstance(outcome, BaseException):
                    results[name] = {"error": str(outcome), "summary": f"Agent {name} failed: {outcome}"}
                else:
                    results[name] = outcome
        else:
            for name, sub_task in runnable:
                try:
                    results[name] = await self._run_agent(name, sub_task)
                except Exception as e:
                    results[name] = {"error": str(e), "summary": f"Agent {name} failed: {e}"}

        # Only summaries go on the blackboard — full results can be megabytes and the
        # blackboard is read on every routing decision.
        await AgentMemory.blackboard_update(
            "last_agent_results",
            {name: r.get("summary", "") for name, r in results.items()},
        )
        succeeded = sum(1 for r in results.values() if "error" not in r and not r.get("skipped"))
        return {
            "agent_results": results,
            "messages": [AIMessage(
                content=f"Dispatched {len(runnable)} agents, {succeeded} succeeded"
            )],
        }

    async def _synthesise(self, state: SupervisorState) -> dict:
        results = state["agent_results"]
        summaries = [f"[{name}] {r.get('summary', 'no summary')}" for name, r in results.items()]

        # Determine overall threat level from results
        severities: list[str] = []
        for r in results.values():
            severity = r.get("severity")
            if isinstance(severity, str):
                severities.append(severity.lower())
            for rr in r.get("risk_reports") or []:
                score = _as_float(rr.get("risk_score"))
                if score >= 9:
                    severities.append("critical")
                elif score >= 7:
                    severities.append("high")
            for anomaly in r.get("anomalies") or []:
                anomaly_severity = str(anomaly.get("severity", "")).lower()
                if anomaly_severity in ("critical", "high"):
                    severities.append(anomaly_severity)

        actionable = [s for s in severities if s in ("critical", "high", "medium", "low")]
        assessed = "critical" if "critical" in actionable else (
            "high" if "high" in actionable
            else "medium" if "medium" in actionable
            else "low"
        )
        # A quiet run may not knock down a level an escalation just raised.
        threat_level = await threat_levels.propose(assessed, source=self.name)
        await self._safe_publish("agent_events", {
            "agent": self.name, "event": "threat_level", "threat_level": threat_level,
            "assessed": assessed,
        })

        # If this run found high/critical activity, request a report
        if assessed in ("critical", "high") and "reporting" not in results:
            try:
                report_result = await self._run_agent("reporting", {
                    **state["task"],
                    "report_type": "executive",
                    "agent_results": {k: v.get("summary", "") for k, v in results.items()},
                })
                results["reporting"] = report_result
                summaries.append(f"[reporting] {report_result.get('summary', '')}")
            except Exception:
                pass

        final_report = {
            "threat_level": threat_level,
            "agent_summaries": summaries,
            "agent_results": results,
        }
        summary = f"Mesh run complete | Threat level: {threat_level.upper()} | Agents: {list(results.keys())}"
        return {
            "final_report": final_report,
            "summary": summary,
            "messages": [AIMessage(content=summary)],
        }

    async def _run_agent(self, name: str, task: dict) -> dict:
        if name not in self._agents:
            raise KeyError(f"Unknown agent: {name}")
        return await self._agents[name]._run_with_telemetry(task)

    @property
    def agent_names(self) -> list[str]:
        return list(self._agents.keys())

    async def run(self, input_data: dict) -> dict:
        initial: SupervisorState = {
            "messages": [HumanMessage(content=f"SOC task: {json.dumps(input_data, default=str)[:300]}")],
            "task": input_data,
            "routing_decision": {},
            "agent_results": {},
            "final_report": {},
            "summary": "",
        }
        final = await self._graph.ainvoke(initial)
        return {
            "final_report": final["final_report"],
            "agent_results": final["agent_results"],
            "routing_decision": final["routing_decision"],
            "summary": final["summary"],
        }

    # ── Escalation handling ──────────────────────────────────────────────────

    @staticmethod
    def _escalation_source(escalation: dict) -> str:
        event = escalation.get("event") if isinstance(escalation.get("event"), dict) else {}
        fields = event.get("parsed_fields") if isinstance(event.get("parsed_fields"), dict) else {}
        anomaly = escalation.get("anomaly") if isinstance(escalation.get("anomaly"), dict) else {}
        for candidate in (
            event.get("source_ip"), fields.get("src_ip"), escalation.get("source_ip"),
            escalation.get("attacker_ip"), anomaly.get("source"),
        ):
            if _ip_candidates(candidate):
                return str(candidate)
        return ""

    @classmethod
    def _escalation_key(cls, escalation: dict) -> str:
        """
        Stable fingerprint for an escalation, used to suppress duplicate responses
        while the same attack keeps firing.

        The raising agent is deliberately not part of it: the same attacker seen by
        both threat detection and log analysis is one incident, not two.
        """
        parts = [
            metrics.threat_type_label(escalation.get("threat_type") or escalation.get("type")),
            str(escalation.get("cve_id") or ""),
            str(escalation.get("framework") or ""),
            cls._escalation_source(escalation),
        ]
        digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
        return f"escalation_seen:{digest}"

    async def handle_escalation(self, escalation: dict) -> dict | None:
        """
        Called when an agent publishes to the `escalations` Redis channel.

        Escalations are dispatched straight to the incident-response playbook rather
        than back through the LLM router. Routing an escalation raised *by* the threat
        detection agent back *into* the threat detection agent would re-raise the same
        escalation forever; this path is deliberately acyclic. A Redis-backed cooldown
        additionally collapses repeat escalations for the same source into one response.
        """
        if not settings.escalation_auto_response:
            return None
        if await self.is_paused():
            # Pausing the supervisor pauses automated response too; it used to keep
            # opening incidents from escalations regardless.
            await self._safe_publish("agent_events", {
                "agent": self.name, "event": "escalation_skipped", "reason": "supervisor paused",
                "threat_type": escalation.get("threat_type") or escalation.get("type"),
            })
            return None

        await self._safe_publish("agent_events", {
            "agent": self.name,
            "event": "escalation_received",
            "escalation": escalation,
        })

        # Cooldown: SET NX means exactly one worker responds per fingerprint per window.
        key = self._escalation_key(escalation)
        try:
            first = await redis_client.cache.set_if_absent(
                key, {"severity": escalation.get("severity")}, ttl=settings.escalation_cooldown_seconds
            )
        except Exception:
            first = True
        if not first:
            return None

        severity = threat_levels.normalize(escalation.get("severity")) or "high"
        threat_type = escalation.get("threat_type") or escalation.get("type") or "unknown"
        event = escalation.get("event") if isinstance(escalation.get("event"), dict) else {}

        incident = {
            "title": f"{str(threat_type).replace('_', ' ').title()} escalated by {escalation.get('agent', 'agent')}",
            "type": threat_type,
            "severity": severity,
            "description": escalation.get("reasoning") or json.dumps(escalation, default=str)[:1000],
            "affected_assets": _ip_candidates(
                self._escalation_source(escalation), event.get("destination_ip"),
                escalation.get("victim_ip"),
            ),
        }
        task = {
            "incident": incident,
            "threat_assessment": escalation.get("assessment") or {"threat_type": threat_type,
                                                                  "severity": severity},
            # Links the detection that raised this to the incident it opens.
            "threat_event_ids": [escalation["event_id"]] if escalation.get("event_id") else [],
        }

        results: dict[str, dict] = {}
        try:
            results["incident_response"] = await self._run_agent("incident_response", task)
        except Exception as exc:
            results["incident_response"] = {"error": str(exc)}

        # Critical escalations also get an immediate threat brief for the analyst.
        if severity == "critical":
            try:
                results["reporting"] = await self._run_agent("reporting", {
                    "report_type": "threat",
                    "escalation": escalation,
                    "incident": incident,
                })
            except Exception as exc:
                results["reporting"] = {"error": str(exc)}

        effective = await threat_levels.propose(severity, source=f"escalation:{escalation.get('agent')}")
        await self._safe_publish("agent_events", {
            "agent": self.name, "event": "threat_level", "threat_level": effective,
        })
        await self._safe_publish("agent_events", {
            "agent": self.name,
            "event": "escalation_handled",
            "threat_type": threat_type,
            "severity": severity,
            "incident_id": (results.get("incident_response") or {}).get("incident_id"),
            "agents_run": list(results.keys()),
        })
        return results
