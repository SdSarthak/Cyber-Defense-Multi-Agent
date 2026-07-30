"""Supervisor Agent — LangGraph orchestrator that routes tasks to specialist agents."""
from __future__ import annotations
import asyncio
import hashlib
import json
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
from agents.compliance.agent import ComplianceAgent
from agents.reporting.agent import ReportingAgent
from core import metrics
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
        threat_level = await AgentMemory.blackboard_get("threat_level") or "normal"
        chain = ROUTER_PROMPT | self.llm
        resp = await chain.ainvoke({
            "task": json.dumps(state["task"], default=str),
            "threat_level": threat_level,
        })
        decision = parse_json_response(resp.content) or {
            "agents": ["threat_detection"], "reasoning": "parse error fallback",
            "priority": "normal", "parallel": False,
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
        parallel = decision.get("parallel", True)
        results: dict[str, dict] = {}

        if parallel:
            gathered = await asyncio.gather(
                *(self._run_agent(name, state["task"]) for name in agents_to_run),
                return_exceptions=True,
            )
            for name, outcome in zip(agents_to_run, gathered):
                if isinstance(outcome, BaseException):
                    results[name] = {"error": str(outcome), "summary": f"Agent {name} failed: {outcome}"}
                else:
                    results[name] = outcome
        else:
            for name in agents_to_run:
                try:
                    results[name] = await self._run_agent(name, state["task"])
                except Exception as e:
                    results[name] = {"error": str(e), "summary": f"Agent {name} failed: {e}"}

        # Only summaries go on the blackboard — full results can be megabytes and the
        # blackboard is read on every routing decision.
        await AgentMemory.blackboard_update(
            "last_agent_results",
            {name: r.get("summary", "") for name, r in results.items()},
        )
        succeeded = sum(1 for r in results.values() if "error" not in r)
        return {
            "agent_results": results,
            "messages": [AIMessage(
                content=f"Dispatched {len(agents_to_run)} agents, {succeeded} succeeded"
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
        threat_level = "critical" if "critical" in actionable else (
            "high" if "high" in actionable
            else "medium" if "medium" in actionable
            else "low"
        )
        await AgentMemory.blackboard_set("threat_level", threat_level, ttl=3600)
        metrics.set_threat_level(threat_level)
        await self._safe_publish("agent_events", {
            "agent": self.name, "event": "threat_level", "threat_level": threat_level,
        })

        # If threat is high/critical, request a report
        if threat_level in ("critical", "high") and "reporting" not in results:
            try:
                report_result = await self._run_agent("reporting", {
                    "report_type": "executive",
                    **state["task"],
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
    def _escalation_key(escalation: dict) -> str:
        """
        Stable fingerprint for an escalation, used to suppress duplicate responses
        while the same attack keeps firing.
        """
        event = escalation.get("event") or {}
        parts = [
            str(escalation.get("agent", "")),
            str(escalation.get("threat_type") or escalation.get("type") or ""),
            str(escalation.get("cve_id") or ""),
            str(event.get("source_ip") or (event.get("parsed_fields") or {}).get("src_ip") or ""),
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

        await self._safe_publish("agent_events", {
            "agent": self.name,
            "event": "escalation_received",
            "escalation": escalation,
        })

        # Cooldown: SET NX means exactly one worker responds per fingerprint per window.
        key = self._escalation_key(escalation)
        try:
            first = await redis_client.cache.set_if_absent(
                key, {"ts": escalation.get("severity")}, ttl=settings.escalation_cooldown_seconds
            )
        except Exception:
            first = True
        if not first:
            return None

        severity = str(escalation.get("severity", "high")).lower()
        threat_type = escalation.get("threat_type") or escalation.get("type") or "unknown"
        event = escalation.get("event") or {}

        incident = {
            "title": f"{str(threat_type).replace('_', ' ').title()} escalated by {escalation.get('agent', 'agent')}",
            "type": threat_type,
            "severity": severity,
            "description": escalation.get("reasoning") or json.dumps(escalation, default=str)[:1000],
            "affected_assets": [a for a in (
                event.get("destination_ip"), event.get("source_ip"),
            ) if a],
        }
        task = {
            "incident": incident,
            "threat_assessment": escalation.get("assessment") or {"threat_type": threat_type,
                                                                  "severity": severity},
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

        await AgentMemory.blackboard_set("threat_level", severity, ttl=3600)
        metrics.set_threat_level(severity)
        await self._safe_publish("agent_events", {
            "agent": self.name,
            "event": "escalation_handled",
            "threat_type": threat_type,
            "severity": severity,
            "agents_run": list(results.keys()),
        })
        return results
