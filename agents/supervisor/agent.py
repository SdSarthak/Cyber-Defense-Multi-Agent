"""Supervisor Agent — LangGraph orchestrator that routes tasks to specialist agents."""
from __future__ import annotations
import json
import asyncio
from typing import TypedDict, Annotated, Literal
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from agents.threat_detection.agent import ThreatDetectionAgent
from agents.log_analysis.agent import LogAnalysisAgent
from agents.vulnerability_intel.agent import VulnerabilityIntelAgent
from agents.incident_response.agent import IncidentResponseAgent
from agents.compliance.agent import ComplianceAgent
from agents.reporting.agent import ReportingAgent
from core.database.redis_client import cache
from core.memory.agent_memory import AgentMemory

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
{
  "agents": ["agent1", "agent2"],
  "reasoning": str,
  "priority": "immediate|high|normal|low",
  "parallel": bool
}
Return ONLY valid JSON."""),
    ("human", "Task:\n{task}\n\nCurrent threat level from blackboard:\n{threat_level}"),
])

AgentName = Literal[
    "threat_detection", "log_analysis", "vulnerability_intel",
    "incident_response", "compliance", "reporting"
]


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
            "task": json.dumps(state["task"]),
            "threat_level": threat_level,
        })
        try:
            decision = json.loads(resp.content)
        except json.JSONDecodeError:
            decision = {"agents": ["threat_detection"], "reasoning": "parse error fallback",
                        "priority": "normal", "parallel": False}

        if "all" in decision.get("agents", []):
            decision["agents"] = list(self._agents.keys())

        await cache.publish("agent_events", {
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
        agents_to_run = decision.get("agents", [])
        parallel = decision.get("parallel", True)
        results: dict[str, dict] = {}

        if parallel:
            tasks = {
                name: asyncio.create_task(
                    self._run_agent(name, state["task"])
                )
                for name in agents_to_run
                if name in self._agents
            }
            for name, task in tasks.items():
                try:
                    results[name] = await task
                except Exception as e:
                    results[name] = {"error": str(e), "summary": f"Agent {name} failed: {e}"}
        else:
            for name in agents_to_run:
                if name in self._agents:
                    try:
                        results[name] = await self._run_agent(name, state["task"])
                    except Exception as e:
                        results[name] = {"error": str(e)}

        await AgentMemory.blackboard_update("last_agent_results", results)
        return {
            "agent_results": results,
            "messages": [AIMessage(content=f"Dispatched {len(results)} agents, received {len(results)} results")],
        }

    async def _synthesise(self, state: SupervisorState) -> dict:
        results = state["agent_results"]
        summaries = [f"[{name}] {r.get('summary', 'no summary')}" for name, r in results.items()]

        # Determine overall threat level from results
        severities = []
        for r in results.values():
            if "severity" in r:
                severities.append(r["severity"])
            if "risk_reports" in r:
                for rr in r["risk_reports"]:
                    if rr.get("risk_score", 0) >= 9:
                        severities.append("critical")
                    elif rr.get("risk_score", 0) >= 7:
                        severities.append("high")

        threat_level = "critical" if "critical" in severities else (
            "high" if "high" in severities else "medium" if severities else "low"
        )
        await AgentMemory.blackboard_set("threat_level", threat_level, ttl=3600)

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
        agent = self._agents[name]
        result = await agent._run_with_telemetry(task)
        return result

    async def run(self, input_data: dict) -> dict:
        initial: SupervisorState = {
            "messages": [HumanMessage(content=f"SOC task: {json.dumps(input_data)[:300]}")],
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

    async def handle_escalation(self, escalation: dict) -> None:
        """Called when an agent publishes to the escalations Redis channel."""
        await cache.publish("agent_events", {
            "agent": self.name,
            "event": "escalation_received",
            "escalation": escalation,
        })
        task = {
            "type": "escalation",
            "source_agent": escalation.get("agent"),
            "severity": escalation.get("severity", "high"),
            **escalation,
        }
        await self._run_with_telemetry(task)
