"""Threat Detection Agent — real-time anomaly and IOC detection using LangGraph."""
from __future__ import annotations
import ipaddress
import json
from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from core import metrics
from core.tools import threat_tools
from core.rag import rag_chain
from core.database import repository
from core.parsing import parse_json_response


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class ThreatState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    raw_event: dict
    threat_assessment: dict
    enrichment: dict
    mitre_mapping: dict
    severity: str
    should_escalate: bool
    event_id: str | None
    summary: str


ASSESSMENT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a Tier-2 SOC analyst. Analyze this security event and return a JSON object with:
- threat_type: classification of the threat (e.g. "port_scan", "brute_force", "sql_injection", "c2_beacon", "data_exfiltration", "none")
- severity: one of "critical", "high", "medium", "low", "info"
- confidence: float 0.0-1.0
- indicators: list of IOCs found
- mitre_tactics: list of MITRE ATT&CK tactic names
- mitre_techniques: list of technique IDs (e.g. T1046)
- reasoning: brief explanation
- should_escalate: bool

Return ONLY valid JSON, no markdown fences."""),
    ("human", "Security event:\n{event}\n\nThreat intel context:\n{context}"),
])

ENRICHMENT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", "You are a threat intelligence enrichment engine. Given tool results for an IOC, "
               "produce a concise enrichment summary as JSON with keys: "
               "reputation_score (0-100), known_malicious (bool), threat_actor, campaigns, recommended_action."),
    ("human", "IOC: {ioc}\nTool results:\n{tool_results}"),
])


class ThreatDetectionAgent(BaseSecurityAgent):
    name = "threat_detection"
    description = "Detects and classifies threats in real-time security events"

    def __init__(self):
        super().__init__()
        self._graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(ThreatState)
        graph.add_node("assess_threat", self._assess_threat)
        graph.add_node("enrich_iocs", self._enrich_iocs)
        graph.add_node("map_mitre", self._map_mitre)
        graph.add_node("decide_escalation", self._decide_escalation)
        graph.add_node("persist_event", self._persist_event)

        graph.set_entry_point("assess_threat")
        graph.add_edge("assess_threat", "enrich_iocs")
        graph.add_edge("enrich_iocs", "map_mitre")
        graph.add_edge("map_mitre", "decide_escalation")
        graph.add_edge("decide_escalation", "persist_event")
        graph.add_edge("persist_event", END)
        return graph.compile()

    async def _assess_threat(self, state: ThreatState) -> dict:
        event_str = json.dumps(state["raw_event"], indent=2)
        context = await rag_chain.threat_rag.ainvoke(
            f"threat classification for: {state['raw_event'].get('threat_type', event_str[:200])}"
        )

        chain = ASSESSMENT_PROMPT | self.llm
        response = await chain.ainvoke({"event": event_str, "context": context})
        assessment = parse_json_response(response.content)
        if assessment is None:
            assessment = {"threat_type": "unknown", "severity": "medium", "confidence": 0.5,
                          "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
                          "reasoning": str(response.content), "should_escalate": False}

        return {
            "messages": [AIMessage(content=f"Assessment complete: {assessment.get('threat_type')}")],
            "threat_assessment": assessment,
            "severity": assessment.get("severity", "medium"),
        }

    async def _enrich_iocs(self, state: ThreatState) -> dict:
        assessment = state.get("threat_assessment", {})
        indicators = assessment.get("indicators") or []
        enrichment: dict = {}

        for ioc in [i for i in indicators if isinstance(i, str)][:3]:
            tool_results: list[str] = []
            try:
                tool_results.append(str(await threat_tools.score_ioc.ainvoke({"ioc": ioc})))
            except Exception:
                pass
            if _is_ip(ioc):
                try:
                    tool_results.append(str(await threat_tools.enrich_ip.ainvoke({"ip": ioc})))
                except Exception:
                    pass

            if tool_results:
                chain = ENRICHMENT_PROMPT | self.llm
                resp = await chain.ainvoke({"ioc": ioc, "tool_results": "\n".join(tool_results)})
                enrichment[ioc] = parse_json_response(resp.content) or {"raw": str(resp.content)}

        return {"enrichment": enrichment,
                "messages": [AIMessage(content=f"Enriched {len(enrichment)} IOCs")]}

    async def _map_mitre(self, state: ThreatState) -> dict:
        assessment = state.get("threat_assessment", {})
        mitre_mapping = {
            "tactics": assessment.get("mitre_tactics", []),
            "techniques": assessment.get("mitre_techniques", []),
        }
        return {"mitre_mapping": mitre_mapping,
                "messages": [AIMessage(content=f"MITRE mapping: {mitre_mapping}")]}

    async def _decide_escalation(self, state: ThreatState) -> dict:
        assessment = state.get("threat_assessment", {})
        severity = state.get("severity", "medium")
        threat_type = assessment.get("threat_type") or "unknown"
        confidence = _as_float(assessment.get("confidence"))

        # A high-confidence verdict of "no threat" must not escalate — only escalate
        # on confidence when the model actually classified something malicious.
        confident_threat = confidence > 0.85 and threat_type not in ("none", "unknown", "benign")
        should_escalate = bool(
            severity in ("critical", "high")
            or assessment.get("should_escalate", False)
            or confident_threat
        )

        metrics.threat_events_total.labels(
            severity=str(severity), threat_type=str(threat_type)
        ).inc()

        if should_escalate:
            await self.escalate({
                "severity": severity,
                "threat_type": threat_type,
                "event": state["raw_event"],
                "assessment": assessment,
            })

        summary = (
            f"{str(threat_type).upper()} detected | "
            f"Severity: {severity} | "
            f"Confidence: {confidence:.0%} | "
            f"Escalated: {should_escalate}"
        )
        return {"should_escalate": should_escalate, "summary": summary,
                "messages": [AIMessage(content=summary)]}

    async def _persist_event(self, state: ThreatState) -> dict:
        """Write the classified event to PostgreSQL as the durable system of record."""
        event_id = await repository.save_threat_event(
            raw_event=state["raw_event"],
            assessment=state.get("threat_assessment", {}),
            enrichment=state.get("enrichment", {}),
        )
        return {"event_id": event_id, "messages": []}

    async def run(self, input_data: dict) -> dict:
        initial_state: ThreatState = {
            "messages": [HumanMessage(content=json.dumps(input_data, default=str))],
            "raw_event": input_data,
            "threat_assessment": {},
            "enrichment": {},
            "mitre_mapping": {},
            "severity": "info",
            "should_escalate": False,
            "event_id": None,
            "summary": "",
        }
        final_state = await self._graph.ainvoke(initial_state)
        return {
            "threat_assessment": final_state["threat_assessment"],
            "enrichment": final_state["enrichment"],
            "mitre_mapping": final_state["mitre_mapping"],
            "severity": final_state["severity"],
            "should_escalate": final_state["should_escalate"],
            "event_id": final_state.get("event_id"),
            "summary": final_state["summary"],
        }


