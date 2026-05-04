"""Threat Detection Agent — real-time anomaly and IOC detection using LangGraph."""
from __future__ import annotations
import json
from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from core.tools.threat_tools import THREAT_TOOLS
from core.rag.rag_chain import threat_rag
from core.database.redis_client import cache


class ThreatState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    raw_event: dict
    threat_assessment: dict
    enrichment: dict
    mitre_mapping: dict
    severity: str
    should_escalate: bool
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

        graph.set_entry_point("assess_threat")
        graph.add_edge("assess_threat", "enrich_iocs")
        graph.add_edge("enrich_iocs", "map_mitre")
        graph.add_edge("map_mitre", "decide_escalation")
        graph.add_edge("decide_escalation", END)
        return graph.compile()

    async def _assess_threat(self, state: ThreatState) -> dict:
        event_str = json.dumps(state["raw_event"], indent=2)
        context = ""
        try:
            context = await threat_rag.ainvoke(
                f"threat classification for: {state['raw_event'].get('threat_type', event_str[:200])}"
            )
        except Exception:
            pass

        chain = ASSESSMENT_PROMPT | self.llm
        response = await chain.ainvoke({"event": event_str, "context": context})
        try:
            assessment = json.loads(response.content)
        except json.JSONDecodeError:
            assessment = {"threat_type": "unknown", "severity": "medium", "confidence": 0.5,
                          "indicators": [], "mitre_tactics": [], "mitre_techniques": [],
                          "reasoning": response.content, "should_escalate": False}

        return {
            "messages": [AIMessage(content=f"Assessment complete: {assessment.get('threat_type')}")],
            "threat_assessment": assessment,
            "severity": assessment.get("severity", "medium"),
        }

    async def _enrich_iocs(self, state: ThreatState) -> dict:
        assessment = state.get("threat_assessment", {})
        indicators = assessment.get("indicators", [])
        enrichment = {}

        for ioc in indicators[:3]:  # limit to 3 IOCs to avoid rate limits
            tool_results = []
            if "." in str(ioc) and not ioc.startswith("http"):
                from core.tools.threat_tools import lookup_ip_reputation
                result = await lookup_ip_reputation.ainvoke({"ip": ioc})
                tool_results.append(result)
                result2 = await lookup_virustotal_safe(ioc)
                if result2:
                    tool_results.append(result2)

            if tool_results:
                chain = ENRICHMENT_PROMPT | self.llm
                resp = await chain.ainvoke({"ioc": ioc, "tool_results": "\n".join(tool_results)})
                try:
                    enrichment[ioc] = json.loads(resp.content)
                except Exception:
                    enrichment[ioc] = {"raw": resp.content}

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
        should_escalate = (
            severity in ("critical", "high")
            or assessment.get("should_escalate", False)
            or assessment.get("confidence", 0) > 0.85
        )

        if should_escalate:
            await cache.publish("escalations", {
                "agent": self.name,
                "severity": severity,
                "threat_type": assessment.get("threat_type"),
                "event": state["raw_event"],
                "assessment": assessment,
            })

        summary = (
            f"{assessment.get('threat_type', 'unknown').upper()} detected | "
            f"Severity: {severity} | "
            f"Confidence: {assessment.get('confidence', 0):.0%} | "
            f"Escalated: {should_escalate}"
        )
        return {"should_escalate": should_escalate, "summary": summary,
                "messages": [AIMessage(content=summary)]}

    async def run(self, input_data: dict) -> dict:
        initial_state: ThreatState = {
            "messages": [HumanMessage(content=json.dumps(input_data))],
            "raw_event": input_data,
            "threat_assessment": {},
            "enrichment": {},
            "mitre_mapping": {},
            "severity": "info",
            "should_escalate": False,
            "summary": "",
        }
        final_state = await self._graph.ainvoke(initial_state)
        return {
            "threat_assessment": final_state["threat_assessment"],
            "enrichment": final_state["enrichment"],
            "mitre_mapping": final_state["mitre_mapping"],
            "severity": final_state["severity"],
            "should_escalate": final_state["should_escalate"],
            "summary": final_state["summary"],
        }


async def lookup_virustotal_safe(ioc: str) -> str | None:
    try:
        from core.tools.threat_tools import lookup_virustotal
        return await lookup_virustotal.ainvoke({"ioc": ioc})
    except Exception:
        return None
