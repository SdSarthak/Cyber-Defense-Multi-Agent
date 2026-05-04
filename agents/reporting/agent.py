"""Reporting Agent — generates executive summaries, threat reports, and compliance briefs."""
from __future__ import annotations
import json
from datetime import datetime
from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from core.database.redis_client import cache

EXEC_REPORT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a CISO-level security reporting specialist. Create a concise executive security report.
The report must be professional, data-driven, and actionable.
Return JSON:
{
  "executive_summary": str (2-3 sentences for C-suite),
  "threat_landscape": {"current_threats": [str], "trend": "improving|stable|deteriorating"},
  "key_metrics": {
    "total_incidents": int,
    "critical_incidents": int,
    "mean_time_to_detect_hours": float,
    "mean_time_to_respond_hours": float,
    "vulnerabilities_open": int,
    "compliance_score": float
  },
  "top_risks": [{"risk": str, "likelihood": str, "impact": str, "mitigation": str}],
  "recommended_actions": [{"priority": str, "action": str, "owner": str, "deadline": str}],
  "compliance_status": {"frameworks": {}, "overall": str},
  "period": str
}
Return ONLY valid JSON."""),
    ("human", "Security data for period {period}:\n{data}"),
])

THREAT_REPORT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a threat intelligence analyst writing a detailed threat report.
Return JSON:
{
  "title": str,
  "tlp": "WHITE|GREEN|AMBER|RED",
  "threat_actors": [{"name": str, "motivation": str, "ttps": [str]}],
  "attack_vectors": [str],
  "targeted_assets": [str],
  "iocs": {"ips": [str], "domains": [str], "hashes": [str]},
  "mitre_coverage": {"tactics": [str], "techniques": [str]},
  "recommendations": [str],
  "confidence": "high|medium|low"
}
Return ONLY valid JSON."""),
    ("human", "Threat events and assessments:\n{threat_data}"),
])


class ReportState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    report_type: str
    input_data: dict
    report: dict
    summary: str


class ReportingAgent(BaseSecurityAgent):
    name = "reporting"
    description = "Generates executive security reports, threat intelligence briefs, and compliance summaries"

    def __init__(self):
        super().__init__()
        self._graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(ReportState)
        graph.add_node("generate_report", self._generate_report)
        graph.add_node("store_report", self._store_report)
        graph.set_entry_point("generate_report")
        graph.add_edge("generate_report", "store_report")
        graph.add_edge("store_report", END)
        return graph.compile()

    async def _generate_report(self, state: ReportState) -> dict:
        report_type = state["report_type"]
        data = state["input_data"]

        if report_type == "executive":
            chain = EXEC_REPORT_PROMPT | self.llm
            period = data.get("period", datetime.utcnow().strftime("%Y-%m"))
            resp = await chain.ainvoke({"period": period, "data": json.dumps(data, indent=2)[:4000]})
        elif report_type == "threat":
            chain = THREAT_REPORT_PROMPT | self.llm
            resp = await chain.ainvoke({"threat_data": json.dumps(data, indent=2)[:4000]})
        else:
            return {"report": {"error": f"Unknown report type: {report_type}"}, "summary": "Unknown report type"}

        try:
            report = json.loads(resp.content)
        except json.JSONDecodeError:
            report = {"raw_content": resp.content, "type": report_type, "generated_at": datetime.utcnow().isoformat()}

        report["generated_at"] = datetime.utcnow().isoformat()
        report["report_type"] = report_type
        return {
            "report": report,
            "messages": [AIMessage(content=f"{report_type.title()} report generated")],
        }

    async def _store_report(self, state: ReportState) -> dict:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        key = f"report:{state['report_type']}:{ts}"
        await cache.set(key, state["report"], ttl=604800)  # 7 days
        await cache.lpush("reports:index", {"key": key, "type": state["report_type"], "ts": ts})
        await cache.publish("agent_events", {
            "agent": self.name,
            "event": "report_ready",
            "report_key": key,
            "report_type": state["report_type"],
        })
        summary = f"{state['report_type'].title()} report stored at key={key}"
        return {"summary": summary, "messages": [AIMessage(content=summary)]}

    async def run(self, input_data: dict) -> dict:
        report_type = input_data.get("report_type", "executive")
        initial: ReportState = {
            "messages": [HumanMessage(content=f"Generate {report_type} report")],
            "report_type": report_type,
            "input_data": input_data,
            "report": {},
            "summary": "",
        }
        final = await self._graph.ainvoke(initial)
        return {"report": final["report"], "summary": final["summary"]}
