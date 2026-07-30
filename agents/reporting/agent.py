"""Reporting Agent — generates executive summaries, threat reports, and compliance briefs."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from core.database import redis_client, repository
from core.parsing import parse_json_response

EXEC_REPORT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a CISO-level security reporting specialist. Create a concise executive security report.
The report must be professional, data-driven, and actionable.
Return JSON:
{{
  "executive_summary": str (2-3 sentences for C-suite),
  "threat_landscape": {{"current_threats": [str], "trend": "improving|stable|deteriorating"}},
  "key_metrics": {{
    "total_incidents": int,
    "critical_incidents": int,
    "mean_time_to_detect_hours": float,
    "mean_time_to_respond_hours": float,
    "vulnerabilities_open": int,
    "compliance_score": float
  }},
  "top_risks": [{{"risk": str, "likelihood": str, "impact": str, "mitigation": str}}],
  "recommended_actions": [{{"priority": str, "action": str, "owner": str, "deadline": str}}],
  "compliance_status": {{"frameworks": {{}}, "overall": str}},
  "period": str
}}
Return ONLY valid JSON."""),
    ("human", "Security data for period {period}:\n{data}"),
])

THREAT_REPORT_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a threat intelligence analyst writing a detailed threat report.
Return JSON:
{{
  "title": str,
  "tlp": "WHITE|GREEN|AMBER|RED",
  "threat_actors": [{{"name": str, "motivation": str, "ttps": [str]}}],
  "attack_vectors": [str],
  "targeted_assets": [str],
  "iocs": {{"ips": [str], "domains": [str], "hashes": [str]}},
  "mitre_coverage": {{"tactics": [str], "techniques": [str]}},
  "recommendations": [str],
  "confidence": "high|medium|low"
}}
Return ONLY valid JSON."""),
    ("human", "Threat events and assessments:\n{threat_data}"),
])


class ReportState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    report_type: str
    input_data: dict
    report: dict
    report_key: str | None
    summary: str


class ReportingAgent(BaseSecurityAgent):
    name = "reporting"
    description = "Generates executive security reports, threat intelligence briefs, and compliance summaries"

    def __init__(self):
        super().__init__()
        self._graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(ReportState)
        graph.add_node("gather_context", self._gather_context)
        graph.add_node("generate_report", self._generate_report)
        graph.add_node("store_report", self._store_report)
        graph.set_entry_point("gather_context")
        graph.add_edge("gather_context", "generate_report")
        graph.add_edge("generate_report", "store_report")
        graph.add_edge("store_report", END)
        return graph.compile()

    async def _gather_context(self, state: ReportState) -> dict:
        """
        Pull real SOC telemetry out of PostgreSQL so the report is grounded in
        recorded data rather than only whatever the caller happened to pass in.
        """
        data = dict(state["input_data"])
        try:
            data.setdefault("recent_threats", await repository.recent_threat_events(limit=25))
            data.setdefault("open_incidents", await repository.count_open_incidents())
            data.setdefault("severity_breakdown", await repository.threat_severity_counts(hours=24))
            if state["report_type"] == "executive":
                data.setdefault("open_vulnerabilities", await repository.list_vulnerabilities(limit=20))
                data.setdefault("compliance_checks", await repository.compliance_history(limit=30))
        except Exception:
            pass
        return {
            "input_data": data,
            "messages": [AIMessage(content="Gathered SOC telemetry for reporting")],
        }

    async def _generate_report(self, state: ReportState) -> dict:
        report_type = state["report_type"]
        data = state["input_data"]
        now = datetime.now(timezone.utc)

        if report_type == "executive":
            chain = EXEC_REPORT_PROMPT | self.llm
            period = data.get("period") or now.strftime("%Y-%m")
            resp = await chain.ainvoke({
                "period": period,
                "data": json.dumps(data, indent=2, default=str)[:4000],
            })
        elif report_type == "threat":
            chain = THREAT_REPORT_PROMPT | self.llm
            resp = await chain.ainvoke({
                "threat_data": json.dumps(data, indent=2, default=str)[:4000],
            })
        else:
            return {
                "report": {
                    "error": f"Unknown report type: {report_type}",
                    "supported": ["executive", "threat"],
                },
                "summary": f"Unknown report type '{report_type}' — supported: executive, threat",
                "messages": [AIMessage(content=f"Unknown report type: {report_type}")],
            }

        report = parse_json_response(resp.content) or {
            "raw_content": str(resp.content), "type": report_type,
        }
        report["generated_at"] = now.isoformat()
        report["report_type"] = report_type
        return {
            "report": report,
            "messages": [AIMessage(content=f"{report_type.title()} report generated")],
        }

    async def _store_report(self, state: ReportState) -> dict:
        if state["report"].get("error"):
            # Nothing worth persisting for an unsupported report type.
            return {"messages": []}

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        key = f"report:{state['report_type']}:{ts}"
        try:
            await redis_client.cache.set(key, state["report"], ttl=604800)  # 7 days
            await redis_client.cache.lpush(
                "reports:index", {"key": key, "type": state["report_type"], "ts": ts}
            )
            await redis_client.cache.ltrim("reports:index", 0, 99)
        except Exception:
            pass
        await self._safe_publish("agent_events", {
            "agent": self.name,
            "event": "report_ready",
            "report_key": key,
            "report_type": state["report_type"],
        })
        summary = f"{state['report_type'].title()} report stored at key={key}"
        return {"report_key": key, "summary": summary, "messages": [AIMessage(content=summary)]}

    async def run(self, input_data: dict) -> dict:
        report_type = input_data.get("report_type", "executive")
        initial: ReportState = {
            "messages": [HumanMessage(content=f"Generate {report_type} report")],
            "report_type": report_type,
            "input_data": input_data,
            "report": {},
            "report_key": None,
            "summary": "",
        }
        final = await self._graph.ainvoke(initial)
        return {
            "report": final["report"],
            "report_key": final.get("report_key"),
            "summary": final["summary"],
        }
