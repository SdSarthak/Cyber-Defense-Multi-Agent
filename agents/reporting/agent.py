"""Reporting Agent — generates executive summaries, threat reports, and compliance briefs."""
from __future__ import annotations
import json
import uuid
from collections import Counter
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
The "telemetry" section is the platform's own record and is authoritative. Use its
figures as given; never invent numbers. Where a metric is null, say it is not measured.
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
    ("human", "Threat events and assessments (telemetry is authoritative):\n{threat_data}"),
])


TELEMETRY_BUDGET = 6000
REQUEST_BUDGET = 3000


def _compact_threat(t: dict) -> dict:
    keys = ("created_at", "severity", "threat_type", "source_ip", "destination_ip",
            "confidence_score", "mitre_techniques", "incident_id")
    return {k: t.get(k) for k in keys if t.get(k) not in (None, [], "")}


def _compact_vuln(v: dict) -> dict:
    keys = ("cve_id", "cvss_score", "severity", "remediation_status", "asset_ip")
    return {k: v.get(k) for k in keys if v.get(k) is not None}


def _dumps(obj) -> str:
    return json.dumps(obj, default=str, separators=(",", ":"))


def _fit(telemetry: dict, budget: int) -> str:
    """
    Serialise telemetry within ``budget`` chars by shortening its lists, never by
    cutting the JSON mid-way.

    The old code dumped caller data and telemetry together with indent=2 and sliced
    the string at 4000 chars, so a handful of threat events crowded out the incident,
    vulnerability and compliance figures and the model made those numbers up.
    """
    data = json.loads(_dumps(telemetry))
    text = _dumps(data)
    while len(text) > budget:
        lists = [(k, v) for k, v in data.items() if isinstance(v, list) and v]
        if not lists:
            break
        key, longest = max(lists, key=lambda kv: len(_dumps(kv[1])))
        data[key] = longest[: max(len(longest) // 2, 0)]
        text = _dumps(data)
    return text[:budget]


def _bounded_request(data: dict) -> str:
    text = _dumps(data)
    return text if len(text) <= REQUEST_BUDGET else text[:REQUEST_BUDGET] + "...(truncated)"


class ReportState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    report_type: str
    input_data: dict
    telemetry: dict
    computed_metrics: dict
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
        Pull real SOC telemetry out of PostgreSQL, and compute the headline metrics
        here rather than asking the model to estimate them.
        """
        telemetry: dict = {}
        computed: dict = {}
        persisted = repository.enabled()
        try:
            incidents = await repository.incident_metrics(hours=24 * 30)
            telemetry["incidents_last_30d"] = incidents
            telemetry["threat_severity_last_24h"] = await repository.threat_severity_counts(hours=24)
            telemetry["recent_threats"] = [
                _compact_threat(t) for t in await repository.recent_threat_events(limit=25)
            ]
            vulns: list[dict] = []
            compliance: dict = {}
            if state["report_type"] == "executive":
                vulns = await repository.list_vulnerabilities(limit=200)
                compliance = await repository.compliance_summary()
                telemetry["vulnerabilities"] = {
                    "total": len(vulns),
                    "open": sum(1 for v in vulns if v.get("remediation_status") in ("open", "urgent")),
                    "by_severity": dict(Counter(v.get("severity") for v in vulns)),
                    "top": [_compact_vuln(v) for v in vulns[:15]],
                }
                telemetry["compliance_by_framework"] = compliance
            framework_scores = [c["score"] for c in compliance.values() if c.get("score") is not None]
            computed = {
                "total_incidents": incidents["total_incidents"] if persisted else None,
                "critical_incidents": incidents["critical_incidents"] if persisted else None,
                "mean_time_to_detect_hours": incidents["mean_time_to_detect_hours"],
                "mean_time_to_respond_hours": incidents["mean_time_to_respond_hours"],
                "vulnerabilities_open": telemetry.get("vulnerabilities", {}).get("open") if persisted else None,
                "compliance_score": (
                    round(sum(framework_scores) / len(framework_scores), 1) if framework_scores else None
                ),
            }
        except Exception:
            pass
        telemetry["key_metrics"] = computed
        return {
            "telemetry": telemetry,
            "computed_metrics": computed,
            "messages": [AIMessage(content="Gathered SOC telemetry for reporting")],
        }

    async def _generate_report(self, state: ReportState) -> dict:
        report_type = state["report_type"]
        request = {k: v for k, v in state["input_data"].items() if k != "report_type"}
        now = datetime.now(timezone.utc)
        # Telemetry first and budgeted on its own, so caller data can never push the
        # recorded figures out of the prompt.
        payload = (
            f"telemetry:\n{_fit(state.get('telemetry') or {}, TELEMETRY_BUDGET)}\n\n"
            f"request context:\n{_bounded_request(request)}"
        )

        if report_type == "executive":
            chain = EXEC_REPORT_PROMPT | self.llm
            period = request.get("period") or now.strftime("%Y-%m")
            resp = await chain.ainvoke({"period": period, "data": payload})
        elif report_type == "threat":
            chain = THREAT_REPORT_PROMPT | self.llm
            resp = await chain.ainvoke({"threat_data": payload})
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
        if report_type == "executive" and state.get("computed_metrics"):
            # Authoritative figures replace whatever the model wrote; unmeasured ones
            # stay null rather than being estimated.
            report["key_metrics"] = dict(state["computed_metrics"])
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
        # A suffix keeps two reports generated in the same second from overwriting
        # each other (concurrent escalations did exactly that).
        key = f"report:{state['report_type']}:{ts}:{uuid.uuid4().hex[:8]}"
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
            "telemetry": {},
            "computed_metrics": {},
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
