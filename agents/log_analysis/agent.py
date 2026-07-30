"""Log Analysis Agent — batch log ingestion, anomaly scoring, pattern detection."""
from __future__ import annotations
import json
import re
from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from core.config import settings
from core.database import es_client, repository
from core.parsing import parse_json_response


LOG_PATTERNS = {
    "brute_force": re.compile(r"(failed (password|login)|authentication failure|invalid (user|password))", re.I),
    "sql_injection": re.compile(r"(union\s+select|or\s+1=1|drop\s+table|xp_cmdshell|'--)", re.I),
    "xss": re.compile(r"(<script|javascript:|onerror=|onload=)", re.I),
    "path_traversal": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f)", re.I),
    "command_injection": re.compile(r"(;(ls|cat|id|whoami|wget|curl)|&&(ls|id)|`id`)", re.I),
    "port_scan": re.compile(r"(nmap|masscan|zmap|SYN_RECV.*:0)", re.I),
    "data_exfil": re.compile(r"(curl.*\|bash|wget.*-O-|nc\s+-e|/dev/tcp/)", re.I),
}

ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a log analysis expert. Analyze the following batch of security logs.
For each anomalous entry, identify:
1. The anomaly type
2. Severity (critical/high/medium/low)
3. Affected source/destination
4. Recommended action

Return a JSON object:
{{
  "anomaly_count": int,
  "total_analyzed": int,
  "anomalies": [
    {{"log_index": int, "anomaly_type": str, "severity": str, "source": str, "description": str, "action": str}}
  ],
  "patterns_detected": [str],
  "risk_summary": str
}}
Return ONLY valid JSON."""),
    ("human", "Log batch ({count} entries):\n{logs}\n\nPre-detected pattern hits:\n{pattern_hits}"),
])


class LogAnalysisState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    log_batch: list[dict]
    pattern_hits: dict
    anomalies: list[dict]
    risk_summary: str
    stored: dict
    summary: str


def _entry_text(entry: dict) -> str:
    """Flatten a log entry into searchable text, tolerating null/absent fields."""
    parts = [entry.get("message"), entry.get("raw")]
    fields = entry.get("parsed_fields")
    if isinstance(fields, dict):
        parts.extend(str(v) for v in fields.values())
    return " ".join(str(p) for p in parts if p)


class LogAnalysisAgent(BaseSecurityAgent):
    name = "log_analysis"
    description = "Analyzes security logs for anomalies, attack patterns, and suspicious behaviour"

    def __init__(self):
        super().__init__()
        self._graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(LogAnalysisState)
        graph.add_node("pattern_scan", self._pattern_scan)
        graph.add_node("llm_analysis", self._llm_analysis)
        graph.add_node("score_anomalies", self._score_anomalies)
        graph.add_node("store_logs", self._store_logs)
        graph.set_entry_point("pattern_scan")
        graph.add_edge("pattern_scan", "llm_analysis")
        graph.add_edge("llm_analysis", "score_anomalies")
        graph.add_edge("score_anomalies", "store_logs")
        graph.add_edge("store_logs", END)
        return graph.compile()

    async def _pattern_scan(self, state: LogAnalysisState) -> dict:
        hits: dict[str, list[int]] = {k: [] for k in LOG_PATTERNS}
        for i, entry in enumerate(state["log_batch"]):
            if not isinstance(entry, dict):
                continue
            text = _entry_text(entry)
            for name, pattern in LOG_PATTERNS.items():
                if pattern.search(text):
                    hits[name].append(i)
        hits = {k: v for k, v in hits.items() if v}
        return {
            "pattern_hits": hits,
            "messages": [AIMessage(content=f"Pattern scan: {len(hits)} pattern types found")],
        }

    async def _llm_analysis(self, state: LogAnalysisState) -> dict:
        batch = state["log_batch"]
        # Summarise logs to avoid token overflow
        log_text = "\n".join(
            f"[{i}] {e.get('timestamp','')} {e.get('source','')} {str(e.get('message') or '')[:200]}"
            for i, e in enumerate(batch[:settings.log_analysis_batch_size])
            if isinstance(e, dict)
        )
        pattern_text = json.dumps(state["pattern_hits"])
        chain = ANALYSIS_PROMPT | self.llm
        resp = await chain.ainvoke({
            "count": len(batch),
            "logs": log_text,
            "pattern_hits": pattern_text,
        })
        result = parse_json_response(resp.content) or {
            "anomaly_count": 0, "total_analyzed": len(batch),
            "anomalies": [], "patterns_detected": [], "risk_summary": str(resp.content),
        }
        anomalies = [a for a in (result.get("anomalies") or []) if isinstance(a, dict)]
        return {
            "anomalies": anomalies,
            "risk_summary": result.get("risk_summary", ""),
            "messages": [AIMessage(content=f"LLM found {result.get('anomaly_count', len(anomalies))} anomalies")],
        }

    async def _score_anomalies(self, state: LogAnalysisState) -> dict:
        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        scored = sorted(
            state["anomalies"],
            key=lambda a: severity_map.get(str(a.get("severity", "low")).lower(), 1),
            reverse=True,
        )
        # Push high-severity anomalies to escalation channel
        for anomaly in scored:
            if str(anomaly.get("severity", "")).lower() in ("critical", "high"):
                await self.escalate({
                    "source": "log_analysis",
                    "severity": anomaly.get("severity"),
                    "threat_type": anomaly.get("anomaly_type"),
                    "anomaly": anomaly,
                })
        summary = (
            f"Analyzed {len(state['log_batch'])} logs | "
            f"{len(scored)} anomalies | "
            f"Patterns: {list(state['pattern_hits'].keys())}"
        )
        return {"anomalies": scored, "summary": summary,
                "messages": [AIMessage(content=summary)]}

    async def _store_logs(self, state: LogAnalysisState) -> dict:
        """Mirror the analysed batch into PostgreSQL and Elasticsearch."""
        anomaly_indices: dict[int, dict] = {}
        for anomaly in state["anomalies"]:
            index = anomaly.get("log_index")
            if isinstance(index, int) and 0 <= index < len(state["log_batch"]):
                anomaly_indices[index] = anomaly

        rows = await repository.save_log_entries(
            state["log_batch"], anomaly_indices, es_index=settings.elasticsearch_log_index
        )
        indexed = await es_client.index_logs(state["log_batch"], anomaly_indices)
        return {
            "stored": {"postgres_rows": rows, "elasticsearch_docs": indexed},
            "messages": [AIMessage(content=f"Stored {rows} rows, indexed {indexed} documents")],
        }

    async def run(self, input_data: dict) -> dict:
        logs = [entry for entry in (input_data.get("logs") or []) if isinstance(entry, dict)]
        if not logs:
            return {"summary": "No logs provided", "anomalies": [], "pattern_hits": {},
                    "risk_summary": "", "stored": {}}
        initial: LogAnalysisState = {
            "messages": [HumanMessage(content=f"Analyze {len(logs)} log entries")],
            "log_batch": logs,
            "pattern_hits": {},
            "anomalies": [],
            "risk_summary": "",
            "stored": {},
            "summary": "",
        }
        final = await self._graph.ainvoke(initial)
        return {
            "anomalies": final["anomalies"],
            "pattern_hits": final["pattern_hits"],
            "risk_summary": final["risk_summary"],
            "stored": final["stored"],
            "summary": final["summary"],
        }
