"""Log Analysis Agent — batch log ingestion, anomaly scoring, pattern detection."""
from __future__ import annotations
import ipaddress
import json
import re
from collections import defaultdict
from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from core import metrics
from core.config import settings
from core.database import es_client, repository
from core.parsing import parse_json_response


LOG_PATTERNS = {
    "brute_force": re.compile(r"(failed (password|login)|authentication failure|invalid (user|password))", re.I),
    # `or\s+1=1` alone missed the most common form of the tautology, the quoted
    # `' OR '1'='1` — including the payload this project's own simulator emits, which
    # therefore sailed past the pre-detector. The backreference requires both operands
    # to be the same token, which is the tautology signature and keeps ordinary prose
    # containing "or x=y" out of the results.
    "sql_injection": re.compile(
        r"(union\s+select|\bor\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\2\b|drop\s+table|xp_cmdshell|'--)",
        re.I,
    ),
    "xss": re.compile(r"(<script|javascript:|onerror=|onload=)", re.I),
    "path_traversal": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f)", re.I),
    "command_injection": re.compile(r"(;(ls|cat|id|whoami|wget|curl)|&&(ls|id)|`id`)", re.I),
    "port_scan": re.compile(r"(nmap|masscan|zmap|SYN_RECV.*:0|\bport scan\b)", re.I),
    "data_exfil": re.compile(
        r"(curl.*\|bash|wget.*-O-|nc\s+-e|/dev/tcp/|\bexfiltration\b|large outbound transfer)", re.I
    ),
    "c2_beacon": re.compile(r"(\bbeacon\b|\bc2\b|command[- ]and[- ]control)", re.I),
}

# What a pattern hit means on its own, without the LLM's opinion. Brute force is
# handled separately: one failed password is noise, a burst from one source is not.
PATTERN_RULES = {
    "sql_injection": ("sql_injection", "high"),
    "command_injection": ("command_injection", "high"),
    "path_traversal": ("path_traversal", "high"),
    "xss": ("xss", "medium"),
    "port_scan": ("port_scan", "medium"),
    "data_exfil": ("data_exfiltration", "critical"),
    "c2_beacon": ("c2_beacon", "critical"),
}
BRUTE_FORCE_THRESHOLD = 5

# Ground-truth labels the simulator attaches; a real parser never emits them, and the
# detector must not be able to read the answer off the log.
_LABEL_FIELDS = {"attack_type", "attack", "stage"}
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

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
    pattern_anomalies: list[dict]
    anomalies: list[dict]
    risk_summary: str
    llm_skipped: bool
    stored: dict
    summary: str


def _entry_text(entry: dict) -> str:
    """Flatten a log entry into searchable text, tolerating null/absent fields."""
    parts = [entry.get("message"), entry.get("raw")]
    fields = entry.get("parsed_fields")
    if isinstance(fields, dict):
        parts.extend(str(v) for k, v in fields.items() if k not in _LABEL_FIELDS)
    return " ".join(str(p) for p in parts if p)


def _is_ip(value) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def _source_ip(entry: dict) -> str | None:
    fields = entry.get("parsed_fields") if isinstance(entry.get("parsed_fields"), dict) else {}
    for candidate in (fields.get("src_ip"), entry.get("source_ip")):
        if candidate and _is_ip(candidate):
            return str(candidate)
    match = _IP_RE.search(str(entry.get("message") or ""))
    return match.group(1) if match and _is_ip(match.group(1)) else None


def _destination_ip(entry: dict) -> str | None:
    fields = entry.get("parsed_fields") if isinstance(entry.get("parsed_fields"), dict) else {}
    for candidate in (fields.get("dst_ip"), fields.get("c2_ip"), entry.get("destination_ip"), entry.get("host")):
        if candidate and _is_ip(candidate):
            return str(candidate)
    return None


def _severity(anomaly: dict) -> str:
    value = str(anomaly.get("severity", "low")).strip().lower()
    return value if value in SEVERITY_RANK else "low"


def detect(batch: list) -> tuple[dict[str, list[int]], list[dict]]:
    """
    The deterministic detector: (pattern hits by name, anomalies).

    A clear signature is reported — and escalated — even when the LLM misses it or its
    answer fails to parse. Pure, so scripts/evaluate_detection.py can measure it.
    """
    hits: dict[str, list[int]] = {k: [] for k in LOG_PATTERNS}
    for i, entry in enumerate(batch):
        if not isinstance(entry, dict):
            continue
        text = _entry_text(entry)
        for name, pattern in LOG_PATTERNS.items():
            if pattern.search(text):
                hits[name].append(i)
    hits = {k: v for k, v in hits.items() if v}

    anomalies: list[dict] = []
    for pattern, indices in hits.items():
        if pattern not in PATTERN_RULES:
            continue
        anomaly_type, severity = PATTERN_RULES[pattern]
        for i in indices:
            anomalies.append({
                "log_index": i, "anomaly_type": anomaly_type, "severity": severity,
                "source": _source_ip(batch[i]) or "", "detector": "pattern",
                "description": f"{anomaly_type.replace('_', ' ')} signature matched",
                "action": "investigate",
            })

    failures: dict[str, list[int]] = defaultdict(list)
    for i in hits.get("brute_force", []):
        failures[_source_ip(batch[i]) or "unknown"].append(i)
    for source, indices in failures.items():
        if source != "unknown" and len(indices) >= BRUTE_FORCE_THRESHOLD:
            anomalies.append({
                "log_index": indices[0], "anomaly_type": "brute_force", "severity": "high",
                "source": source, "detector": "pattern",
                "description": f"{len(indices)} failed logins from {source} in one batch",
                "action": "block_ip",
            })
    return hits, anomalies


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
        hits, anomalies = detect(state["log_batch"])
        return {
            "pattern_hits": hits,
            "pattern_anomalies": anomalies,
            "messages": [AIMessage(content=f"Pattern scan: {len(hits)} pattern types, {len(anomalies)} anomalies")],
        }

    def _llm_wanted(self, state: LogAnalysisState) -> bool:
        mode = str(settings.log_analysis_llm_mode or "always").lower()
        if mode == "off":
            return False
        if mode == "on_hits":
            return bool(state["pattern_anomalies"]) or any(
                name != "brute_force" for name in state["pattern_hits"]
            )
        return True

    async def _llm_analysis(self, state: LogAnalysisState) -> dict:
        batch = state["log_batch"]
        if not self._llm_wanted(state):
            return {
                "anomalies": [],
                "risk_summary": "LLM analysis skipped: no suspicious signatures in batch",
                "llm_skipped": True,
                "messages": [AIMessage(content="LLM analysis skipped")],
            }
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
        anomalies = [
            {**a, "detector": "llm"} for a in (result.get("anomalies") or []) if isinstance(a, dict)
        ]
        return {
            "anomalies": anomalies,
            "risk_summary": result.get("risk_summary", ""),
            "llm_skipped": False,
            "messages": [AIMessage(content=f"LLM found {result.get('anomaly_count', len(anomalies))} anomalies")],
        }

    def _merge(self, llm: list[dict], pattern: list[dict]) -> list[dict]:
        """LLM findings first; add pattern findings the model did not already report."""
        seen = {
            (a.get("log_index"), metrics.threat_type_label(a.get("anomaly_type"))) for a in llm
        }
        seen_sources = {
            (str(a.get("source") or ""), metrics.threat_type_label(a.get("anomaly_type"))) for a in llm
        }
        merged = list(llm)
        for a in pattern:
            label = metrics.threat_type_label(a.get("anomaly_type"))
            if (a.get("log_index"), label) in seen:
                continue
            if a.get("anomaly_type") == "brute_force" and (a.get("source"), label) in seen_sources:
                continue
            merged.append(a)
        return merged

    async def _score_anomalies(self, state: LogAnalysisState) -> dict:
        batch = state["log_batch"]
        scored = sorted(
            self._merge(state["anomalies"], state["pattern_anomalies"]),
            key=lambda a: SEVERITY_RANK.get(_severity(a), 1),
            reverse=True,
        )

        # One escalation per (attack type, source) per batch, carrying the offending
        # log entry: the supervisor's cooldown and the incident's affected assets both
        # key on the source IP, which the old payload never included.
        groups: dict[tuple[str, str], dict] = {}
        for anomaly in scored:
            if _severity(anomaly) not in ("critical", "high"):
                continue
            index = anomaly.get("log_index")
            entry = batch[index] if isinstance(index, int) and 0 <= index < len(batch) else {}
            source = (
                str(anomaly.get("source")) if _is_ip(anomaly.get("source")) else _source_ip(entry)
            ) or ""
            key = (metrics.threat_type_label(anomaly.get("anomaly_type")), source)
            groups.setdefault(key, {"anomaly": anomaly, "entry": entry, "source": source, "count": 0})
            groups[key]["count"] += 1

        for group in groups.values():
            anomaly, entry = group["anomaly"], group["entry"]
            event = {
                "source_ip": group["source"] or None,
                "destination_ip": _destination_ip(entry),
                "message": entry.get("message"),
                "timestamp": entry.get("timestamp"),
                "log_source": entry.get("source"),
            }
            await self.escalate({
                "severity": _severity(anomaly),
                "threat_type": anomaly.get("anomaly_type"),
                "anomaly": anomaly,
                "occurrences": group["count"],
                "event": {k: v for k, v in event.items() if v is not None},
                "reasoning": anomaly.get("description"),
            })

        summary = (
            f"Analyzed {len(batch)} logs | "
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
                anomaly_indices.setdefault(index, anomaly)

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
            "pattern_anomalies": [],
            "anomalies": [],
            "risk_summary": "",
            "llm_skipped": False,
            "stored": {},
            "summary": "",
        }
        final = await self._graph.ainvoke(initial)
        return {
            "anomalies": final["anomalies"],
            "pattern_hits": final["pattern_hits"],
            "risk_summary": final["risk_summary"],
            "llm_skipped": final.get("llm_skipped", False),
            "stored": final["stored"],
            "summary": final["summary"],
        }
