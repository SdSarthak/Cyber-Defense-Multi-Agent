"""Compliance Agent — continuous control evaluation against SOC2, ISO 27001, NIST CSF."""
from __future__ import annotations
import json
import uuid
from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from core.config import settings
from core.rag import rag_chain
from core.database import repository
from core.parsing import parse_json_response

FRAMEWORKS = {
    "SOC2": {
        "CC6.1": "Logical and physical access controls",
        "CC6.2": "Prior to issuing system credentials and granting system access",
        "CC6.3": "Role-based access and least privilege",
        "CC7.1": "Detection and monitoring of threats",
        "CC7.2": "Monitoring system components for anomalies",
        "CC8.1": "Change management procedures",
        "A1.1": "System availability and capacity",
    },
    "NIST_CSF": {
        "ID.AM-1": "Physical devices and systems inventoried",
        "PR.AC-1": "Identities and credentials managed",
        "PR.DS-1": "Data-at-rest protected",
        "DE.CM-1": "Network monitored for cyber events",
        "DE.CM-7": "Monitoring for unauthorized personnel and connections",
        "RS.RP-1": "Response plan executed during incidents",
        "RC.RP-1": "Recovery plan executed during events",
    },
    "ISO27001": {
        "A.9.1.1": "Access control policy",
        "A.9.4.1": "Information access restriction",
        "A.12.4.1": "Event logging",
        "A.12.6.1": "Management of technical vulnerabilities",
        "A.16.1.1": "Responsibilities and procedures for incident management",
        "A.16.1.2": "Reporting information security events",
    },
}

# Which slice of platform telemetry speaks to each control. Controls the platform has
# no data for get an explicit "not collected" marker instead of an empty object.
CONTROL_EVIDENCE = {
    "SOC2": {
        "CC6.1": "access", "CC6.2": "access", "CC6.3": "access",
        "CC7.1": "monitoring", "CC7.2": "monitoring", "A1.1": "availability",
    },
    "NIST_CSF": {
        "PR.AC-1": "access", "DE.CM-1": "monitoring", "DE.CM-7": "monitoring",
        "RS.RP-1": "incident_response",
    },
    "ISO27001": {
        "A.9.1.1": "access", "A.9.4.1": "access", "A.12.4.1": "monitoring",
        "A.12.6.1": "vulnerability", "A.16.1.1": "incident_response",
        "A.16.1.2": "incident_response",
    },
}

VALID_STATUSES = ("pass", "fail", "partial", "na")


async def collect_platform_evidence() -> dict[str, dict]:
    """
    Evidence the SOC platform can attest to from its own configuration and records.

    Compliance evaluation used to judge every control against ``{}`` unless the caller
    hand-supplied evidence, so the dashboard's scores were the model's guesses.
    """
    log_stats = await repository.log_stats(hours=24)
    severity_counts = await repository.threat_severity_counts(hours=24)
    incidents = await repository.incident_metrics(hours=24 * 30)
    vulns = await repository.list_vulnerabilities(limit=200)
    registry = await repository.list_agent_registry()

    weak_passwords = [
        name for name, pw in (
            (settings.admin_username, settings.admin_password),
            (settings.analyst_username, settings.analyst_password),
        ) if settings.insecure_password(pw)
    ]
    return {
        "access": {
            "authentication": "JWT bearer token required on every /api/v1 route and the /ws socket",
            "roles": {"admin": "full control", "analyst": "read-only"},
            "websocket_auth_required": settings.websocket_auth_required,
            "signing_key_is_default": settings.insecure_secret_key(),
            "accounts_with_default_or_weak_passwords": weak_passwords,
            "insecure_defaults_allowed": settings.allow_insecure_defaults,
            "login_lockout": {
                "max_failures": settings.login_max_failures,
                "lockout_seconds": settings.login_lockout_seconds,
            },
            "token_lifetime_minutes": settings.api_access_token_expire_minutes,
        },
        "monitoring": {
            "log_analysis_last_24h": log_stats or "persistence disabled — no log volume recorded",
            "threat_detections_last_24h_by_severity": severity_counts,
            "log_search_backend": "elasticsearch" if settings.elasticsearch_enabled else "disabled",
            "metrics_endpoint": "/metrics (Prometheus)",
            "agents": [
                {k: a.get(k) for k in ("agent_name", "status", "last_heartbeat", "tasks_completed", "tasks_failed")}
                for a in registry
            ],
        },
        "availability": {
            "persistence_enabled": settings.enable_persistence,
            "agent_heartbeats_recorded": len(registry),
        },
        "vulnerability": {
            "known_vulnerabilities": len(vulns),
            "critical_or_high": sum(1 for v in vulns if v.get("severity") in ("critical", "high")),
            "open_remediations": sum(1 for v in vulns if v.get("remediation_status") in ("open", "urgent")),
            "scheduled_scan_targets": len(settings.split_csv(settings.vuln_scan_targets)),
            "scan_interval_seconds": settings.vuln_scan_interval,
        },
        "incident_response": {
            "incidents_last_30d": incidents,
            "playbooks": ["brute_force", "ransomware", "data_exfiltration", "c2_beacon", "sql_injection", "default"],
            "containment_mode": settings.containment_mode,
            "containment_requires_approval": settings.containment_require_approval,
        },
    }


def _evidence_for(framework: str, control_id: str, platform: dict, provided: dict) -> dict:
    category = CONTROL_EVIDENCE.get(framework, {}).get(control_id)
    evidence: dict = {}
    if category and category in platform:
        evidence["platform"] = platform[category]
    else:
        evidence["platform"] = {
            "collected": False,
            "note": "The platform records no telemetry for this control; supply evidence via the API.",
        }
    if control_id in provided:
        evidence["provided"] = provided[control_id]
    return evidence


def _as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


EVAL_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a compliance auditor. Evaluate the security control against evidence.
Return JSON:
{{
  "status": "pass|fail|partial|na",
  "score": float (0-100),
  "findings": [str],
  "evidence_quality": "strong|moderate|weak|none",
  "remediation": str,
  "risk_if_failed": "critical|high|medium|low"
}}
Return ONLY valid JSON."""),
    ("human", "Framework: {framework}\nControl: {control_id} - {control_name}\nEvidence:\n{evidence}\nPolicy context:\n{policy_context}"),
])


class ComplianceState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    framework: str
    evidence: dict
    evaluation_id: str
    control_results: list[dict]
    overall_score: float | None
    failed_controls: list[str]
    summary: str


class ComplianceAgent(BaseSecurityAgent):
    name = "compliance"
    description = "Evaluates security controls against compliance frameworks (SOC2, NIST CSF, ISO 27001)"

    def __init__(self):
        super().__init__()
        self._graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(ComplianceState)
        graph.add_node("evaluate_controls", self._evaluate_controls)
        graph.add_node("score_framework", self._score_framework)
        graph.add_node("generate_findings", self._generate_findings)
        graph.set_entry_point("evaluate_controls")
        graph.add_edge("evaluate_controls", "score_framework")
        graph.add_edge("score_framework", "generate_findings")
        graph.add_edge("generate_findings", END)
        return graph.compile()

    async def _evaluate_controls(self, state: ComplianceState) -> dict:
        framework = state["framework"]
        controls = FRAMEWORKS.get(framework, {})
        provided = state["evidence"] if isinstance(state["evidence"], dict) else {}
        try:
            platform = await collect_platform_evidence()
        except Exception:
            platform = {}
        results = []
        for control_id, control_name in controls.items():
            evidence = _evidence_for(framework, control_id, platform, provided)
            policy_ctx = await rag_chain.compliance_rag.ainvoke(
                f"{framework} {control_id} {control_name} compliance requirements"
            )

            chain = EVAL_PROMPT | self.llm
            resp = await chain.ainvoke({
                "framework": framework,
                "control_id": control_id,
                "control_name": control_name,
                "evidence": json.dumps(evidence, default=str)[:6000],
                "policy_context": policy_ctx or "(no policy context available)",
            })
            parsed = parse_json_response(resp.content)
            if parsed is None:
                # No verdict is not a 50% verdict: the old fallback invented a score.
                result = {
                    "status": "na", "score": None, "evidence_quality": "none",
                    "findings": ["The evaluation response could not be parsed"],
                    "remediation": "", "risk_if_failed": None,
                }
            else:
                result = dict(parsed)
                status = str(result.get("status") or "").strip().lower()
                result["status"] = status if status in VALID_STATUSES else "partial"
                score = result.get("score")
                result["score"] = (
                    max(0.0, min(100.0, _as_float(score))) if score is not None else None
                )
                if result.get("risk_if_failed"):
                    result["risk_if_failed"] = str(result["risk_if_failed"]).strip().lower()
            result["control_id"] = control_id
            result["control_name"] = control_name
            result["evidence"] = evidence
            results.append(result)
        return {
            "control_results": results,
            "messages": [AIMessage(content=f"Evaluated {len(results)} controls for {framework}")],
        }

    async def _score_framework(self, state: ComplianceState) -> dict:
        results = state["control_results"]
        if not results:
            return {
                "overall_score": 0.0,
                "failed_controls": [],
                "messages": [AIMessage(content="No controls defined for this framework")],
            }
        scores = [_as_float(r.get("score")) for r in results if r.get("score") is not None]
        overall = round(sum(scores) / len(scores), 1) if scores else None
        failed = [r["control_id"] for r in results if r.get("status") == "fail"]
        return {
            "overall_score": overall,
            "failed_controls": failed,
            "messages": [AIMessage(content=f"Overall compliance score: {overall}% | Failed: {len(failed)}")],
        }

    async def _generate_findings(self, state: ComplianceState) -> dict:
        critical_failures = [
            r for r in state["control_results"]
            if r.get("status") == "fail" and r.get("risk_if_failed") in ("critical", "high")
        ]

        # Persist the control-by-control verdict so posture can be trended over time.
        await repository.save_compliance_results(
            state["framework"], state["control_results"], evaluation_id=state["evaluation_id"]
        )

        if critical_failures:
            await self.escalate({
                "type": "compliance_gap",
                "severity": "high",
                "framework": state["framework"],
                "failed_controls": [r.get("control_id") for r in critical_failures],
                "overall_score": state["overall_score"],
            })

        score = state["overall_score"]
        summary = (
            f"{state['framework']} compliance: {score if score is not None else 'n/a'}% | "
            f"Failed controls: {len(state['failed_controls'])} | "
            f"Critical gaps: {len(critical_failures)}"
        )
        return {"summary": summary, "messages": [AIMessage(content=summary)]}

    async def run(self, input_data: dict) -> dict:
        framework = input_data.get("framework", "SOC2")
        evidence = input_data.get("evidence", {})
        if framework not in FRAMEWORKS:
            return {
                "framework": framework,
                "control_results": [],
                "overall_score": 0.0,
                "failed_controls": [],
                "summary": f"Unsupported framework '{framework}'. Supported: {sorted(FRAMEWORKS)}",
            }
        initial: ComplianceState = {
            "messages": [HumanMessage(content=f"Evaluate {framework} compliance")],
            "framework": framework,
            "evidence": evidence,
            "evaluation_id": str(uuid.uuid4()),
            "control_results": [],
            "overall_score": None,
            "failed_controls": [],
            "summary": "",
        }
        final = await self._graph.ainvoke(initial)
        return {
            "framework": framework,
            "evaluation_id": final["evaluation_id"],
            "control_results": final["control_results"],
            "overall_score": final["overall_score"],
            "failed_controls": final["failed_controls"],
            "summary": final["summary"],
        }
