"""Compliance Agent — continuous control evaluation against SOC2, ISO 27001, NIST CSF."""
from __future__ import annotations
import json
from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from core.rag.rag_chain import compliance_rag

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

EVAL_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a compliance auditor. Evaluate the security control against evidence.
Return JSON:
{
  "status": "pass|fail|partial|na",
  "score": float (0-100),
  "findings": [str],
  "evidence_quality": "strong|moderate|weak|none",
  "remediation": str,
  "risk_if_failed": "critical|high|medium|low"
}
Return ONLY valid JSON."""),
    ("human", "Framework: {framework}\nControl: {control_id} - {control_name}\nEvidence:\n{evidence}\nPolicy context:\n{policy_context}"),
])


class ComplianceState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    framework: str
    evidence: dict
    control_results: list[dict]
    overall_score: float
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
        evidence = state["evidence"]
        results = []
        for control_id, control_name in controls.items():
            policy_ctx = ""
            try:
                policy_ctx = await compliance_rag.ainvoke(
                    f"{framework} {control_id} {control_name} compliance requirements"
                )
            except Exception:
                pass

            chain = EVAL_PROMPT | self.llm
            resp = await chain.ainvoke({
                "framework": framework,
                "control_id": control_id,
                "control_name": control_name,
                "evidence": json.dumps(evidence.get(control_id, {})),
                "policy_context": policy_ctx,
            })
            try:
                result = json.loads(resp.content)
            except Exception:
                result = {"status": "partial", "score": 50.0, "findings": [], "remediation": ""}
            result["control_id"] = control_id
            result["control_name"] = control_name
            results.append(result)
        return {
            "control_results": results,
            "messages": [AIMessage(content=f"Evaluated {len(results)} controls for {framework}")],
        }

    async def _score_framework(self, state: ComplianceState) -> dict:
        results = state["control_results"]
        if not results:
            return {"overall_score": 0.0, "failed_controls": []}
        scores = [r.get("score", 0) for r in results]
        overall = sum(scores) / len(scores)
        failed = [r["control_id"] for r in results if r.get("status") == "fail"]
        return {
            "overall_score": round(overall, 1),
            "failed_controls": failed,
            "messages": [AIMessage(content=f"Overall compliance score: {overall:.1f}% | Failed: {len(failed)}")],
        }

    async def _generate_findings(self, state: ComplianceState) -> dict:
        critical_failures = [
            r for r in state["control_results"]
            if r.get("status") == "fail" and r.get("risk_if_failed") in ("critical", "high")
        ]
        summary = (
            f"{state['framework']} compliance: {state['overall_score']}% | "
            f"Failed controls: {len(state['failed_controls'])} | "
            f"Critical gaps: {len(critical_failures)}"
        )
        return {"summary": summary, "messages": [AIMessage(content=summary)]}

    async def run(self, input_data: dict) -> dict:
        framework = input_data.get("framework", "SOC2")
        evidence = input_data.get("evidence", {})
        initial: ComplianceState = {
            "messages": [HumanMessage(content=f"Evaluate {framework} compliance")],
            "framework": framework,
            "evidence": evidence,
            "control_results": [],
            "overall_score": 0.0,
            "failed_controls": [],
            "summary": "",
        }
        final = await self._graph.ainvoke(initial)
        return {
            "framework": framework,
            "control_results": final["control_results"],
            "overall_score": final["overall_score"],
            "failed_controls": final["failed_controls"],
            "summary": final["summary"],
        }
