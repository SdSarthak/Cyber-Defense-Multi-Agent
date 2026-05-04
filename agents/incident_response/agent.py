"""Incident Response Agent — automated playbook execution and incident lifecycle management."""
from __future__ import annotations
import json
import uuid
from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, END
from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
from langchain_core.prompts import ChatPromptTemplate
from agents.base_agent import BaseSecurityAgent
from core.database.redis_client import cache
from core.memory.agent_memory import AgentMemory

PLAYBOOKS = {
    "brute_force": [
        "Block source IP at firewall",
        "Reset compromised account credentials",
        "Enable MFA on affected accounts",
        "Review authentication logs for last 24h",
        "Notify security team",
    ],
    "ransomware": [
        "Isolate affected host(s) from network immediately",
        "Preserve memory dump and disk image",
        "Identify patient-zero and infection vector",
        "Check backup integrity and initiate recovery",
        "Notify legal, compliance, and management",
        "File incident report with law enforcement if required",
    ],
    "data_exfiltration": [
        "Block destination IPs/domains at egress firewall",
        "Terminate suspicious network connections",
        "Identify exfiltrated data scope",
        "Preserve evidence (PCAP, logs)",
        "Initiate breach notification procedure",
    ],
    "c2_beacon": [
        "Isolate beaconing host",
        "Block C2 domain/IP at DNS and firewall",
        "Conduct memory forensics for malware artifacts",
        "Scan other hosts for same IOCs",
        "Wipe and reimage host after evidence collection",
    ],
    "sql_injection": [
        "Block attacking IP at WAF",
        "Review database audit logs for exfiltrated data",
        "Patch or mitigate vulnerable endpoint",
        "Rotate database credentials",
        "Notify data protection officer if PII affected",
    ],
    "default": [
        "Collect and preserve all relevant logs",
        "Identify scope and affected assets",
        "Apply containment measures",
        "Notify security team",
        "Document timeline and actions",
    ],
}

RESPONSE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are an incident response coordinator. Given the incident details and playbook steps,
generate a detailed response plan as JSON:
{
  "incident_id": str,
  "playbook": str,
  "priority": "p1|p2|p3|p4",
  "containment_actions": [{"action": str, "automated": bool, "status": "pending"}],
  "investigation_steps": [str],
  "communication_plan": {"internal": str, "external": str},
  "timeline": [{"time": str, "event": str}],
  "estimated_resolution": str,
  "lessons_learned": [str]
}
Return ONLY valid JSON."""),
    ("human", "Incident:\n{incident}\n\nPlaybook steps:\n{playbook_steps}\n\nThreat assessment:\n{assessment}"),
])


class IRState(TypedDict):
    messages: Annotated[list[BaseMessage], operator.add]
    incident: dict
    threat_assessment: dict
    playbook_name: str
    response_plan: dict
    actions_taken: list[dict]
    summary: str


class IncidentResponseAgent(BaseSecurityAgent):
    name = "incident_response"
    description = "Executes incident response playbooks and coordinates containment actions"

    def __init__(self):
        super().__init__()
        self._graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        graph = StateGraph(IRState)
        graph.add_node("select_playbook", self._select_playbook)
        graph.add_node("build_response_plan", self._build_response_plan)
        graph.add_node("execute_containment", self._execute_containment)
        graph.add_node("update_incident", self._update_incident)
        graph.set_entry_point("select_playbook")
        graph.add_edge("select_playbook", "build_response_plan")
        graph.add_edge("build_response_plan", "execute_containment")
        graph.add_edge("execute_containment", "update_incident")
        graph.add_edge("update_incident", END)
        return graph.compile()

    async def _select_playbook(self, state: IRState) -> dict:
        threat_type = (
            state["threat_assessment"].get("threat_type", "")
            or state["incident"].get("type", "default")
        ).lower()
        playbook_name = "default"
        for key in PLAYBOOKS:
            if key in threat_type:
                playbook_name = key
                break
        return {
            "playbook_name": playbook_name,
            "messages": [AIMessage(content=f"Selected playbook: {playbook_name}")],
        }

    async def _build_response_plan(self, state: IRState) -> dict:
        playbook_steps = PLAYBOOKS.get(state["playbook_name"], PLAYBOOKS["default"])
        chain = RESPONSE_PROMPT | self.llm
        resp = await chain.ainvoke({
            "incident": json.dumps(state["incident"]),
            "playbook_steps": json.dumps(playbook_steps),
            "assessment": json.dumps(state["threat_assessment"]),
        })
        try:
            plan = json.loads(resp.content)
            if not plan.get("incident_id"):
                plan["incident_id"] = state["incident"].get("id", str(uuid.uuid4()))
        except json.JSONDecodeError:
            plan = {
                "incident_id": state["incident"].get("id", str(uuid.uuid4())),
                "playbook": state["playbook_name"],
                "priority": "p2",
                "containment_actions": [{"action": s, "automated": False, "status": "pending"} for s in playbook_steps],
                "investigation_steps": [],
                "communication_plan": {},
                "timeline": [],
                "estimated_resolution": "TBD",
                "lessons_learned": [],
            }
        return {"response_plan": plan,
                "messages": [AIMessage(content=f"Response plan built: {plan.get('priority')} priority")]}

    async def _execute_containment(self, state: IRState) -> dict:
        actions_taken = []
        for action in state["response_plan"].get("containment_actions", []):
            if action.get("automated"):
                result = await self._simulate_action(action["action"], state["incident"])
                action["status"] = "completed" if result["success"] else "failed"
                action["result"] = result
                actions_taken.append(action)
        await cache.publish("incident_updates", {
            "agent": self.name,
            "incident_id": state["response_plan"].get("incident_id"),
            "actions_taken": len(actions_taken),
            "plan": state["response_plan"],
        })
        return {"actions_taken": actions_taken,
                "messages": [AIMessage(content=f"Executed {len(actions_taken)} automated containment actions")]}

    async def _update_incident(self, state: IRState) -> dict:
        await cache.set(
            f"incident:{state['response_plan'].get('incident_id')}",
            {
                "response_plan": state["response_plan"],
                "actions_taken": state["actions_taken"],
                "status": "investigating",
            },
            ttl=86400,
        )
        summary = (
            f"Incident {state['response_plan'].get('incident_id', 'N/A')} | "
            f"Playbook: {state['playbook_name']} | "
            f"Priority: {state['response_plan'].get('priority')} | "
            f"Actions: {len(state['actions_taken'])} automated"
        )
        return {"summary": summary, "messages": [AIMessage(content=summary)]}

    @staticmethod
    async def _simulate_action(action: str, incident: dict) -> dict:
        """In simulation mode, mark actions as completed. In production, integrate SOAR/firewall APIs."""
        return {"success": True, "action": action, "note": "simulated"}

    async def run(self, input_data: dict) -> dict:
        incident = input_data.get("incident", {})
        threat_assessment = input_data.get("threat_assessment", {})
        initial: IRState = {
            "messages": [HumanMessage(content=f"Respond to incident: {json.dumps(incident)[:200]}")],
            "incident": incident,
            "threat_assessment": threat_assessment,
            "playbook_name": "default",
            "response_plan": {},
            "actions_taken": [],
            "summary": "",
        }
        final = await self._graph.ainvoke(initial)
        return {
            "response_plan": final["response_plan"],
            "actions_taken": final["actions_taken"],
            "playbook_name": final["playbook_name"],
            "summary": final["summary"],
        }
