"""
Guards against a whole class of prompt bugs.

Every agent prompt embeds a literal JSON schema. In a ChatPromptTemplate a single
brace opens a template variable, so an unescaped `{"severity": str}` becomes an
input variable named `"severity": str` and the template raises KeyError at invoke
time — on every single call, for every user. Doubling the braces (`{{`) is the fix;
these tests assert each prompt declares exactly the variables its caller supplies.
"""
import pytest

from agents.compliance.agent import EVAL_PROMPT
from agents.incident_response.agent import RESPONSE_PROMPT
from agents.log_analysis.agent import ANALYSIS_PROMPT
from agents.reporting.agent import EXEC_REPORT_PROMPT, THREAT_REPORT_PROMPT
from agents.supervisor.agent import ROUTER_PROMPT
from agents.threat_detection.agent import ASSESSMENT_PROMPT, ENRICHMENT_PROMPT
from agents.vulnerability_intel.agent import RISK_PROMPT

# prompt -> the exact kwargs the agent passes at the call site
PROMPT_INPUTS = [
    pytest.param(ASSESSMENT_PROMPT, {"event", "context"}, id="threat_assessment"),
    pytest.param(ENRICHMENT_PROMPT, {"ioc", "tool_results"}, id="threat_enrichment"),
    pytest.param(ANALYSIS_PROMPT, {"count", "logs", "pattern_hits"}, id="log_analysis"),
    pytest.param(RISK_PROMPT, {"cve_data", "asset_context", "kb_context"}, id="vuln_risk"),
    pytest.param(
        RESPONSE_PROMPT, {"incident", "playbook_steps", "assessment"}, id="incident_response"
    ),
    pytest.param(
        EVAL_PROMPT,
        {"framework", "control_id", "control_name", "evidence", "policy_context"},
        id="compliance_eval",
    ),
    pytest.param(EXEC_REPORT_PROMPT, {"period", "data"}, id="executive_report"),
    pytest.param(THREAT_REPORT_PROMPT, {"threat_data"}, id="threat_report"),
    pytest.param(ROUTER_PROMPT, {"task", "threat_level"}, id="supervisor_router"),
]


@pytest.mark.parametrize("prompt,expected", PROMPT_INPUTS)
def test_prompt_declares_exactly_the_expected_variables(prompt, expected):
    assert set(prompt.input_variables) == expected


@pytest.mark.parametrize("prompt,expected", PROMPT_INPUTS)
def test_prompt_formats_without_keyerror(prompt, expected):
    """Formatting with only the documented inputs must succeed."""
    rendered = prompt.format(**{name: "x" for name in expected})
    assert rendered


@pytest.mark.parametrize("prompt,expected", PROMPT_INPUTS)
def test_json_schema_braces_survive_rendering(prompt, expected):
    """The escaped schema must render back as literal single braces for the model."""
    rendered = prompt.format(**{name: "x" for name in expected})
    if "JSON" in rendered or "json" in rendered:
        assert "{{" not in rendered, "double braces leaked into the rendered prompt"
