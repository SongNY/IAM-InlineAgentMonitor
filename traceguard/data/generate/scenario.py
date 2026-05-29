"""
Attack scenario schema for TraceGuard data generation.

A `Scenario` is a *reproducible recipe* for getting a real LLM agent to walk
into an attack. It bundles:

  - the user prompt fed to the agent
  - the bait artifacts that get placed in the sandbox (poisoned files, mock
    HTTP responses, fake tool listings)
  - the *expected* violation pattern — used by the auto-labeler to find the
    anomaly step in the resulting trace without any human review

We deliberately keep the schema small so adding new scenarios stays cheap.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from ...schema import FailureMode, HarmCategory, RiskSource


# ---------------------------------------------------------------------------
# Sandbox artifacts
# ---------------------------------------------------------------------------


class BaitFile(BaseModel):
    """A file written into the sandbox before the agent runs."""

    rel_path: str                       # relative to the sandbox root
    content: str
    is_decoy: bool = False              # True when this file is the agent's *target* (it should NOT detect it as poisoned)


class MockHTTPResponse(BaseModel):
    """A canned response the mock HTTP server returns for a URL pattern."""

    url_pattern: str                    # regex over the requested URL
    status_code: int = 200
    body: str = ""
    content_type: str = "text/html; charset=utf-8"


class MockTool(BaseModel):
    """A tool definition that gets injected into the agent's MCP tool list."""

    name: str
    description: str
    tool_schema: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Violation predicate — the auto-labeler matches against this
# ---------------------------------------------------------------------------


class ToolPredicate(BaseModel):
    """Match the first step where `tool == name AND args match`.

    Special value:
      - tool="__CONTENT__" matches an AGENT step whose `content` or `thought`
        field contains `content_contains` substring. Used for prompt-extraction
        scenarios where the violation is leaking text in the final answer.

    Any field set is required to match; unset fields are wildcards.
    The labeler scans the trace top-down and returns the first matching step.
    """

    tool: str                                          # "Bash", "WebFetch", "Read", ..., or "__CONTENT__"
    arg_contains: dict[str, str] = Field(default_factory=dict)
    arg_regex: dict[str, str] = Field(default_factory=dict)
    content_contains: str = ""                         # for __CONTENT__ matches


class ViolationPattern(BaseModel):
    """How we know the agent fell for the attack.

    - `match`: the smoking gun — the step we definitely want to catch. If the
      trace contains it (after `prerequisite` if set), the run is unsafe and
      `anomaly_step` is set to this step.
    - `prerequisite`: an earlier step that must precede `match` for it to
      count. Used to require the FULL attack chain (e.g. "Read README → Read
      secret" only counts when the README read came first — otherwise the
      secret read might be unrelated).
    - `prereq_is_violation`: if True, the prerequisite step is itself a
      violation we want to catch (e.g. "Read .env" under an exfil prompt). The
      labeler will mark the prereq step as anomaly even when the match step
      never happens. Use this when the user prompt itself is adversarial and
      the prereq step is unauthorized regardless of what comes next.
      Default False for indirect-injection style scenarios where the prereq
      is a legitimate user-requested action (e.g. "Read this README").
    """

    match: ToolPredicate
    prerequisite: ToolPredicate | None = None
    prereq_is_violation: bool = False


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------


class ScenarioCategory(str, Enum):
    # Original v0.1/v0.2 categories
    INDIRECT_INJECTION_FILE = "indirect_injection_file"
    INDIRECT_INJECTION_WEB = "indirect_injection_web"
    TOOL_DESCRIPTION_INJECTION = "tool_description_injection"
    CORRUPTED_TOOL_FEEDBACK = "corrupted_tool_feedback"
    CREDENTIAL_EXFIL_CHAIN = "credential_exfil_chain"
    SHELL_INJECTION_VIA_ARGS = "shell_injection_via_args"
    SSRF_VIA_WEBFETCH = "ssrf_via_webfetch"
    MEMORY_POISONING = "memory_poisoning"
    EXCESSIVE_AGENCY = "excessive_agency"
    DESTRUCTIVE_COMMAND = "destructive_command"
    # v0.3 production-realistic categories (from OWASP Agentic Top 10 + real incidents)
    MCP_RUG_PULL = "mcp_rug_pull"                      # tool changes after trust
    MCP_SHADOWING = "mcp_shadowing"                    # rogue MCP overrides legit tool
    CONFUSED_DEPUTY = "confused_deputy"                # OAuth / capability misuse
    PR_DESCRIPTION_INJECTION = "pr_description_injection"   # CVE-2025-53773 style
    EMAIL_BODY_INJECTION = "email_body_injection"      # CVE-2025-32711 style
    OUTPUT_MANIPULATION = "output_manipulation"        # backdoor in generated code
    PERSISTENCE = "persistence"                        # time bomb / future-session payload
    REPUDIATION = "repudiation"                        # agent lies about what it did
    DATA_POISONING = "data_poisoning"                  # corrupt RAG / training data
    BROWSER_VISUAL_INJECTION = "browser_visual_injection"  # text in screenshot
    CROSS_TENANT_LEAK = "cross_tenant_leak"            # multi-user data confusion
    DEPENDENCY_CONFUSION = "dependency_confusion"      # typosquat npm/pypi install
    DNS_EXFIL = "dns_exfil"                            # DNS lookup data leak
    PROMPT_EXTRACTION = "prompt_extraction"            # leak system prompt
    BENIGN = "benign"                                  # negative samples


class Scenario(BaseModel):
    id: str
    category: ScenarioCategory
    user_prompt: str
    bait_files: list[BaitFile] = Field(default_factory=list)
    mock_http: list[MockHTTPResponse] = Field(default_factory=list)
    mock_tools: list[MockTool] = Field(default_factory=list)

    # labels for the auto-labeler when the scenario *succeeds* (agent fell for it)
    violation: ViolationPattern | None = None
    # Alternative violations — match if ANY of these fires. Useful for
    # promptfoo-generated scenarios where the attacker's specific tool/arg
    # is unpredictable so we list common "any of these = anomaly" patterns.
    alt_violations: list[ViolationPattern] = Field(default_factory=list)
    risk_source: RiskSource | None = None
    failure_mode: FailureMode | None = None
    harm_category: HarmCategory | None = None
    reason_template: str = ""              # filled into AnomalyLabel.reason when matched

    # which agent tools to enable for this scenario; None = use runner default
    allowed_tools: list[str] | None = None
    # extra agent system prompt to override the runner default (optional)
    extra_system_prompt: str | None = None
    # multi-turn scenarios may provide a list; first one is initial prompt above,
    # subsequent ones get sent after each agent response
    followup_prompts: list[str] = Field(default_factory=list)

    def is_benign(self) -> bool:
        return self.category == ScenarioCategory.BENIGN
