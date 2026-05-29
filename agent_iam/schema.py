"""
Schema for agent trajectories and anomaly labels.

Label space is adopted directly from ATBench (Apache 2.0, AI45Research/ATBench)
because their three-tier taxonomy (risk_source × failure_mode × harm_category)
is the most fine-grained labeled trajectory dataset publicly available, and
matching their schema makes joint evaluation trivial.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Trace step types
# ---------------------------------------------------------------------------


class Role(str, Enum):
    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    SYSTEM = "system"


class TraceStep(BaseModel):
    """One step in an agent trajectory (ReAct-style: thought / action / observation)."""

    step_idx: int
    role: Role
    thought: str | None = None
    action: dict[str, Any] | None = None  # e.g. {"tool": "Read", "args": {"path": ".env"}}
    observation: str | dict[str, Any] | None = None
    content: str | None = None  # for raw user/system messages without thought/action

    def as_canonical(self) -> str:
        """Render this step as a single canonical text block for tokenization.

        Tags are emitted as bare special tokens so that `<step>`, `<action>`,
        `</action>` etc. are matched as exact-substring special tokens by the
        HF tokenizer. Any per-step metadata (step idx, role, tool) is emitted
        as text content *after* the opening tag — never as an XML-style
        attribute — because attributes like `<action tool=Read>` are not
        substrings of the special token `<action>` and the matcher misses
        them entirely.
        """
        parts = [f"<step> idx={self.step_idx} role={self.role.value}"]
        if self.thought is not None:
            parts.append(f"<thought>{self.thought}</thought>")
        if self.action is not None:
            tool = self.action.get("tool", "?")
            args = self.action.get("args", {})
            parts.append(f"<action>{tool}({args})</action>")
        if self.observation is not None:
            obs = self.observation if isinstance(self.observation, str) else str(self.observation)
            parts.append(f"<observation>{_truncate(obs, 500)}</observation>")
        if self.content is not None:
            parts.append(f"<content>{_truncate(self.content, 500)}</content>")
        parts.append("</step>")
        return "\n".join(parts)


class Trajectory(BaseModel):
    """A full agent trajectory plus optional anomaly label."""

    id: str
    task_instruction: str
    steps: list[TraceStep]
    label: AnomalyLabel | None = None
    source: str = "unknown"  # "atbench", "agentdojo", "agentbank", "synthesized", "live"

    def as_canonical(self) -> str:
        head = f"<task>{self.task_instruction}</task>"
        body = "\n".join(s.as_canonical() for s in self.steps)
        return head + "\n" + body


# ---------------------------------------------------------------------------
# Label space (ATBench-compatible)
# ---------------------------------------------------------------------------


class RiskSource(str, Enum):
    """Where the risk originates (8 categories from ATBench)."""

    USER_PROMPT_INJECTION = "user_prompt_injection"
    TOOL_DESCRIPTION_INJECTION = "tool_description_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    CORRUPTED_TOOL_FEEDBACK = "corrupted_tool_feedback"
    AGENT_HALLUCINATION = "agent_hallucination"
    OVER_AGENCY = "over_agency"
    MISCONFIGURED_PERMISSION = "misconfigured_permission"
    AMBIGUOUS_INSTRUCTION = "ambiguous_instruction"


class FailureMode(str, Enum):
    """What the agent does wrong (14 from ATBench, condensed)."""

    UNAUTHORIZED_DISCLOSURE = "unauthorized_disclosure"   # leak secrets / PII
    DATA_EXFILTRATION = "data_exfiltration"               # outbound transmit
    UNAUTHORIZED_ACTION = "unauthorized_action"           # action outside scope
    DESTRUCTIVE_ACTION = "destructive_action"             # rm -rf etc.
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MISLEADING_INFORMATION = "misleading_information"
    INSTRUCTION_FOR_HARM = "instruction_for_harm"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    FAILED_REFUSAL = "failed_refusal"
    HALLUCINATED_TOOL_USE = "hallucinated_tool_use"
    CHAIN_HIJACK = "chain_hijack"                         # task hijacked mid-trace
    SIDE_EFFECT_LEAK = "side_effect_leak"
    POISONED_MEMORY = "poisoned_memory"
    OTHER = "other"


class HarmCategory(str, Enum):
    PRIVACY = "privacy"
    SECURITY = "security"
    FINANCIAL = "financial"
    PHYSICAL_HEALTH = "physical_health"
    FAIRNESS = "fairness"
    LEGAL = "legal"
    PSYCHOLOGICAL = "psychological"
    REPUTATIONAL = "reputational"
    SYSTEM_INTEGRITY = "system_integrity"
    NONE = "none"


class AnomalyLabel(BaseModel):
    is_anomaly: bool
    anomaly_step: int | None = None
    risk_source: RiskSource | None = None
    failure_mode: FailureMode | None = None
    harm_category: HarmCategory | None = None
    reason: str | None = None


# ---------------------------------------------------------------------------
# Runtime verdict (what the monitor returns to the agent executor)
# ---------------------------------------------------------------------------


VerdictSymbol = Literal["OK", "WARN", "STOP"]


class Verdict(BaseModel):
    symbol: VerdictSymbol
    risk_type: str = ""           # FailureMode value, or "" if OK
    explanation: str = ""
    perplexity: float | None = None   # legacy action-span PPL score (ppl_score path)
    p_stop: float | None = None       # verdict-head P(<symbol>STOP</symbol>) score (check path)
    threshold: float | None = None
    next_action_repr: str = ""    # the action being judged

    @property
    def block(self) -> bool:
        return self.symbol == "STOP"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate(text: str, n: int) -> str:
    if len(text) <= n:
        return text
    return text[: n - 3] + "..."
