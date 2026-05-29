"""Data structures + config for the API-based security monitor.

This monitor is the *stateless-call + external-state* design: every trace is a
fresh `messages.create` call whose context the code reassembles, instead of a
long-lived KV session. State (Ledger + sliding window) lives here, in Python.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Output enums (mirrored in the system policy and enforced by the parser).
VERDICTS = ("ok", "warn", "block")
CATEGORIES = (
    "none",
    "data_exfiltration",
    "privilege_escalation",
    "destructive",
    "injection",
    "other",
)


@dataclass
class Trace:
    """One agent step to be judged. `args`/`result`/`action` are free-form."""

    step_id: int
    action: str = ""
    tool: str = ""
    args: Any = None
    result: Any = None
    timestamp: float | None = None


@dataclass
class LedgerEntry:
    """An append-only safety fact the monitor chose to remember."""

    step_id: int
    fact: str


@dataclass
class Verdict:
    """The monitor's decision for one trace."""

    verdict: str  # ok | warn | block
    severity: int  # 0..3
    category: str  # one of CATEGORIES
    reason: str
    remember: list[str] = field(default_factory=list)

    @property
    def block(self) -> bool:
        return self.verdict == "block"

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "severity": self.severity,
            "category": self.category,
            "reason": self.reason,
            "remember": list(self.remember),
        }


@dataclass
class MonitorState:
    """External state: append-only Ledger (long-range memory) + recent window."""

    ledger: list[LedgerEntry] = field(default_factory=list)
    window: list[Trace] = field(default_factory=list)


@dataclass
class MonitorConfig:
    """Defaults from the spec (§11). Tune per deployment."""

    model: str = "claude-sonnet-4-6"           # MUST differ from the monitored agent's model
    max_tokens: int = 256
    window_max_traces: int = 10
    window_token_budget: int = 10_000
    per_trace_token_cap: int = 1_500
    ledger_token_soft_cap: int = 4_000
    api_timeout_s: float = 20.0
    api_max_retries: int = 2
    fail_closed_verdict: str = "block"
    use_structured_outputs: bool = False        # optional: constrain output via output_config.format


# JSON schema for the optional structured-outputs path (output_config.format).
OUTPUT_JSON_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "severity": {"type": "integer", "enum": [0, 1, 2, 3]},
        "category": {"type": "string", "enum": list(CATEGORIES)},
        "reason": {"type": "string"},
        "remember": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "severity", "category", "reason", "remember"],
    "additionalProperties": False,
}
