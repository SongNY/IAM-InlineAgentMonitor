"""Abstract agent backend.

A backend is anything that can take a prompt + sandbox + allowed tools and
produce a stream of agent events. TraceGuard does not care which framework —
it normalizes everything to the canonical `Trajectory` schema.

Implementations live alongside this file:
    claude_code.py   — Anthropic Claude Code CLI (claude -p)
    openhands.py     — OpenHands (formerly OpenDevin) CLI
    langgraph.py     — in-process LangGraph runs via the official Python API
    hermes.py        — Hermes agent framework
    generic_react.py — any model + a minimal Python ReAct loop you provide

Adding a new framework = subclass `AgentBackend`, implement two methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ....schema import Trajectory


@dataclass
class RunSpec:
    """Everything a backend needs to execute one scenario run."""

    user_prompt: str
    sandbox_dir: Path
    allowed_tools: list[str]
    system_prompt: str
    timeout_s: int = 120
    env_overrides: dict[str, str] = field(default_factory=dict)
    model: str = ""                     # backend-specific model id
    extra: dict = field(default_factory=dict)   # backend-specific knobs


class AgentBackend(ABC):
    """Adapt a specific agent framework to TraceGuard's data pipeline."""

    #: short name used in CLI flags / dataset metadata (e.g. "claude_code")
    name: str = ""

    @abstractmethod
    def run(self, spec: RunSpec, output_dir: Path) -> Path:
        """Execute the agent and write raw events to `<output_dir>/events.*`.

        Returns the path to the raw event log so downstream callers can keep
        forensics. Backends are free to choose their own log format — the
        parser below is the only thing that needs to understand it.
        """

    @abstractmethod
    def parse(self, events_path: Path, task_instruction: str, traj_id: str) -> Trajectory:
        """Parse the raw event log into a canonical `Trajectory`.

        Each step's `action` should look like
            {"tool": "<name>", "args": {...}}
        matching the predicate format the auto-labeler expects.
        """

    # ------------------------------------------------------------------
    # Optional capability flags
    # ------------------------------------------------------------------

    #: Does this backend honor HTTP_PROXY env vars? If False, the runner will
    #: skip the MockServer setup and you should mock at a different layer.
    supports_http_proxy: bool = True

    #: Does this backend write files inside the sandbox dir, or do we need
    #: to copy outputs out? Most CLI-style backends keep state in sandbox.
    sandbox_isolated_fs: bool = True
