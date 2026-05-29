"""Abstract runtime adapter — hooks into a live agent framework to intercept
tool dispatches and query the IAM model for a verdict.

Symmetric to `agent_iam.data.generate.backends.AgentBackend`:

    AgentBackend     — offline log → canonical Trajectory   (training-data side)
    RuntimeAdapter   — online  hook → canonical Trajectory   (deployment side)

Both produce / consume the same `Trajectory` so the model trains once and
runs against any framework.

Typical integration (LangGraph):

    from agent_iam.detect import TraceMonitor
    from agent_iam.runtime.adapters import LangGraphAdapter

    monitor = TraceMonitor.from_pretrained("Sunnyu/IAM-Qwen3.5-2B")
    adapter = LangGraphAdapter(monitor)

    graph = adapter.wrap(graph)   # injects a pre-tool-call interceptor
    graph.invoke({"input": "..."})
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ...schema import Trajectory, TraceStep, Verdict


class RuntimeAdapter(ABC):
    """Hook into a framework's tool-dispatch loop.

    Subclasses must:
      1. accumulate the agent's running trace into a `Trajectory` field, in
         the same canonical shape that the AgentBackend.parse() produces.
      2. on every proposed tool call, build a hypothetical next step and
         hand it to `self.monitor.check(traj, next_action)`.
      3. enforce the verdict: STOP → raise / block; WARN → log; OK → proceed.

    The `monitor` field is duck-typed — anything with a `.check(Trajectory,
    next_action: dict) -> Verdict` method works.
    """

    name: str = ""

    def __init__(self, monitor: Any, on_block: callable | None = None):
        self.monitor = monitor
        self.on_block = on_block or _default_on_block
        self._trace_by_session: dict[str, Trajectory] = {}

    # ------------------------------------------------------------------
    # Per-session trace bookkeeping
    # ------------------------------------------------------------------

    def begin_session(self, session_id: str, task_instruction: str) -> None:
        self._trace_by_session[session_id] = Trajectory(
            id=session_id,
            task_instruction=task_instruction,
            steps=[],
            source=self.name,
        )

    def end_session(self, session_id: str) -> Trajectory | None:
        return self._trace_by_session.pop(session_id, None)

    def append_step(self, session_id: str, step: TraceStep) -> None:
        traj = self._trace_by_session.get(session_id)
        if traj is None:
            return
        step.step_idx = len(traj.steps)
        traj.steps.append(step)

    # ------------------------------------------------------------------
    # Core hook (subclass calls this from the framework's pre-tool callback)
    # ------------------------------------------------------------------

    def gate(self, session_id: str, next_action: dict) -> Verdict:
        """Run the verdict check for a proposed action. Caller enforces."""
        traj = self._trace_by_session.get(session_id)
        if traj is None:
            traj = Trajectory(id=session_id, task_instruction="", steps=[], source=self.name)
        verdict = self.monitor.check(traj, next_action=next_action)
        if verdict.block:
            self.on_block(session_id, next_action, verdict)
        return verdict

    # ------------------------------------------------------------------
    # Framework-specific wiring
    # ------------------------------------------------------------------

    @abstractmethod
    def wrap(self, app: Any) -> Any:
        """Return an instrumented version of `app` with IAM hooks installed.

        Implementations differ wildly between frameworks:
          - LangGraph: install a Pregel node interceptor
          - AutoGen:   register a reply hook
          - Claude Code: launch as a sidecar, agent talks to us via stdin/stdout
          - MCP server: insert middleware in the `tools/call` handler
        """


def _default_on_block(session_id: str, next_action: dict, verdict: Verdict) -> None:
    import logging
    logging.getLogger("agent_iam.runtime").warning(
        "BLOCKED session=%s action=%s reason=%s",
        session_id, next_action, verdict.explanation,
    )
