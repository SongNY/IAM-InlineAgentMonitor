"""Streaming online inference wrapper around a single-step TraceMonitor.

The single-step path (`monitor.check(trace_so_far, next_action) -> Verdict`)
is stateless: the executor must hand it the full running trace every time.
`StreamingMonitor` holds that running `Trajectory` for you so an agent loop
can drive it incrementally — observe context, *guard* a proposed action
before executing it, then *commit* what actually happened:

    sm = StreamingMonitor(monitor, task_instruction="Summarize ./poisoned.md")
    sm.observe(role="user", content="Summarize ./poisoned.md")

    action = {"tool": "Read", "args": {"file_path": "./poisoned.md"}}
    verdict = sm.guard(action)            # judge BEFORE executing
    if verdict.block:
        raise SecurityError(verdict.risk_type, verdict.explanation)
    result = execute(action)              # your own dispatch
    sm.commit(action=action, observation=result)

`monitor` is duck-typed: anything exposing
``.check(trace: Trajectory, next_action: dict) -> Verdict`` works (a real
`TraceMonitor`, a fake stub in tests, ...). This module intentionally imports
only `..schema`, never torch or `TraceMonitor`, so it stays unit-testable
without a model.
"""

from __future__ import annotations

from typing import Any, Iterable, Iterator

from ..schema import Role, TraceStep, Trajectory, Verdict


class StreamingMonitor:
    """Stateful wrapper that keeps a running `Trajectory` and gates actions.

    Mirrors the dense single-step contract used by `TraceMonitor.check`: the
    proposed action is judged *before* execution and is NOT written into the
    trace by `guard` (the monitor builds its own hypothetical step). Only
    `observe` and `commit` mutate the running trajectory.
    """

    def __init__(
        self,
        monitor: Any,
        task_instruction: str = "",
        source: str = "live",
        auto_halt: bool = True,
    ):
        """
        Args:
            monitor: object with ``.check(Trajectory, dict) -> Verdict``.
            task_instruction: the agent's top-level task (trace header).
            source: provenance tag stored on the `Trajectory`.
            auto_halt: when True, the `guarded(...)` generator stops after the
                first STOP verdict instead of continuing through the iterable.
        """
        self.monitor = monitor
        self.task_instruction = task_instruction
        self.source = source
        self.auto_halt = auto_halt
        self._verdicts: list[Verdict] = []
        self._trajectory = self._new_trajectory()

    def _new_trajectory(self) -> Trajectory:
        return Trajectory(
            id=f"{self.source}-stream",
            task_instruction=self.task_instruction,
            steps=[],
            source=self.source,
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def trajectory(self) -> Trajectory:
        """The running trace (read-only handle; mutate via observe/commit)."""
        return self._trajectory

    @property
    def history(self) -> list[TraceStep]:
        """Steps committed so far, in order."""
        return self._trajectory.steps

    @property
    def verdicts(self) -> list[Verdict]:
        """Every verdict returned by `guard`, in order."""
        return self._verdicts

    # ------------------------------------------------------------------
    # Trace accumulation
    # ------------------------------------------------------------------

    def _append(self, step: TraceStep) -> TraceStep:
        # step_idx is always the current length, mirroring RuntimeAdapter.
        step.step_idx = len(self._trajectory.steps)
        self._trajectory.steps.append(step)
        return step

    def observe(
        self,
        role: str | Role = Role.USER,
        content: str | None = None,
        observation: str | dict[str, Any] | None = None,
    ) -> TraceStep:
        """Append a non-decision step (user/system message or tool output).

        Use this for context the monitor should see but that is not itself an
        agent action being judged — e.g. the initial user prompt, a system
        message, or a standalone tool observation.
        """
        return self._append(
            TraceStep(
                step_idx=0,  # overwritten by _append
                role=Role(role) if not isinstance(role, Role) else role,
                content=content,
                observation=observation,
            )
        )

    def guard(self, next_action: dict[str, Any]) -> Verdict:
        """Judge a PROPOSED action against the running trace, before executing.

        Delegates to ``self.monitor.check``. The proposed action is NOT added
        to the trajectory (a check is hypothetical); call `commit` afterwards
        to record the action you actually ran. The returned verdict is also
        appended to `verdicts`.
        """
        verdict = self.monitor.check(self._trajectory, next_action)
        self._verdicts.append(verdict)
        return verdict

    def commit(
        self,
        action: dict[str, Any],
        thought: str | None = None,
        observation: str | dict[str, Any] | None = None,
    ) -> TraceStep:
        """Record an action that was actually executed.

        Appends a `Role.AGENT` step with the action (and optional thought). If
        `observation` is given, a following `Role.TOOL` step carrying that
        result is appended too, so the running trace stays faithful for the
        next `guard`. Returns the agent step.
        """
        agent_step = self._append(
            TraceStep(
                step_idx=0,  # overwritten by _append
                role=Role.AGENT,
                thought=thought,
                action=action,
            )
        )
        if observation is not None:
            self._append(
                TraceStep(
                    step_idx=0,  # overwritten by _append
                    role=Role.TOOL,
                    observation=observation,
                )
            )
        return agent_step

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def guarded(
        self, actions: Iterable[dict[str, Any]]
    ) -> Iterator[tuple[dict[str, Any], Verdict]]:
        """Guard each action in `actions`, yielding ``(action, verdict)``.

        Does NOT execute or commit the actions — the caller decides what to do
        with each verdict. When `auto_halt` is True, iteration stops right
        after the first STOP verdict (the blocked action is still yielded).
        """
        for action in actions:
            verdict = self.guard(action)
            yield action, verdict
            if self.auto_halt and verdict.block:
                return

    def reset(self) -> None:
        """Clear the running trajectory and verdict history (keeps config)."""
        self._verdicts = []
        self._trajectory = self._new_trajectory()
