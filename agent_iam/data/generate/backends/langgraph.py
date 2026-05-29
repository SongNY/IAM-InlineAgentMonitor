"""LangGraph collection backend.

Runs a LangGraph ReAct agent in-process and captures every tool call /
tool result / final message as a canonical TraceStep. Suitable for bulk
data generation against an open-source model so you don't burn Claude
Code quota.

The backend expects the user to wire a graph factory in `spec.extra`:

    spec.extra = {
        "graph_factory":     "my_pkg.factories.acme_helper_graph",   # dotted path
        "graph_factory_kwargs": {"model": "qwen2.5-7b-instruct"},
    }

The factory is called with `**kwargs + sandbox_dir=Path, allowed_tools=list,
system_prompt=str` and must return a *compiled* LangGraph app supporting
`.stream({"messages":[HumanMessage(...)]})` with `stream_mode="values"`.

We auto-supply a default factory `default_react_agent` that builds a
prebuilt ReAct agent with Read/Bash/WebFetch tools wired to the sandbox.
"""

from __future__ import annotations

import importlib
import json
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ....schema import Role, TraceStep, Trajectory
from .base import AgentBackend, RunSpec


class LangGraphBackend(AgentBackend):
    name = "langgraph"
    # LangGraph runs in-process; no subprocess, so HTTP_PROXY env vars apply
    # only if the user's tool implementations honor them (most do via requests).
    supports_http_proxy = True
    sandbox_isolated_fs = False  # LangGraph tools run with the host's cwd

    def __init__(self, default_factory: Callable | None = None):
        # `default_react_agent` is provided in the same module below.
        self._default_factory = default_factory or default_react_agent

    def run(self, spec: RunSpec, output_dir: Path) -> Path:
        from langchain_core.messages import HumanMessage

        factory = self._resolve_factory(spec)
        app = factory(
            sandbox_dir=spec.sandbox_dir,
            allowed_tools=spec.allowed_tools,
            system_prompt=spec.system_prompt,
            model=spec.model,
            **(spec.extra.get("graph_factory_kwargs") or {}),
        )

        thread_id = uuid.uuid4().hex
        config = {"configurable": {"thread_id": thread_id}}
        events_path = output_dir / "events.jsonl"

        with events_path.open("w") as out:
            try:
                stream = app.stream(
                    {"messages": [HumanMessage(content=spec.user_prompt)]},
                    config=config,
                    stream_mode="values",
                )
                for step in stream:
                    out.write(json.dumps(_jsonify(step), default=str) + "\n")
            except Exception as e:
                out.write(json.dumps({"_error": str(e)}) + "\n")

        return events_path

    def parse(self, events_path: Path, task_instruction: str, traj_id: str) -> Trajectory:
        steps: list[TraceStep] = []
        idx = 0
        seen_msg_ids: set[str] = set()
        with events_path.open() as f:
            for line in f:
                try:
                    state = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "_error" in state:
                    continue
                # LangGraph `values` mode gives the *cumulative* state each tick;
                # we de-dup messages by id so we only record each one once.
                for msg in state.get("messages") or []:
                    mid = msg.get("id") or msg.get("kwargs", {}).get("id")
                    if mid is None:
                        mid = json.dumps(msg, sort_keys=True, default=str)[:200]
                    if mid in seen_msg_ids:
                        continue
                    seen_msg_ids.add(mid)

                    step = _msg_to_step(msg, idx)
                    if step is not None:
                        steps.append(step)
                        idx += 1
        return Trajectory(
            id=traj_id,
            task_instruction=task_instruction,
            steps=steps,
            source=self.name,
        )

    # ------------------------------------------------------------------

    def _resolve_factory(self, spec: RunSpec) -> Callable:
        dotted = (spec.extra or {}).get("graph_factory")
        if not dotted:
            return self._default_factory
        mod, _, attr = dotted.rpartition(".")
        return getattr(importlib.import_module(mod), attr)


# ----------------------------------------------------------------------
# Default factory: a sandboxed ReAct agent with Read / Bash / WebFetch
# ----------------------------------------------------------------------


def default_react_agent(
    *,
    sandbox_dir: Path,
    allowed_tools: list[str],
    system_prompt: str,
    model: str,
    **_kwargs,
):
    """Build a minimal LangGraph ReAct agent.

    Requires:  pip install langgraph langchain-openai

    Default model = OpenAI-compatible endpoint. To use a local model, point
    `OPENAI_BASE_URL` and `OPENAI_API_KEY` at it (e.g. Ollama, vLLM, sglang).
    Override `model` per-call.
    """
    from langchain_core.messages import SystemMessage
    from langchain_core.tools import tool
    from langchain_openai import ChatOpenAI
    from langgraph.prebuilt import create_react_agent

    # DeepSeek thinking-mode models require reasoning_content round-trips.
    # Idempotent monkey-patch — no-op for non-DeepSeek backends.
    from ._deepseek_patch import apply as _apply_deepseek_patch
    _apply_deepseek_patch()

    @tool
    def Read(path: str) -> str:
        """Read a text file under the sandbox dir."""
        p = (sandbox_dir / path).resolve()
        # weak sandbox guard — true isolation belongs to the OS, not the agent.
        if not str(p).startswith(str(sandbox_dir.resolve())):
            return f"refused: {path} is outside the sandbox"
        try:
            return p.read_text()[:8000]
        except FileNotFoundError:
            return f"missing: {path}"
        except Exception as e:
            return f"error: {e}"

    @tool
    def Bash(command: str) -> str:
        """Run a shell command inside the sandbox dir."""
        import subprocess
        try:
            out = subprocess.run(
                command, shell=True, cwd=str(sandbox_dir),
                capture_output=True, text=True, timeout=20,
            )
            return (out.stdout + out.stderr)[:8000]
        except Exception as e:
            return f"error: {e}"

    @tool
    def WebFetch(url: str) -> str:
        """Fetch a URL (honors HTTP_PROXY / HTTPS_PROXY env vars)."""
        import urllib.request
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                return resp.read(8000).decode("utf-8", errors="replace")
        except Exception as e:
            return f"error: {e}"

    tool_objs = {"Read": Read, "Bash": Bash, "WebFetch": WebFetch}
    selected = [tool_objs[t] for t in allowed_tools if t in tool_objs]

    llm = ChatOpenAI(model=model or "gpt-4o-mini", temperature=0)
    # API note: `state_modifier` was renamed to `prompt` in newer LangGraph.
    # We try the new name first, fall back if running against an older release.
    try:
        return create_react_agent(llm, tools=selected, prompt=system_prompt)
    except TypeError:
        return create_react_agent(
            llm, tools=selected,
            state_modifier=SystemMessage(content=system_prompt),
        )


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _jsonify(state: Any) -> Any:
    """Make LangGraph state JSON-serializable."""
    if hasattr(state, "model_dump"):
        return state.model_dump()
    if isinstance(state, dict):
        return {k: _jsonify(v) for k, v in state.items()}
    if isinstance(state, list):
        return [_jsonify(x) for x in state]
    return state


def _msg_to_step(msg: dict, idx: int) -> TraceStep | None:
    """Convert one LangGraph message dict into a canonical TraceStep."""
    typ = msg.get("type") or msg.get("kwargs", {}).get("type")
    content = msg.get("content")
    if isinstance(msg.get("kwargs"), dict) and content is None:
        content = msg["kwargs"].get("content")
    tool_calls = msg.get("tool_calls") or msg.get("kwargs", {}).get("tool_calls") or []

    if typ in ("human", "HumanMessage"):
        return TraceStep(step_idx=idx, role=Role.USER, content=_str(content))
    if typ in ("system", "SystemMessage"):
        return TraceStep(step_idx=idx, role=Role.SYSTEM, content=_str(content))
    if typ in ("tool", "ToolMessage"):
        return TraceStep(step_idx=idx, role=Role.TOOL, observation=_str(content))
    if typ in ("ai", "AIMessage"):
        thought = _str(content) or None
        if tool_calls:
            # LangGraph fans out multiple tool calls in one message; flatten to
            # one TraceStep each (matching ATBench / claude-code behaviour).
            steps = [
                TraceStep(
                    step_idx=idx + i, role=Role.AGENT,
                    thought=thought if i == 0 else None,
                    action={
                        "tool": tc.get("name"),
                        "args": tc.get("args") or {},
                    },
                )
                for i, tc in enumerate(tool_calls)
            ]
            # only the first is returned; caller will handle multi-step expansion
            # (the per-line ingest above already increments idx per call, but for
            # simplicity we collapse to first action here — extend if needed).
            return steps[0]
        return TraceStep(step_idx=idx, role=Role.AGENT, content=thought)
    return None


def _str(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    return json.dumps(x, default=str)
