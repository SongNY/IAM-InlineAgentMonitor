"""One-line deployment: turn IAM into a live guard around your agent's tools.

    import agent_iam
    tools = agent_iam.guard(tools)        # loads IAM-2B (GPU autodetected), gates every call

That's it. Every tool call is now checked by the monitor *before* it runs; a
STOP raises :class:`IAMBlocked` so the harmful action never executes. The model
is loaded once and cached across calls, so this is cheap to call repeatedly.

Forms:
    agent_iam.guard({"read": read, "post": post})   # dict registry -> guarded dict
    agent_iam.guard([tool_a, tool_b])               # list -> guarded list
    safe = agent_iam.guard(single_tool_fn)          # one callable -> guarded callable
    adapter = agent_iam.guard()                      # no tools -> a ready GenericAdapter

Knobs: ``model`` (HF id or local path), ``threshold`` (P(STOP) cutoff),
``device`` ("cuda"/"cpu"/None=autodetect), ``on_block`` (callback), and a
``session_id`` / ``task_instruction`` for the running trace.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .runtime.adapters import GenericAdapter  # torch-free

DEFAULT_MODEL = "Sunnyu/IAM-Qwen3.5-2B"

# Cache loaded monitors by (model, threshold, device) so repeated guard() calls
# don't reload multi-GB weights. The heavy import (torch/transformers) happens
# lazily inside _load_monitor, keeping `import agent_iam` light.
_MONITOR_CACHE: dict[tuple, Any] = {}


def _load_monitor(model: str, threshold: float, device: str | None):
    key = (model, threshold, device)
    mon = _MONITOR_CACHE.get(key)
    if mon is None:
        from .detect.online import TraceMonitor  # imports torch — deferred to first use
        mon = TraceMonitor.from_pretrained(model, threshold=threshold, device=device)
        _MONITOR_CACHE[key] = mon
    return mon


def guard(
    tools: Any = None,
    *,
    model: str = DEFAULT_MODEL,
    threshold: float = 0.5,
    device: str | None = None,
    session_id: str = "default",
    task_instruction: str = "",
    on_block: Callable | None = None,
) -> Any:
    """Load IAM and gate tool calls in one line (GPU autodetected).

    Returns the same *shape* you pass in:
      - a dict ``{name: fn}``  -> a guarded dict
      - a list of callables    -> a guarded list
      - a single callable      -> a guarded callable
      - nothing                -> a ready :class:`GenericAdapter`

    A STOP verdict raises :class:`agent_iam.IAMBlocked` before the tool runs.
    """
    monitor = _load_monitor(model, threshold, device)
    adapter = GenericAdapter(monitor, on_block=on_block)
    if tools is None:
        if task_instruction:
            adapter.begin_session(session_id, task_instruction)
        return adapter
    if callable(tools) and not isinstance(tools, Mapping):
        return adapter.guard_tool(tools, session_id=session_id)
    return adapter.wrap(tools, session_id=session_id, task_instruction=task_instruction)


# Friendly alias.
protect = guard
