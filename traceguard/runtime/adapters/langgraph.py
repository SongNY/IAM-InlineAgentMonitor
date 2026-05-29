"""LangGraph runtime adapter.

Strategy: LangGraph compiles a state graph into a Pregel runtime. We insert
a synchronous interceptor node ahead of any `ToolNode` so we can gate the
proposed tool call before dispatch.

Two integration points:

  A) `wrap(graph)` — given a compiled graph, returns a new graph with the
     interceptor edged before every tool node. Best for opinionated users.

  B) Manual: call `adapter.gate(session_id, next_action)` yourself from
     wherever you build the tool call (works for any custom graph shape).

Trace accumulation:
  - On `__start__`, we open a session keyed by the LangGraph `thread_id`.
  - On every assistant message with tool_calls, we record the (thought, action)
    pair as a TraceStep; on each ToolMessage we record the observation.
  - On graph end, we hand the completed Trajectory to any registered sinks
    (e.g. for collection-pipeline reuse).
"""

from __future__ import annotations

import json
from typing import Any

from ...schema import Role, TraceStep
from .base import RuntimeAdapter


class LangGraphAdapter(RuntimeAdapter):
    name = "langgraph"

    def wrap(self, app: Any) -> Any:
        """Install a pre-tool interceptor on a compiled LangGraph app.

        We use the callback API rather than rewriting nodes — it's the
        upstream-stable surface and doesn't require knowing the graph topology.
        """
        try:
            from langchain_core.callbacks import BaseCallbackHandler
        except ImportError as e:
            raise RuntimeError(
                "LangGraphAdapter requires langchain-core. Install with: "
                "pip install langgraph langchain-core"
            ) from e

        outer = self

        class _Cb(BaseCallbackHandler):
            def on_chain_start(self, serialized, inputs, *, run_id, **kw):
                outer.begin_session(str(run_id), str(inputs)[:200])

            def on_chat_model_end(self, response, *, run_id, parent_run_id=None, **kw):
                sid = str(parent_run_id or run_id)
                # extract tool_calls from the AIMessage
                for gen in response.generations:
                    for g in gen:
                        msg = getattr(g, "message", None)
                        if msg is None:
                            continue
                        thought = getattr(msg, "content", None) or None
                        tool_calls = getattr(msg, "tool_calls", []) or []
                        for tc in tool_calls:
                            action = {
                                "tool": tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", "?"),
                                "args": tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", {}),
                            }
                            # the gate happens here, before LangGraph dispatches the ToolNode
                            verdict = outer.gate(sid, action)
                            outer.append_step(sid, TraceStep(
                                step_idx=0, role=Role.AGENT,
                                thought=thought, action=action,
                            ))
                            if verdict.block:
                                raise PermissionError(
                                    f"TraceGuard STOP: {verdict.risk_type}: {verdict.explanation}"
                                )

            def on_tool_end(self, output, *, run_id, parent_run_id=None, **kw):
                sid = str(parent_run_id or run_id)
                outer.append_step(sid, TraceStep(
                    step_idx=0, role=Role.TOOL,
                    observation=output if isinstance(output, str) else json.dumps(output, default=str),
                ))

            def on_chain_end(self, outputs, *, run_id, **kw):
                outer.end_session(str(run_id))

        # Bind the callback onto the compiled graph's config.
        # Users can pass extra callbacks alongside; we don't replace.
        original_invoke = app.invoke
        original_stream = getattr(app, "stream", None)
        original_ainvoke = getattr(app, "ainvoke", None)

        def _merged_config(config: dict | None) -> dict:
            cfg = dict(config or {})
            cbs = list(cfg.get("callbacks") or [])
            cbs.append(_Cb())
            cfg["callbacks"] = cbs
            return cfg

        def invoke(input, config=None, **kw):
            return original_invoke(input, _merged_config(config), **kw)

        app.invoke = invoke
        if original_stream:
            def stream(input, config=None, **kw):
                return original_stream(input, _merged_config(config), **kw)
            app.stream = stream
        if original_ainvoke:
            async def ainvoke(input, config=None, **kw):
                return await original_ainvoke(input, _merged_config(config), **kw)
            app.ainvoke = ainvoke

        return app
