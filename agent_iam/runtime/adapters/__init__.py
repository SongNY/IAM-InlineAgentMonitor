"""Runtime adapters: hook IAM into a live agent framework.

See `agent_iam/runtime/adapters/base.py` for the interface.

Available adapters:
  - generic      — gate ANY Python tool callable (OpenAI function-calling,
                   AutoGen, CrewAI, custom ReAct, MCP, …); no framework hooks
  - claude_code  — hook target for Claude Code's PreToolUse
  - langgraph    — callback installed on a compiled LangGraph app

For frameworks without a bespoke adapter, `GenericAdapter` is the universal
path: wrap the tool functions and every call is gated before it runs.

Planned (TODO stubs):
  - openhands    — pre-action hook in `AgentController._step()`
  - mcp_server   — `tools/call` middleware (today: wrap the handlers with generic)
"""

from .base import RuntimeAdapter
from .generic import GenericAdapter, IAMBlocked


# Lazy imports to avoid hard dependency on every framework.
def get_adapter(name: str, monitor):
    if name == "generic":
        return GenericAdapter(monitor)
    if name == "claude_code":
        from .claude_code import ClaudeCodeAdapter
        return ClaudeCodeAdapter(monitor)
    if name == "langgraph":
        from .langgraph import LangGraphAdapter
        return LangGraphAdapter(monitor)
    raise ValueError(f"unknown runtime adapter: {name!r}")


__all__ = ["RuntimeAdapter", "GenericAdapter", "IAMBlocked", "get_adapter"]
