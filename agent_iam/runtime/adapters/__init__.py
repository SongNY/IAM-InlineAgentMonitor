"""Runtime adapters: hook IAM into a live agent framework.

See `agent_iam/runtime/adapters/base.py` for the interface.

Available adapters (1.x scope):
  - claude_code  — hook target for Claude Code's PreToolUse
  - langgraph    — callback installed on a compiled LangGraph app

Planned (TODO stubs):
  - openhands    — pre-action hook in `AgentController._step()`
  - autogen      — `register_reply` interceptor
  - crewai       — `before_task_kickoff` hook
  - hermes       — `on_action` middleware
  - mcp_server   — `tools/call` middleware
"""

from .base import RuntimeAdapter

# Lazy imports to avoid hard dependency on every framework.
def get_adapter(name: str, monitor):
    if name == "claude_code":
        from .claude_code import ClaudeCodeAdapter
        return ClaudeCodeAdapter(monitor)
    if name == "langgraph":
        from .langgraph import LangGraphAdapter
        return LangGraphAdapter(monitor)
    raise ValueError(f"unknown runtime adapter: {name!r}")


__all__ = ["RuntimeAdapter", "get_adapter"]
