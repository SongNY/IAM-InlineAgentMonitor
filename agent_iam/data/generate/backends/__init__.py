"""Collection backends: read a framework's trace logs and convert to
IAM's canonical `Trajectory` schema. Used during training-data
generation. See `base.py` for the interface.

Available (1.x scope):
  - claude_code  — claude -p --output-format stream-json
  - openhands    — workspace/events/*.json

Planned (TODO stubs):
  - langgraph    — LangSmith export or app.stream() events
  - autogen      — agent.chat_messages
  - crewai       — crew.usage_metrics + task outputs
  - hermes       — Hermes event log
  - generic_react — for any model + a minimal Python ReAct loop you provide
"""

from .base import AgentBackend, RunSpec


def get_backend(name: str) -> AgentBackend:
    if name == "claude_code":
        from .claude_code import ClaudeCodeBackend
        return ClaudeCodeBackend()
    if name == "openhands":
        from .openhands import OpenHandsBackend
        return OpenHandsBackend()
    if name == "langgraph":
        from .langgraph import LangGraphBackend
        return LangGraphBackend()
    if name == "openai_react":
        from .openai_react import OpenAIReActBackend
        return OpenAIReActBackend()
    raise ValueError(f"unknown collection backend: {name!r}")


__all__ = ["AgentBackend", "RunSpec", "get_backend"]
