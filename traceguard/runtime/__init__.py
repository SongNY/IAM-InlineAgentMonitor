"""Runtime: drive TraceGuard against a live agent.

  - `StreamingMonitor` — stateful per-session wrapper that holds the running
    trace and gates proposed actions step by step (`runtime.stream`).
  - `adapters`          — framework-specific hooks (LangGraph, Claude Code, ...).

`StreamingMonitor` only needs `..schema` (no torch), so importing it here keeps
`import traceguard.runtime` light.
"""

from .stream import StreamingMonitor

__all__ = ["StreamingMonitor"]
