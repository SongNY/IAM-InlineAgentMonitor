"""Optional pre-filter: skip the monitor call for clearly low-risk actions.

Gating read-only / allowlisted tools saves latency and tokens. The rule is
deliberately conservative — when in doubt, send the step to the monitor.
"""

from __future__ import annotations

from collections.abc import Callable

from .types import Trace

# Common read-only / side-effect-free tool names. Extend per deployment.
DEFAULT_READONLY_TOOLS = frozenset(
    {
        "read", "read_file", "cat", "view", "open",
        "glob", "grep", "search", "find", "ls", "list",
        "get", "fetch_local", "stat",
    }
)


class Gate:
    """Decide whether a trace needs monitoring.

    `should_monitor(trace) -> bool`. Returns False (skip) only for actions that
    are confidently safe: an allowlisted read-only tool with no network egress.
    Everything else — unknown tools, anything that writes, executes, or reaches
    the network — goes to the monitor.
    """

    def __init__(
        self,
        readonly_tools: frozenset[str] | set[str] = DEFAULT_READONLY_TOOLS,
        custom: Callable[[Trace], bool] | None = None,
    ):
        self.readonly_tools = frozenset(t.lower() for t in readonly_tools)
        self.custom = custom  # custom(trace) -> True means "must monitor"

    def should_monitor(self, trace: Trace) -> bool:
        if self.custom is not None:
            try:
                if self.custom(trace):
                    return True
            except Exception:
                return True  # a broken gate must not silently skip monitoring
        tool = (trace.tool or "").lower()
        if not tool:
            return True  # unknown / unspecified tool — monitor it
        if tool in self.readonly_tools:
            return False  # confidently safe → skip the call
        return True
