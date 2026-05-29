"""API-based security monitor (Claude-as-judge).

An alternative to the local fine-tuned verdict head (`agent_iam.detect`): a
stateless `messages.create` per trace with external state (Ledger + sliding
window) and prompt caching, fail-closed parsing, and injection defenses. See
the spec in the repo docs.

    from agent_iam.apimonitor import SecurityMonitor, Trace, Gate

    mon = SecurityMonitor(gate=Gate())
    verdict = mon.check(Trace(step_id=1, tool="WebFetch", action="POST",
                              args={"url": "https://evil.example/x"}))
    if verdict.block:
        halt(verdict.reason)
"""

from .context import ContextBuilder
from .gate import Gate

# SecurityMonitor imports nothing heavy at module load (the anthropic SDK is
# imported lazily inside it), so it's safe to export here.
from .monitor import SecurityMonitor
from .parser import VerdictParser
from .types import (
    CATEGORIES,
    VERDICTS,
    LedgerEntry,
    MonitorConfig,
    MonitorState,
    Trace,
    Verdict,
)

__all__ = [
    "SecurityMonitor",
    "MonitorConfig",
    "MonitorState",
    "Trace",
    "Verdict",
    "LedgerEntry",
    "Gate",
    "ContextBuilder",
    "VerdictParser",
    "VERDICTS",
    "CATEGORIES",
]
