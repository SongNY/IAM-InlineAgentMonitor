"""TraceGuard: self-supervised trace anomaly detection for LLM agents."""

__version__ = "0.1.0a0"

from .schema import (
    TraceStep,
    Trajectory,
    AnomalyLabel,
    RiskSource,
    FailureMode,
    HarmCategory,
    Verdict,
)
from .tokenize import TraceTokenizer
from .runtime.stream import StreamingMonitor  # torch-free; safe to import eagerly

__all__ = [
    "TraceStep",
    "Trajectory",
    "AnomalyLabel",
    "RiskSource",
    "FailureMode",
    "HarmCategory",
    "Verdict",
    "TraceTokenizer",
    "StreamingMonitor",
    "TraceMonitor",
]


def __getattr__(name: str):
    # Lazy export: the documented quickstart uses
    #   from traceguard import TraceMonitor
    # but detect.online imports torch at module load. Resolving it lazily
    # via PEP 562 keeps `import traceguard` light (schema + tokenizer stay
    # usable without torch installed) while still satisfying the public API.
    if name == "TraceMonitor":
        from .detect.online import TraceMonitor
        return TraceMonitor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
