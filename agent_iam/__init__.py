"""IAM: self-supervised trace anomaly detection for LLM agents."""

__version__ = "0.1.0a0"

from .defend import guard, protect  # torch-free at import; loads the model on first call
from .runtime.adapters import GenericAdapter, IAMBlocked  # torch-free
from .runtime.stream import StreamingMonitor  # torch-free; safe to import eagerly
from .schema import (
    AnomalyLabel,
    FailureMode,
    HarmCategory,
    RiskSource,
    TraceStep,
    Trajectory,
    Verdict,
)
from .tokenize import TraceTokenizer

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
    "GenericAdapter",
    "IAMBlocked",
    "guard",
    "protect",
    "TraceMonitor",
]


def __getattr__(name: str):
    # Lazy export: the documented quickstart uses
    #   from agent_iam import TraceMonitor
    # but detect.online imports torch at module load. Resolving it lazily
    # via PEP 562 keeps `import agent_iam` light (schema + tokenizer stay
    # usable without torch installed) while still satisfying the public API.
    if name == "TraceMonitor":
        from .detect.online import TraceMonitor
        return TraceMonitor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
