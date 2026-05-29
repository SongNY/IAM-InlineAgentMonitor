"""TraceGuard attack-trace generation pipeline.

Public API:

    from traceguard.data.generate import ALL_SCENARIOS, run_all
    run_all(ALL_SCENARIOS, out_dir=Path("./runs"))
"""

from .runner import RunResult, run_all, run_scenario
from .scenario import (
    BaitFile,
    MockHTTPResponse,
    MockTool,
    Scenario,
    ScenarioCategory,
    ToolPredicate,
    ViolationPattern,
)
from .scenarios import ALL_SCENARIOS

__all__ = [
    "ALL_SCENARIOS",
    "BaitFile",
    "MockHTTPResponse",
    "MockTool",
    "RunResult",
    "Scenario",
    "ScenarioCategory",
    "ToolPredicate",
    "ViolationPattern",
    "run_all",
    "run_scenario",
]
