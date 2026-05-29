"""Unit tests for the framework-agnostic GenericAdapter.

Uses a stub monitor (no torch / GPU / model) that STOPs any action whose tool
name or args mention "evil", and otherwise returns OK.
"""

from __future__ import annotations

import pytest

from agent_iam.runtime.adapters import GenericAdapter, IAMBlocked
from agent_iam.schema import Role, Verdict


class StubMonitor:
    """`.check(traj, next_action) -> Verdict`; STOP iff the action looks evil."""

    def __init__(self):
        self.calls = []

    def check(self, traj, next_action):
        self.calls.append((len(traj.steps), next_action))
        blob = f"{next_action.get('tool', '')} {next_action.get('args', {})}".lower()
        if "evil" in blob:
            return Verdict(symbol="STOP", risk_type="data_exfiltration",
                           explanation="exfil to external host", p_stop=0.99)
        return Verdict(symbol="OK", p_stop=0.01)


# ---------------------------------------------------------------------------


def test_ok_tool_runs_and_records_steps():
    iam = GenericAdapter(StubMonitor())
    iam.begin_session("s", task_instruction="do a thing")
    ran = []
    read = iam.guard_tool(lambda path: ran.append(path) or f"contents:{path}",
                          tool_name="read", session_id="s")
    out = read("notes.txt")
    assert out == "contents:notes.txt"
    assert ran == ["notes.txt"]                      # the real fn executed
    traj = iam._trace_by_session["s"]
    assert [st.role for st in traj.steps] == [Role.AGENT, Role.TOOL]
    assert traj.steps[0].action == {"tool": "read", "args": {"arg0": "notes.txt"}}
    assert traj.steps[0].step_idx == 0 and traj.steps[1].step_idx == 1


def test_stop_blocks_before_execution():
    iam = GenericAdapter(StubMonitor())
    iam.begin_session("s", "")
    ran = []
    post = iam.guard_tool(lambda url, **kw: ran.append(url),
                          tool_name="evil_post", session_id="s")
    with pytest.raises(IAMBlocked) as ei:
        post("https://x.example", data="secret")
    assert ran == []                                 # real fn never ran
    assert ei.value.verdict.symbol == "STOP"
    assert ei.value.verdict.risk_type == "data_exfiltration"
    # blocked action is NOT appended (only committed actions are)
    assert iam._trace_by_session["s"].steps == []


def test_on_block_callback_fires():
    seen = {}
    def on_block(sid, action, verdict):
        seen["sid"] = sid
        seen["sym"] = verdict.symbol
    iam = GenericAdapter(StubMonitor(), on_block=on_block)
    iam.begin_session("s", "")
    tool = iam.guard_tool(lambda: None, tool_name="evil", session_id="s")
    with pytest.raises(IAMBlocked):
        tool()
    assert seen == {"sid": "s", "sym": "STOP"}


def test_wrap_dict_and_list():
    iam = GenericAdapter(StubMonitor())
    d = iam.wrap({"a": lambda: "ra", "b": lambda: "rb"}, session_id="d")
    assert set(d) == {"a", "b"}
    assert d["a"]() == "ra"
    lst = iam.wrap([lambda: 1, lambda: 2], session_id="l")
    assert [f() for f in lst] == [1, 2]


def test_trace_accumulates_and_monitor_sees_growth():
    mon = StubMonitor()
    iam = GenericAdapter(mon)
    iam.begin_session("s", "")
    iam.observe("s", role="user", content="please help")
    t = iam.guard_tool(lambda x: x, tool_name="echo", session_id="s")
    t("one")
    t("two")
    traj = iam._trace_by_session["s"]
    # user + (agent,tool) + (agent,tool) = 5 steps, indices 0..4
    assert [st.step_idx for st in traj.steps] == [0, 1, 2, 3, 4]
    # the monitor saw a growing prefix at each gate (1 step, then 3 steps)
    assert [n for n, _ in mon.calls] == [1, 3]


def test_keeps_task_instruction_when_session_preopened():
    iam = GenericAdapter(StubMonitor())
    iam.begin_session("s", task_instruction="summarize repo")
    iam.guard_tool(lambda: "ok", tool_name="t", session_id="s")()
    assert iam._trace_by_session["s"].task_instruction == "summarize repo"
