"""Tests for the one-line `agent_iam.guard()` entry point.

The model load is monkeypatched out (a stub monitor), so these run without
torch / a GPU / a downloaded checkpoint — they verify the wiring, not inference.
"""

from __future__ import annotations

import pytest

import agent_iam
from agent_iam import IAMBlocked
from agent_iam.schema import Verdict


class StubMonitor:
    def check(self, traj, next_action):
        blob = f"{next_action.get('tool', '')} {next_action.get('args', {})}".lower()
        if "evil" in blob:
            return Verdict(symbol="STOP", risk_type="data_exfiltration",
                           explanation="blocked", p_stop=0.99)
        return Verdict(symbol="OK", p_stop=0.01)


@pytest.fixture(autouse=True)
def _no_real_model(monkeypatch):
    # Replace the heavy loader with a stub so guard() never touches torch.
    monkeypatch.setattr(agent_iam.defend, "_load_monitor",
                        lambda model, threshold, device: StubMonitor())


def test_guard_dict_registry():
    ran = []
    tools = agent_iam.guard({
        "read": lambda p: ran.append(p) or "ok",
        "evil_post": lambda **kw: ran.append("posted"),
    })
    assert set(tools) == {"read", "evil_post"}
    assert tools["read"]("a.txt") == "ok"
    with pytest.raises(IAMBlocked):
        tools["evil_post"](url="x")
    assert ran == ["a.txt"]            # benign ran; evil tool body never executed


def test_guard_single_callable():
    safe = agent_iam.guard(lambda x: x * 2)
    assert safe(3) == 6


def test_guard_list():
    fns = agent_iam.guard([lambda: "a", lambda: "b"])
    assert [f() for f in fns] == ["a", "b"]


def test_guard_no_tools_returns_adapter():
    from agent_iam import GenericAdapter
    adapter = agent_iam.guard(task_instruction="do safely")
    assert isinstance(adapter, GenericAdapter)


def test_protect_is_alias():
    assert agent_iam.protect is agent_iam.guard
