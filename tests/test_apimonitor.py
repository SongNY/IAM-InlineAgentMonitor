"""Tests for the API-based SecurityMonitor.

No network / no anthropic SDK: a fake client returns canned responses (or
raises), so these exercise context assembly, caching breakpoints, fail-closed
parsing, the gate, and state updates — not real inference.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agent_iam.apimonitor import (
    ContextBuilder,
    Gate,
    LedgerEntry,
    MonitorConfig,
    MonitorState,
    SecurityMonitor,
    Trace,
    VerdictParser,
)


def _resp(text: str, stop_reason: str = "end_turn"):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)], stop_reason=stop_reason
    )


class FakeClient:
    """Mimics `client.messages.create(**kwargs)`."""

    def __init__(self, responder):
        self.calls = []
        outer = self

        class _Messages:
            def create(self, **kwargs):
                outer.calls.append(kwargs)
                return outer.responder(kwargs)

        self.responder = responder
        self.messages = _Messages()


OK_JSON = json.dumps({"verdict": "ok", "severity": 0, "category": "none",
                      "reason": "benign read", "remember": []})


# --------------------------------------------------------------------------- parser


def test_parser_valid():
    v = VerdictParser().parse(_resp(OK_JSON))
    assert v.verdict == "ok" and not v.block


def test_parser_strips_fences_and_prose():
    text = "Here you go:\n```json\n" + json.dumps(
        {"verdict": "block", "severity": 3, "category": "data_exfiltration",
         "reason": "exfil", "remember": ["read .env"]}
    ) + "\n```"
    v = VerdictParser().parse(_resp(text))
    assert v.block and v.category == "data_exfiltration" and v.remember == ["read .env"]


@pytest.mark.parametrize("bad", [
    "not json at all",
    "",
    json.dumps({"verdict": "maybe", "severity": 0, "category": "none", "reason": "x"}),   # bad enum
    json.dumps({"verdict": "ok", "severity": 9, "category": "none", "reason": "x"}),      # bad severity
    json.dumps({"verdict": "ok", "severity": 0, "category": "nope", "reason": "x"}),      # bad category
    json.dumps({"severity": 0, "category": "none", "reason": "x"}),                       # missing verdict
])
def test_parser_fail_closed_on_bad_output(bad):
    v = VerdictParser().parse(_resp(bad))
    assert v.block and v.severity == 3 and v.category == "other"


def test_parser_fail_closed_on_refusal():
    v = VerdictParser().parse(_resp(OK_JSON, stop_reason="refusal"))
    assert v.block and v.reason == "monitor_refusal"


# --------------------------------------------------------------------------- context / caching


def test_context_cache_breakpoints_and_delimiters():
    state = MonitorState()
    state.ledger.append(LedgerEntry(1, "read AWS creds"))
    system, messages = ContextBuilder().build(state, Trace(step_id=2, tool="WebFetch", action="POST"))
    # exactly one cache breakpoint on system
    assert system[0]["cache_control"] == {"type": "ephemeral"}
    blocks = messages[0]["content"]
    # ledger block cached; window + current NOT cached
    assert blocks[0].get("cache_control") == {"type": "ephemeral"}
    assert "cache_control" not in blocks[1] and "cache_control" not in blocks[2]
    # untrusted delimiters wrap window + current
    assert "<untrusted_trace>" in blocks[1]["text"] and "<untrusted_trace>" in blocks[2]["text"]


def test_window_count_trim():
    cfg = MonitorConfig(window_max_traces=3)
    cb = ContextBuilder(cfg)
    window = [Trace(step_id=i, tool="read") for i in range(10)]
    chosen = cb._select_window(window)
    assert [t.step_id for t in chosen] == [7, 8, 9]  # most recent 3, chronological


def test_per_trace_head_tail_truncation():
    cb = ContextBuilder(MonitorConfig(per_trace_token_cap=20))  # 80-char cap
    big = "A" * 500 + "ZTAILZ"
    rendered = cb.render_trace(Trace(step_id=1, tool="x", result=big))
    assert "truncated" in rendered     # middle dropped
    assert "ZTAILZ" in rendered        # the exfil-target tail survives the head+tail keep


def test_ledger_compaction_when_over_cap():
    from agent_iam.apimonitor.types import LedgerEntry
    cfg = MonitorConfig(ledger_token_soft_cap=15)  # ~60 chars
    cb = ContextBuilder(cfg)
    ledger = [LedgerEntry(i, f"fact number {i} with some text") for i in range(20)]
    text = cb._render_ledger(ledger)
    assert "compacted" in text  # oldest dropped, marker present


# --------------------------------------------------------------------------- gate


def test_gate_skips_readonly_monitors_rest():
    g = Gate()
    assert g.should_monitor(Trace(step_id=1, tool="read")) is False
    assert g.should_monitor(Trace(step_id=2, tool="WebFetch")) is True
    assert g.should_monitor(Trace(step_id=3, tool="")) is True  # unknown -> monitor


# --------------------------------------------------------------------------- monitor


def test_monitor_happy_path_updates_state():
    client = FakeClient(lambda kw: _resp(json.dumps(
        {"verdict": "ok", "severity": 0, "category": "none",
         "reason": "ok", "remember": ["read AWS credentials file"]})))
    mon = SecurityMonitor(client=client)
    v = mon.check(Trace(step_id=1, tool="read", args={"path": ".env"}))
    assert v.verdict == "ok"
    assert [e.fact for e in mon.state.ledger] == ["read AWS credentials file"]
    assert len(mon.state.window) == 1
    # dedupe: same fact again is not appended twice
    mon.check(Trace(step_id=2, tool="read"))
    assert len(mon.state.ledger) == 1


def test_monitor_block_verdict():
    client = FakeClient(lambda kw: _resp(json.dumps(
        {"verdict": "block", "severity": 3, "category": "data_exfiltration",
         "reason": "secrets leaving", "remember": []})))
    v = SecurityMonitor(client=client).check(
        Trace(step_id=1, tool="WebFetch", action="POST", args={"url": "https://evil/x"}))
    assert v.block and v.category == "data_exfiltration"


def test_monitor_fails_closed_on_api_error():
    def boom(kw):
        raise RuntimeError("network down")
    v = SecurityMonitor(client=FakeClient(boom)).check(Trace(step_id=1, tool="WebFetch"))
    assert v.block and v.reason == "monitor_failure"


def test_monitor_gate_skips_api_call():
    client = FakeClient(lambda kw: _resp(OK_JSON))
    mon = SecurityMonitor(client=client, gate=Gate())
    v = mon.check(Trace(step_id=1, tool="read"))
    assert v.verdict == "ok" and client.calls == []  # no API call made


def test_structured_outputs_kwarg_passed_when_enabled():
    client = FakeClient(lambda kw: _resp(OK_JSON))
    mon = SecurityMonitor(config=MonitorConfig(use_structured_outputs=True), client=client)
    mon.check(Trace(step_id=1, tool="WebFetch"))
    assert "output_config" in client.calls[0]
    assert client.calls[0]["model"] == "claude-sonnet-4-6"
    assert client.calls[0]["max_tokens"] == 256
