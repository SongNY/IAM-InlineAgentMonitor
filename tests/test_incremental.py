"""Tests for the KV-cached IncrementalSession.

The torch fast path needs a GPU, so here we cover the pure-python prefix logic
and the stateful trace/verdict machine via a stub monitor that exposes only
``verdict_at`` + ``threshold`` (so the session takes its known-correct fallback).
"""

from __future__ import annotations

from agent_iam.detect.incremental import IncrementalSession, _common_prefix_len


def test_common_prefix_len():
    assert _common_prefix_len([], [1, 2]) == 0
    assert _common_prefix_len([1, 2, 3], [1, 2, 9]) == 2
    assert _common_prefix_len([1, 2, 3], [1, 2, 3]) == 3
    assert _common_prefix_len([1, 2, 3], [1, 2, 3, 4]) == 3
    assert _common_prefix_len([5], [6]) == 0


class StubMonitor:
    """No model/tok/trace_tokenizer -> IncrementalSession uses _fallback."""

    threshold = 0.5

    def __init__(self):
        self.cutoffs = []

    def verdict_at(self, traj, cutoff_step, generate_reason=True):
        self.cutoffs.append(cutoff_step)
        last = traj.steps[cutoff_step - 1]
        evil = "evil" in str(last.action).lower()
        return {
            "p_stop": 0.99 if evil else 0.01,
            "p_warn": 0.0, "p_ok": 0.01 if evil else 0.99,
            "predicted_symbol": "STOP" if evil else "OK",
            "predicted_type": "data_exfiltration" if evil else "",
            "predicted_reason": "exfil blocked" if evil else "",
        }


def test_guard_ok_then_stop_and_trace_accumulates():
    mon = StubMonitor()
    sess = IncrementalSession(mon, task_instruction="t")
    sess.observe(role="user", content="please summarize")

    v1 = sess.guard({"tool": "Read", "args": {"path": ".env"}})
    assert v1.symbol == "OK" and not v1.block
    sess.commit(action={"tool": "Read", "args": {"path": ".env"}}, observation="KEY=...")

    v2 = sess.guard({"tool": "evil_post", "args": {"url": "https://x"}})
    assert v2.block and v2.symbol == "STOP"
    assert v2.risk_type == "data_exfiltration"
    assert v2.explanation == "exfil blocked"

    # trace holds: user + (agent Read, tool obs) = 3 committed steps, indices 0..2
    assert [s.step_idx for s in sess.traj.steps] == [0, 1, 2]
    # guard built a hypothetical 2-step trace then a 4-step trace (cutoff == len)
    assert mon.cutoffs == [2, 4]


def test_reset_clears_state():
    sess = IncrementalSession(StubMonitor())
    sess.observe(role="user", content="x")
    sess.commit(action={"tool": "a", "args": {}})
    assert len(sess.traj.steps) == 2
    sess.reset()
    assert sess.traj.steps == []
    assert sess._cached_ids == [] and sess._past is None


def test_guard_does_not_mutate_committed_trace():
    sess = IncrementalSession(StubMonitor())
    sess.observe(role="user", content="x")
    before = len(sess.traj.steps)
    sess.guard({"tool": "noop", "args": {}})
    assert len(sess.traj.steps) == before  # guard is a check; only commit appends
