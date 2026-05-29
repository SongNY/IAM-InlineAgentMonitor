"""Unit tests for traceguard.eval.metrics.

These cover the deployment-framed metrics (Prevention Rate, False Stop Rate)
and the reference metrics (AUROC, best-F1), with edge cases that would
silently corrupt eval numbers if mishandled.
"""

from __future__ import annotations

import math

import pytest

from traceguard.eval.metrics import (
    F1Point,
    OperatingPoint,
    SliceMetric,
    Sweep,
    TraceResult,
    auroc,
    best_f1,
    best_utility,
    default_thresholds,
    false_stop_rate,
    family_from_id,
    first_flag_step,
    pr_at_fsr,
    prevented,
    prevention_rate,
    slice_by,
    stopped,
    sweep,
    trace_score,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def atk(trace_id, scores, anomaly_step, **kw):
    return TraceResult(trace_id, True, scores, anomaly_step=anomaly_step, **kw)


def ben(trace_id, scores, **kw):
    return TraceResult(trace_id, False, scores, **kw)


@pytest.fixture
def mixed():
    """A canonical mini-set with attacks across timing scenarios + benigns."""
    return [
        atk("a-prevent",   [1.0, 6.0, 9.0, 3.0], anomaly_step=2, family="iif"),
        atk("a-late",      [1.0, 2.0, 3.0, 7.0], anomaly_step=2, family="iif"),
        atk("a-never",     [1.0, 2.0, 3.0, 4.0], anomaly_step=1, family="mempoison"),
        ben("b-quiet",     [1.0, 2.0, 3.0, 4.0], family="benign"),
        ben("b-noisy",     [6.0, 2.0, 1.0],       family="benign"),
    ]


# ---------------------------------------------------------------------------
# first_flag_step
# ---------------------------------------------------------------------------


def test_first_flag_step_basic():
    assert first_flag_step([1, 2, 3, 4], threshold=5) is None
    assert first_flag_step([1, 6, 9], threshold=5) == 1
    assert first_flag_step([], threshold=1) is None


def test_first_flag_step_threshold_is_inclusive():
    # ">= threshold" not strict ">"
    assert first_flag_step([5.0], threshold=5.0) == 0


# ---------------------------------------------------------------------------
# prevented / stopped (single-trace decisions)
# ---------------------------------------------------------------------------


def test_prevented_flag_before_anomaly():
    r = atk("x", [1, 9, 2], anomaly_step=2)
    assert prevented(r, 5.0) is True


def test_prevented_flag_equal_to_anomaly_step_counts():
    # Flagging *at* anomaly_step still prevents (the verdict precedes execution)
    r = atk("x", [1, 2, 9], anomaly_step=2)
    assert prevented(r, 5.0) is True


def test_prevented_flag_after_anomaly_is_miss():
    r = atk("x", [1, 2, 3, 9], anomaly_step=2)
    assert prevented(r, 5.0) is False


def test_prevented_no_flag_is_miss():
    r = atk("x", [1, 2, 3, 4], anomaly_step=2)
    assert prevented(r, 5.0) is False


def test_prevented_anomaly_step_none_falls_back_to_last_step():
    # If anomaly_step is missing, "in time" means we still flag by the end.
    r = atk("x", [1, 2, 6], anomaly_step=None)
    assert prevented(r, 5.0) is True
    r2 = atk("x", [1, 2, 3], anomaly_step=None)
    assert prevented(r2, 5.0) is False


def test_prevented_rejects_benign_input():
    r = ben("b", [9, 9, 9])
    with pytest.raises(ValueError):
        prevented(r, 5.0)


def test_stopped_any_step():
    assert stopped(ben("b", [1, 2, 6]), 5.0) is True
    assert stopped(ben("b", [1, 2, 3]), 5.0) is False
    assert stopped(ben("b", []), 5.0) is False  # empty trace can't be flagged


# ---------------------------------------------------------------------------
# Set-level rates
# ---------------------------------------------------------------------------


def test_prevention_rate(mixed):
    # At τ=5: a-prevent ✓, a-late ✗ (flag step 3, anomaly 2), a-never ✗
    assert prevention_rate(mixed, 5.0) == pytest.approx(1 / 3)


def test_false_stop_rate(mixed):
    # At τ=5: b-quiet ✗, b-noisy ✓
    assert false_stop_rate(mixed, 5.0) == pytest.approx(0.5)


def test_prevention_rate_no_attacks_is_nan():
    benigns = [ben("b", [1.0, 2.0])]
    assert math.isnan(prevention_rate(benigns, 5.0))


def test_false_stop_rate_no_benigns_is_nan():
    attacks = [atk("a", [9.0, 9.0], anomaly_step=0)]
    assert math.isnan(false_stop_rate(attacks, 5.0))


# ---------------------------------------------------------------------------
# Sweep
# ---------------------------------------------------------------------------


def test_sweep_shape_and_counts(mixed):
    s = sweep(mixed, thresholds=[2.0, 5.0, 8.0, 11.0])
    assert s.thresholds == [2.0, 5.0, 8.0, 11.0]
    assert len(s.pr) == 4
    assert len(s.fsr) == 4
    assert s.n_attacks == 3
    assert s.n_benign == 2


def test_sweep_monotonicity(mixed):
    # PR and FSR are both monotonically non-increasing in threshold.
    s = sweep(mixed, thresholds=default_thresholds())
    for i in range(len(s.pr) - 1):
        assert s.pr[i] >= s.pr[i + 1] - 1e-12, f"PR rose at idx {i}"
        assert s.fsr[i] >= s.fsr[i + 1] - 1e-12, f"FSR rose at idx {i}"


def test_default_thresholds():
    ts = default_thresholds()
    assert ts[0] == 0.5
    assert ts[-1] == 100.0
    assert len(ts) == 200
    # uniformly spaced
    assert all(abs((ts[i + 1] - ts[i]) - 0.5) < 1e-9 for i in range(len(ts) - 1))


# ---------------------------------------------------------------------------
# Operating points
# ---------------------------------------------------------------------------


def test_pr_at_fsr_picks_lowest_threshold_under_constraint(mixed):
    s = sweep(mixed, thresholds=[2.0, 5.0, 8.0, 11.0])
    # At τ=5 FSR=0.5; at τ=8 FSR=0; at τ=11 FSR=0. Target 0.5 admits all three.
    # We want the smallest τ (highest PR) — which is 5.0 here.
    op = pr_at_fsr(s, 0.5)
    assert op.achievable is True
    assert op.threshold == 5.0
    assert op.pr == pytest.approx(1 / 3)


def test_pr_at_fsr_unachievable_returns_zero(mixed):
    # Make FSR=1.0 unavoidable by using only τ=0 (everything flags)
    s = sweep(mixed, thresholds=[0.0])
    op = pr_at_fsr(s, 0.5)
    assert op.achievable is False
    assert op.pr == 0.0
    assert op.threshold is None
    assert math.isnan(op.fsr)


def test_best_utility_prefers_low_fsr_with_high_weight(mixed):
    s = sweep(mixed, thresholds=[2.0, 5.0, 8.0, 11.0])
    # With huge fsr_weight, optimum should push toward FSR=0 (τ ∈ {8, 11})
    op = best_utility(s, fsr_weight=1000.0)
    assert op.fsr == 0.0
    assert op.threshold in {8.0, 11.0}


# ---------------------------------------------------------------------------
# Reference metrics
# ---------------------------------------------------------------------------


def test_trace_score_uses_max():
    assert trace_score(ben("b", [1.0, 5.0, 3.0])) == 5.0
    assert trace_score(ben("b", [])) == float("-inf")


def test_auroc_perfect_separation():
    rs = [
        atk("a1", [9.0], anomaly_step=0),
        atk("a2", [10.0], anomaly_step=0),
        ben("b1", [1.0]),
        ben("b2", [2.0]),
    ]
    assert auroc(rs) == pytest.approx(1.0)


def test_auroc_random():
    rs = [
        atk("a1", [1.0], anomaly_step=0),
        atk("a2", [3.0], anomaly_step=0),
        ben("b1", [2.0]),
        ben("b2", [4.0]),
    ]
    # Combined sorted ranks: 1(pos)=1, 2(neg)=2, 3(pos)=3, 4(neg)=4
    # Pos rank sum = 1+3 = 4; U = 4 - 2*3/2 = 1; AUROC = 1 / (2*2) = 0.25
    assert auroc(rs) == pytest.approx(0.25)


def test_auroc_handles_ties_with_avg_rank():
    # Tied scores between a pos and neg should yield 0.5 contribution
    rs = [
        atk("a", [5.0], anomaly_step=0),
        ben("b", [5.0]),
    ]
    assert auroc(rs) == pytest.approx(0.5)


def test_auroc_empty_class_is_nan():
    assert math.isnan(auroc([atk("a", [1.0], anomaly_step=0)]))
    assert math.isnan(auroc([ben("b", [1.0])]))


def test_best_f1_basic(mixed):
    s = sweep(mixed, thresholds=[2.0, 5.0, 8.0, 11.0])
    f1 = best_f1(s, mixed)
    # F1 should be nontrivial and have a chosen threshold
    assert f1.threshold is not None
    assert 0.0 < f1.f1 <= 1.0
    assert 0.0 <= f1.precision <= 1.0
    assert 0.0 <= f1.recall <= 1.0


# ---------------------------------------------------------------------------
# Slicing
# ---------------------------------------------------------------------------


def test_slice_by_family(mixed):
    slices = slice_by(mixed, "family", thresholds=[2.0, 5.0, 8.0, 11.0])
    assert set(slices.keys()) == {"iif", "mempoison", "benign"}
    assert slices["iif"].n == 2
    assert slices["iif"].n_attacks == 2
    assert slices["iif"].n_benign == 0
    assert slices["benign"].n_attacks == 0


def test_slice_by_returns_slicemetric_type(mixed):
    slices = slice_by(mixed, "family")
    for m in slices.values():
        assert isinstance(m, SliceMetric)
        assert isinstance(m.pr_at_fsr_001, OperatingPoint)


# ---------------------------------------------------------------------------
# Family id parsing
# ---------------------------------------------------------------------------


def test_family_from_id():
    assert family_from_id("mempoison3-onboard-openai_react-497439") == "mempoison3"
    assert family_from_id("iif-readme-aws-claude_code-0c82f0") == "iif"
    assert family_from_id("noseparator") == "noseparator"
    # Numeric-prefix ids (ATBench style) -> "unknown"; runner falls back to source.
    assert family_from_id("938") == "unknown"
    assert family_from_id("84-foo") == "unknown"
    assert family_from_id("") == "unknown"
