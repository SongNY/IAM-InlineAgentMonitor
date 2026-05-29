"""Reusable latency benchmark for a loaded TraceMonitor.

    from agent_iam.eval.bench import run_bench
    run_bench(mon, steps=20, iters=30)   # -> dict of timings, also prints

Measures per-action `check()` latency (uncached, full prefill each call) and
the KV-cached incremental `session()` per-step cost as a trace grows.
"""

from __future__ import annotations

import statistics
import time
from typing import Any

from ..schema import Role, TraceStep, Trajectory


def _pcts(samples_s: list[float]) -> tuple[float, float, float]:
    ms = sorted(x * 1e3 for x in samples_s)

    def p(q: float) -> float:
        return ms[min(len(ms) - 1, int(q * len(ms)))]

    return p(0.50), p(0.90), statistics.mean(ms)


def _trace_of_len(n: int) -> Trajectory:
    steps = [TraceStep(step_idx=0, role=Role.USER, content="do a multi-step task")]
    for i in range(n):
        steps.append(TraceStep(step_idx=0, role=Role.AGENT,
                               action={"tool": "Read", "args": {"path": f"file_{i}.txt"}}))
        steps.append(TraceStep(step_idx=0, role=Role.TOOL, observation=f"contents of file {i} " * 20))
    for i, s in enumerate(steps):
        s.step_idx = i
    return Trajectory(id="bench", task_instruction="do a multi-step task", source="bench", steps=steps)


def run_bench(monitor: Any, *, steps: int = 20, iters: int = 30, verbose: bool = True) -> dict:
    """Benchmark a built monitor. Returns a dict of latency stats (ms)."""
    def log(*a):
        if verbose:
            print(*a)

    action = {"tool": "WebFetch", "args": {"url": "https://x.example/y"}}

    traj = _trace_of_len(steps)
    monitor.check(traj, next_action=action)  # warm up (cuda init / compile / cache write)
    samples = []
    for _ in range(iters):
        t = time.time()
        monitor.check(traj, next_action=action)
        samples.append(time.time() - t)
    p50, p90, mean = _pcts(samples)
    log(f"check() on a {steps}-step trace (uncached, full prefill): "
        f"p50={p50:.0f}ms p90={p90:.0f}ms mean={mean:.0f}ms (n={iters})")

    sess = monitor.session()
    sess.observe(role="user", content="do a multi-step task")
    per_step = []
    for i in range(steps):
        t = time.time()
        sess.guard({"tool": "Read", "args": {"path": f"file_{i}.txt"}})
        per_step.append(time.time() - t)
        sess.commit(action={"tool": "Read", "args": {"path": f"file_{i}.txt"}},
                    observation=f"contents of file {i} " * 20)
    cp50, cp90, cmean = _pcts(per_step)
    log(f"session() incremental, steps 1..{steps} (KV-cache): "
        f"p50={cp50:.0f}ms p90={cp90:.0f}ms mean={cmean:.0f}ms")
    log(f"  first step={per_step[0] * 1e3:.0f}ms  last step={per_step[-1] * 1e3:.0f}ms "
        f"(flat == cache working; rising == falling back to full recompute)")

    return {
        "check_p50_ms": p50, "check_p90_ms": p90, "check_mean_ms": mean,
        "session_p50_ms": cp50, "session_p90_ms": cp90, "session_mean_ms": cmean,
        "session_first_ms": per_step[0] * 1e3, "session_last_ms": per_step[-1] * 1e3,
    }
