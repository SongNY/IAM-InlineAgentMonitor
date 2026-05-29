#!/usr/bin/env python3
"""Measure per-action monitor latency on a GPU.

Run after `pip install -e ".[eval]"` (+ optionally `unsloth`). Reports p50/p90
for the one-shot `check()` and for the KV-cached incremental `session()` as a
trace grows — the numbers the README / paper leave as TODO.

    python scripts/bench_latency.py --model Sunnyu/IAM-Qwen3.5-2B --accel auto --steps 20 --iters 30
"""

from __future__ import annotations

import argparse
import statistics
import time

from agent_iam.detect.online import TraceMonitor
from agent_iam.schema import Role, TraceStep, Trajectory


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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="Sunnyu/IAM-Qwen3.5-2B")
    ap.add_argument("--accel", default="auto", choices=["auto", "unsloth", "hf"])
    ap.add_argument("--steps", type=int, default=20, help="trace length for the session benchmark")
    ap.add_argument("--iters", type=int, default=30, help="check() samples")
    args = ap.parse_args(argv)

    print(f"loading {args.model} (accel={args.accel}) ...")
    monitor = TraceMonitor.from_pretrained(args.model, accel=args.accel)
    action = {"tool": "WebFetch", "args": {"url": "https://x.example/y"}}

    # --- one-shot check() at a fixed, mid-size context -------------------
    traj = _trace_of_len(args.steps)
    monitor.check(traj, next_action=action)  # warm up (cuda init / compile / cache write)
    samples = []
    for _ in range(args.iters):
        t = time.time()
        monitor.check(traj, next_action=action)
        samples.append(time.time() - t)
    p50, p90, mean = _pcts(samples)
    print(f"\ncheck() on a {args.steps}-step trace (uncached, full prefill each call):")
    print(f"  p50={p50:.0f}ms  p90={p90:.0f}ms  mean={mean:.0f}ms  (n={args.iters})")

    # --- KV-cached session(): per-step cost as the trace grows -----------
    sess = monitor.session()
    sess.observe(role="user", content="do a multi-step task")
    per_step = []
    for i in range(args.steps):
        t = time.time()
        sess.guard({"tool": "Read", "args": {"path": f"file_{i}.txt"}})
        per_step.append(time.time() - t)
        sess.commit(action={"tool": "Read", "args": {"path": f"file_{i}.txt"}},
                    observation=f"contents of file {i} " * 20)
    cp50, cp90, cmean = _pcts(per_step)
    print(f"\nsession().guard() incremental, step 1..{args.steps} (KV-cache reuse):")
    print(f"  p50={cp50:.0f}ms  p90={cp90:.0f}ms  mean={cmean:.0f}ms")
    print(f"  first step={per_step[0] * 1e3:.0f}ms  last step={per_step[-1] * 1e3:.0f}ms "
          f"(flat == cache working; rising == falling back to full recompute)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
