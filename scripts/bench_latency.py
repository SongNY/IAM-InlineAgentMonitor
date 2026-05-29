#!/usr/bin/env python3
"""Latency benchmark CLI for the IAM model.

Thin wrapper over `agent_iam.eval.bench.run_bench`. Run on a GPU box / Kaggle
after `pip install -e ".[eval]"` (+ optionally `unsloth`):

    python scripts/bench_latency.py --model Sunnyu/IAM-Qwen3.5-2B --accel auto --steps 20 --iters 30

In a notebook with the model already loaded, call the function directly:

    from agent_iam.eval.bench import run_bench
    run_bench(TraceMonitor(model=model, tokenizer=tokenizer))
"""

from __future__ import annotations

import argparse

from agent_iam.detect.online import TraceMonitor
from agent_iam.eval.bench import run_bench


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="Sunnyu/IAM-Qwen3.5-2B")
    ap.add_argument("--accel", default="auto", choices=["auto", "unsloth", "hf"])
    ap.add_argument("--steps", type=int, default=20)
    ap.add_argument("--iters", type=int, default=30)
    args = ap.parse_args(argv)

    print(f"loading {args.model} (accel={args.accel}) ...")
    monitor = TraceMonitor.from_pretrained(args.model, accel=args.accel)
    run_bench(monitor, steps=args.steps, iters=args.iters)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
