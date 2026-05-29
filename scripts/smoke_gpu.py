#!/usr/bin/env python3
"""GPU smoke-test CLI for the published IAM model.

Thin wrapper over `agent_iam.eval.smoke.run_smoke`. Run on a GPU box / Kaggle
after `pip install -e ".[eval]"` (+ optionally `unsloth`):

    python scripts/smoke_gpu.py --model Sunnyu/IAM-Qwen3.5-2B --accel auto

In a notebook where the model is already in memory, skip this and call the
function directly:

    from agent_iam.detect.online import TraceMonitor
    from agent_iam.eval.smoke import run_smoke
    run_smoke(TraceMonitor(model=model, tokenizer=tokenizer))

Exit code 0 = all checks passed.
"""

from __future__ import annotations

import argparse

from agent_iam.detect.online import TraceMonitor
from agent_iam.eval.smoke import run_smoke


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", default="Sunnyu/IAM-Qwen3.5-2B")
    ap.add_argument("--accel", default="auto", choices=["auto", "unsloth", "hf"])
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--tol", type=float, default=0.05, help="max |p_stop| gap cached-vs-uncached")
    args = ap.parse_args(argv)

    print(f"loading {args.model} (accel={args.accel}) ...")
    monitor = TraceMonitor.from_pretrained(args.model, accel=args.accel, threshold=args.threshold)
    print(f"loaded  device={monitor.device}  model={type(monitor.model).__name__}\n")
    return 0 if run_smoke(monitor, tol=args.tol) else 1


if __name__ == "__main__":
    raise SystemExit(main())
