"""Unified CLI for the eval pipeline.

Two subcommands:

  score   --scorer {monitor,keyword,untrained_lm} \\
          --model <path-if-monitor-or-untrained_lm> \\
          --data <test.jsonl> \\
          --out runs-eval/<name>/scores.jsonl
          [--threshold 8.0] [--limit N]

  report  <scores.jsonl> [<scores.jsonl> ...] \\
          --out runs-eval/report/
          [--slice-keys family source harm_category]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .baselines import keyword_scorer, untrained_lm_scorer
from .report import build_report
from .runner import monitor_scorer, run_split


def _cmd_score(args: argparse.Namespace) -> int:
    if args.scorer == "keyword":
        scorer = keyword_scorer()
    elif args.scorer == "untrained_lm":
        if not args.model:
            print("--scorer untrained_lm requires --model", file=sys.stderr)
            return 2
        scorer = untrained_lm_scorer(args.model, threshold=args.threshold)
    elif args.scorer == "monitor":
        if not args.model:
            print("--scorer monitor requires --model", file=sys.stderr)
            return 2
        from ..detect.online import TraceMonitor
        print(f"Loading TraceMonitor from {args.model}...", file=sys.stderr)
        monitor = TraceMonitor.from_pretrained(args.model, threshold=args.threshold)
        scorer = monitor_scorer(monitor)
    else:
        print(f"unknown scorer: {args.scorer}", file=sys.stderr)
        return 2

    summary = run_split(scorer, args.data, args.out, limit=args.limit)
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    summary = build_report(
        args.scores,
        out_dir=args.out,
        slice_keys=args.slice_keys,
        names=args.names,
    )
    print(json.dumps(summary, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agent_iam.eval", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("score", help="Score a test split with one scorer.")
    sp.add_argument("--scorer", required=True, choices=["monitor", "keyword", "untrained_lm"])
    sp.add_argument("--model", default=None, help="HF model id / local path (monitor + untrained_lm).")
    sp.add_argument("--data", required=True, help="Path to test.jsonl.")
    sp.add_argument("--out", required=True, help="Output scores.jsonl path.")
    sp.add_argument("--threshold", type=float, default=8.0)
    sp.add_argument("--limit", type=int, default=None)
    sp.set_defaults(func=_cmd_score)

    rp = sub.add_parser("report", help="Render report from one or more scores.jsonl files.")
    rp.add_argument("scores", nargs="+", help="scores.jsonl files (one per scorer).")
    rp.add_argument("--out", required=True, help="Output directory for report.md / slices.csv / pr_fsr.png.")
    rp.add_argument("--slice-keys", nargs="+", default=["family", "source", "harm_category"])
    rp.add_argument("--names", nargs="+", default=None, help="Display name for each scores file (same order).")
    rp.set_defaults(func=_cmd_report)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
