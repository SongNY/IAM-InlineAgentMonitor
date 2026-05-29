#!/usr/bin/env python3
"""End-to-end walkthrough of the TraceGuard data-generation pipeline.

This script does not generate traces itself (that needs an agent backend, model API
access, and time) — it prints the exact, ordered commands that make up the pipeline so
you can run them step by step. Each command is taken straight from the `scripts/`
entry points; see each script's ``--help`` for the full flag set.

    python examples/generate_data.py            # print the pipeline
    python examples/generate_data.py --run-collect   # also collect existing run dirs

Pipeline overview:

    (0) synthesize_scenarios.py   optional — draft new attack scenarios with a strong model
    (1) generate_traces.py        drive an agent backend through the scenario library
    (2) build_dataset.py          dedupe + leakage-free train/val/test split
    (3) tokenize_dataset.py       render canonical Trajectory -> {input_ids, labels}

External sources (ATBench / Scale AI MRT / Claude Code history) drop into the same
run-dir layout and are passed to build_dataset.py via --include.
"""

from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

PIPELINE = [
    (
        "0. (optional) synthesize new attack scenarios with a strong model",
        [
            "python", "scripts/synthesize_scenarios.py",
            "--category", "shell_injection",
            "--n", "8",
            "--out", "traceguard/data/generate/scenarios/shell_injection_auto.py",
        ],
    ),
    (
        "1. generate labeled traces by driving an agent backend",
        [
            "python", "scripts/generate_traces.py",
            "--out", "runs",
            "--runs-per-scenario", "2",
            "--backend", "claude_code",   # or: openhands | langgraph | openai_react
            "--model", "haiku",
        ],
    ),
    (
        "1b. (optional) pull external sources into the same run-dir layout",
        [
            "python", "scripts/pull_atbench.py", "--out", "runs-atbench/", "--limit", "1000",
        ],
    ),
    (
        "2. build the dataset (dedupe + leakage-free train/val/test split)",
        [
            "python", "scripts/build_dataset.py",
            "--include", "runs", "runs-atbench",
            "--out", "data/v0.1/",
            "--val", "0.15", "--test", "0.15", "--seed", "42",
        ],
    ),
    (
        "3. tokenize each split for the trainer",
        [
            "python", "scripts/tokenize_dataset.py",
            "--in", "data/v0.1/train.jsonl",
            "--out", "data/v0.1/train.tokenized.jsonl",
            "--tokenizer", "Qwen/Qwen3.5-2B",
            "--max-length", "4096",
        ],
    ),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--run-collect",
        action="store_true",
        help="Actually run the (safe, model-free) collect step over an existing runs/ dir.",
    )
    args = ap.parse_args()

    print("TraceGuard data-generation pipeline\n" + "=" * 38)
    for title, cmd in PIPELINE:
        print(f"\n# {title}")
        print("  " + " ".join(shlex.quote(c) for c in cmd))

    print("\n# collect generated run dirs into one JSONL (no model needed):")
    print("  python scripts/generate_traces.py --collect runs --out-jsonl train.jsonl")

    if args.run_collect:
        runs = REPO_ROOT / "runs"
        if not runs.exists():
            print(f"\n[skip] no {runs} directory yet — run step 1 first.", file=sys.stderr)
            return 0
        print(f"\nCollecting {runs} -> train.jsonl ...")
        subprocess.run(
            ["python", "scripts/generate_traces.py", "--collect", "runs", "--out-jsonl", "train.jsonl"],
            cwd=REPO_ROOT,
            check=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
