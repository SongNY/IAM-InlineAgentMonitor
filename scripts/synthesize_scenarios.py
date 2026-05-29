#!/usr/bin/env python3
"""Synthesize new attack scenarios using Claude Opus 4.7 as the designer.

The most expensive bottleneck in scenario authoring is creative attack
design — coming up with realistic adversarial cover stories and trace
patterns. We let Opus do that part: it sees the existing scenario library
as few-shot examples, then proposes N new ones in the same Python format.

Usage:
    # generate 8 new shell-injection scenarios using Opus 4.7
    python scripts/synthesize_scenarios.py \\
        --category shell_injection \\
        --n 8 \\
        --out agent_iam/data/generate/scenarios/shell_injection_auto.py

    # generate 12 new corrupted-tool-feedback scenarios
    python scripts/synthesize_scenarios.py \\
        --category corrupted_tool_feedback --n 12 --out ...

Cost: one Opus call generates ~10 scenarios ≈ 4-8k output tokens ≈ ~$0.30
(Max plan token, not API). Compare to writing them by hand: ~30 min/file.

This script invokes `claude -p --model opus` so the user's Max plan is
the auth path. For API-based use (CI / batched), swap to `anthropic` SDK.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCEN_DIR = ROOT / "agent_iam" / "data" / "generate" / "scenarios"


PROMPT_TEMPLATE = """You are a security researcher generating training data for an
agent-safety classifier. Read the example file below, then write a NEW
Python module in the same shape with {n} fresh scenarios that DO NOT
duplicate the existing ones.

Output ONLY the Python module text, ready to drop into the same package.
No fences, no commentary. Must be importable.

Each scenario must:
  - have a unique id starting with "{prefix}-"
  - reuse the same Scenario / ViolationPattern / ToolPredicate imports
  - target the same category (ScenarioCategory.{cat_enum})
  - cover a DIFFERENT attack pattern than the examples
  - have a violation predicate that the auto-labeler can match

Existing examples for inspiration (do not copy verbatim):

{examples}

Now produce {n} new scenarios. Reply with the full Python module.
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--category", required=True,
                    help="enum name in ScenarioCategory (e.g. 'shell_injection_via_args')")
    ap.add_argument("--n", type=int, default=8)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--prefix", default=None,
                    help="seed-id prefix; defaults to <category>-auto")
    ap.add_argument("--example", type=Path, default=None,
                    help="example file to show Opus; defaults to scenarios/<category>.py")
    ap.add_argument("--model", default="opus",
                    help="claude model alias (opus/sonnet/haiku) or full id")
    args = ap.parse_args()

    cat_enum = args.category.upper()
    prefix = args.prefix or args.category.split("_")[0] + "-auto"
    example_path = args.example or (SCEN_DIR / f"{args.category}.py")
    if not example_path.exists():
        print(f"no example file at {example_path}; try --example", file=sys.stderr)
        return 1
    example_text = example_path.read_text()

    prompt = PROMPT_TEMPLATE.format(
        n=args.n,
        prefix=prefix,
        cat_enum=cat_enum,
        examples=example_text,
    )

    print(f"asking {args.model} for {args.n} new scenarios in category {cat_enum}...",
          file=sys.stderr)
    result = subprocess.run(
        ["claude", "-p",
         "--model", args.model,
         "--output-format", "text",
         "--no-session-persistence",
         "--dangerously-skip-permissions",
         "--", prompt],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        print("claude -p failed:", result.stderr[:500], file=sys.stderr)
        return result.returncode

    text = result.stdout
    # strip surrounding fences/text if any
    if "```python" in text:
        text = text.split("```python", 1)[1].split("```", 1)[0]
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text.strip() + "\n")
    print(f"wrote {args.out}")
    print(f"Don't forget to add `from . import {args.out.stem}` and "
          f"`*{args.out.stem}.SCENARIOS` to scenarios/__init__.py.",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
