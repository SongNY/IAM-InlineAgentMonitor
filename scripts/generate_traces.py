#!/usr/bin/env python3
"""Drive the attack-trace generation pipeline.

Usage:
    python scripts/generate_traces.py --out runs --runs-per-scenario 2 --model haiku
    python scripts/generate_traces.py --only iif-,exfil- --runs-per-scenario 3

After running:
    python scripts/generate_traces.py --collect runs --out-jsonl train.jsonl

Outputs:
    runs/<run_id>/trajectory.json   (per-run, includes label + steps)
    train.jsonl                     (concatenated, one trajectory per line, ready for training)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# allow running without `pip install -e .` from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_iam.data.generate import ALL_SCENARIOS, run_all


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("runs"),
                    help="dir to write per-run artifacts into")
    ap.add_argument("--runs-per-scenario", type=int, default=1)
    ap.add_argument("--model", default="haiku")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--mock-port", type=int, default=9999)
    ap.add_argument("--system-prompt", default=None,
                    help="override agent system prompt for every run. "
                         "Use '' for empty (most permissive). "
                         "Default keeps the ACME safety rules.")
    ap.add_argument("--backend", default="claude_code",
                    choices=["claude_code", "openhands", "langgraph", "openai_react"],
                    help="which agent framework to drive for data generation")
    ap.add_argument("--claude-bin", default="claude")
    ap.add_argument("--only", default="",
                    help="comma-separated id prefixes; if set, only run matching scenarios")
    ap.add_argument("--collect", type=Path, default=None,
                    help="if set, only collect existing run dirs under this path into the out jsonl")
    ap.add_argument("--out-jsonl", type=Path, default=Path("train.jsonl"))
    args = ap.parse_args()

    if args.collect:
        return collect(args.collect, args.out_jsonl)

    selected = ALL_SCENARIOS
    if args.only:
        prefixes = [p.strip() for p in args.only.split(",") if p.strip()]
        selected = [s for s in ALL_SCENARIOS if any(s.id.startswith(p) for p in prefixes)]

    if args.system_prompt is not None:
        # apply override to every scenario for this run
        selected = [s.model_copy(update={"extra_system_prompt": args.system_prompt})
                    for s in selected]

    print(f"running {len(selected)} scenarios × {args.runs_per_scenario} = "
          f"{len(selected) * args.runs_per_scenario} runs")
    args.out.mkdir(parents=True, exist_ok=True)

    results = run_all(
        selected,
        out_dir=args.out,
        backend=args.backend,
        runs_per_scenario=args.runs_per_scenario,
        model=args.model,
        timeout_s=args.timeout,
        mock_port=args.mock_port,
    )

    unsafe = sum(1 for r in results if r.traj.label and r.traj.label.is_anomaly)
    print(f"\nDone. {unsafe}/{len(results)} traces ended in attack success.")
    return 0


def collect(runs_root: Path, out_jsonl: Path) -> int:
    n = 0
    with out_jsonl.open("w") as f:
        for traj_file in sorted(runs_root.rglob("trajectory.json")):
            try:
                obj = json.loads(traj_file.read_text())
            except json.JSONDecodeError:
                continue
            f.write(json.dumps(obj, separators=(",", ":")) + "\n")
            n += 1
    print(f"collected {n} trajectories → {out_jsonl}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
