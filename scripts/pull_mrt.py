#!/usr/bin/env python3
"""Pull a sample of REAL agent attack trajectories from ScaleAI/mrt.

Usage:
    python scripts/pull_mrt.py --task-pairs 30 --per-pair 6 --out runs-mrt/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_iam.data.mrt import sample_trajectories


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-pairs", type=int, default=30)
    ap.add_argument("--per-pair", type=int, default=6)
    ap.add_argument("--out", type=Path, default=Path("runs-mrt"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    n = 0
    n_unsafe = 0
    for traj in sample_trajectories(
        n_task_pairs=args.task_pairs,
        transcripts_per_pair=args.per_pair,
        out_dir=args.out,
        seed=args.seed,
    ):
        n += 1
        if traj.label and traj.label.is_anomaly:
            n_unsafe += 1
        if n % 20 == 0:
            print(f"  {n}: unsafe={n_unsafe} ({n_unsafe/n:.0%})")
    print(f"\nDONE: {n} trajectories ({n_unsafe} unsafe, {n_unsafe/n if n else 0:.0%})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
