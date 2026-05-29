#!/usr/bin/env python3
"""Pull ATBench (AI45Research/ATBench, Apache 2.0) into our run directory.

Usage:
    python scripts/pull_atbench.py --out runs-atbench/ --limit 1000
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traceguard.data.atbench import load_atbench


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("runs-atbench"))
    ap.add_argument("--split", default="test")
    ap.add_argument("--subset", default="ATBench")
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    n = n_unsafe = n_err = 0
    for i, traj in enumerate(load_atbench(split=args.split, subset=args.subset)):
        if args.limit and i >= args.limit:
            break
        if not traj.steps:
            n_err += 1
            continue
        p = args.out / f"atbench-{traj.id}" / "trajectory.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(traj.model_dump_json(indent=2))
        n += 1
        if traj.label and traj.label.is_anomaly:
            n_unsafe += 1
        if n % 100 == 0:
            print(f"  {n}: unsafe={n_unsafe} ({n_unsafe/n:.0%})")
    print(f"\nDONE: {n} trajectories ({n_unsafe} unsafe, {n_unsafe/n if n else 0:.0%}), errors={n_err}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
