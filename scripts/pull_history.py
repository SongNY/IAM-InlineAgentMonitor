#!/usr/bin/env python3
"""Pull windowed benign Trajectories from past Claude Code sessions.

Usage:
    python scripts/pull_history.py --out runs-history/ --window 16 --stride 12
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_iam.data.claude_history import iter_all_history


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("runs-history"))
    ap.add_argument("--window", type=int, default=16)
    ap.add_argument("--stride", type=int, default=12)
    ap.add_argument("--max-samples", type=int, default=0, help="0 = no cap")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    n = 0
    project_counter: dict[str, int] = {}
    for traj in iter_all_history(window_size=args.window, stride=args.stride):
        p = args.out / traj.id / "trajectory.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(traj.model_dump_json(indent=2))
        n += 1
        proj = traj.id.split("-history-")[-1].split("-")[0] if "history-" in traj.id else traj.id[:20]
        project_counter[proj] = project_counter.get(proj, 0) + 1
        if n % 100 == 0:
            print(f"  {n} windows extracted...")
        if args.max_samples and n >= args.max_samples:
            break
    print(f"\nDONE: {n} benign windowed trajectories")
    print("by project (top 10):")
    for k, v in sorted(project_counter.items(), key=lambda x: -x[1])[:10]:
        print(f"  {k[:50]}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
