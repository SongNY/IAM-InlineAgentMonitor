#!/usr/bin/env python3
"""Build the training dataset from generated run directories.

Reads `<run_dir>/trajectory.json` files, dedupes by content hash, splits into
train/val/test (no scenario leakage across splits), and writes JSONL.

Usage:
    python scripts/build_dataset.py \\
        --include runs-v1 runs-permissive runs-react runs-react-ext \\
        --exclude-broken \\
        --out data/v0.1/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_iam.schema import Trajectory


def _trace_hash(traj: Trajectory) -> str:
    blob = "|".join(
        f"{s.role}:{(s.action or {}).get('tool','')}:{(s.action or {}).get('args','')}:{(s.observation or '')[:80]}:{(s.content or '')[:80]}"
        for s in traj.steps
    )
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _scenario_id(run_id: str) -> str:
    """Extract scenario base id from run_id like 'iif-readme-aws-openai_react-abc'."""
    for backend in ("claude_code", "openai_react", "langgraph", "openhands"):
        marker = f"-{backend}-"
        if marker in run_id:
            return run_id.split(marker)[0]
    return run_id


def collect(roots: list[Path]) -> list[tuple[Trajectory, Path]]:
    seen: set[str] = set()
    out: list[tuple[Trajectory, Path]] = []
    for root in roots:
        for tf in sorted(root.rglob("trajectory.json")):
            try:
                traj = Trajectory.model_validate_json(tf.read_text())
            except Exception:
                continue
            if len(traj.steps) < 2:
                continue
            h = _trace_hash(traj)
            if h in seen:
                continue
            seen.add(h)
            out.append((traj, tf))
    return out


def split_by_scenario(items: list[tuple[Trajectory, Path]], val: float, test: float, seed: int):
    by_scen: dict[str, list] = defaultdict(list)
    for traj, tf in items:
        by_scen[_scenario_id(traj.id)].append((traj, tf))

    rng = random.Random(seed)
    scenarios = sorted(by_scen.keys())
    rng.shuffle(scenarios)
    n = len(scenarios)
    n_test = max(1, int(n * test))
    n_val = max(1, int(n * val))
    test_scen = set(scenarios[:n_test])
    val_scen = set(scenarios[n_test:n_test + n_val])

    train, validation, testset = [], [], []
    for scen, lst in by_scen.items():
        target = testset if scen in test_scen else (validation if scen in val_scen else train)
        target.extend(lst)
    return train, validation, testset, test_scen, val_scen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--include", nargs="+", required=True, type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--val", type=float, default=0.15)
    ap.add_argument("--test", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    items = collect(args.include)
    print(f"collected {len(items)} unique trajectories from {len(args.include)} roots")
    counts = Counter()
    for traj, _ in items:
        counts["unsafe" if (traj.label and traj.label.is_anomaly) else "safe"] += 1
        counts["total"] += 1
    print(f"  safe={counts['safe']}  unsafe={counts['unsafe']}  ratio={counts['unsafe']/counts['total']:.0%}")

    train, val, test, test_scen, val_scen = split_by_scenario(
        items, args.val, args.test, args.seed,
    )
    args.out.mkdir(parents=True, exist_ok=True)
    for name, group in [("train", train), ("val", val), ("test", test)]:
        out_path = args.out / f"{name}.jsonl"
        with out_path.open("w") as f:
            for traj, _ in group:
                f.write(traj.model_dump_json() + "\n")
        nsf = sum(1 for t, _ in group if t.label and t.label.is_anomaly)
        print(f"{name:5}: {len(group):3d} traces ({nsf} unsafe, {len(group)-nsf} safe)  → {out_path}")

    # write scenario-split metadata
    (args.out / "scenario_splits.json").write_text(json.dumps({
        "val_scenarios": sorted(val_scen),
        "test_scenarios": sorted(test_scen),
        "seed": args.seed,
    }, indent=2))
    print(f"\nval scenarios:  {sorted(val_scen)}")
    print(f"test scenarios: {sorted(test_scen)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
