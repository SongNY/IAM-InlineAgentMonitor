#!/usr/bin/env python3
"""Re-apply the current labeler to existing run directories.

Use after changing labeler semantics:
    python scripts/relabel.py runs-v1/ runs-permissive/ runs-langgraph/

For each <run_id>/trajectory.json, find the scenario whose id is the run_id's
prefix (everything before "-<backend>-<hex>") and re-label.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traceguard.data.generate import ALL_SCENARIOS
from traceguard.data.generate.labeler import label_trajectory
from traceguard.schema import Trajectory

SCEN_BY_ID = {s.id: s for s in ALL_SCENARIOS}


def relabel_dir(root: Path) -> tuple[int, int, int]:
    unsafe = safe = bad = 0
    for tf in sorted(root.rglob("trajectory.json")):
        run_id = tf.parent.name
        # parse "<scenario>-<backend>-<hex>"
        parts = run_id.rsplit("-", 2)
        if len(parts) < 3:
            bad += 1
            continue
        scen_id = parts[0]
        scen = SCEN_BY_ID.get(scen_id)
        if scen is None:
            bad += 1
            continue
        try:
            traj = Trajectory.model_validate_json(tf.read_text())
        except Exception:
            bad += 1
            continue
        # blank out prior label so relabeling is fresh
        traj.label = None
        labeled = label_trajectory(traj, scen)
        tf.write_text(labeled.model_dump_json(indent=2))
        if labeled.label and labeled.label.is_anomaly:
            unsafe += 1
        else:
            safe += 1
    return unsafe, safe, bad


def main() -> int:
    roots = [Path(a) for a in sys.argv[1:]] or [Path("runs")]
    totals = Counter()
    for r in roots:
        if not r.exists():
            print(f"skip {r} (missing)")
            continue
        u, s, b = relabel_dir(r)
        print(f"{r}:  unsafe={u}  safe={s}  bad={b}  rate={u/(u+s) if u+s else 0:.1%}")
        totals["unsafe"] += u
        totals["safe"] += s
        totals["bad"] += b
    print("---")
    t = totals["unsafe"] + totals["safe"]
    print(f"TOTAL:  unsafe={totals['unsafe']}  safe={totals['safe']}  bad={totals['bad']}  "
          f"rate={totals['unsafe']/t if t else 0:.1%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
