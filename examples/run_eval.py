#!/usr/bin/env python3
"""Score a held-out split with IAM + a keyword baseline, then build a report.

This mirrors what the Kaggle training notebook does at the end of each epoch, but as a
standalone script. Run it after you have a tokenized/built test split (see
``examples/generate_data.py`` or ``scripts/build_dataset.py``).

    python examples/run_eval.py \
        --model Sunnyu/IAM-Qwen3.5-2B \
        --data data/v0.1/test.jsonl \
        --out runs-eval

Outputs (under ``--out``):
    runs-eval/agent_iam/scores.jsonl
    runs-eval/keyword/scores.jsonl
    runs-eval/report/report.md      (headline PR@FSR table + per-slice tables)
    runs-eval/report/slices.csv
    runs-eval/report/pr_fsr.png     (only if matplotlib is installed; `pip install -e ".[eval]"`)

NOTE: loading the model needs torch + transformers and (realistically) a GPU. The eval
*metrics* themselves are pure-Python, but scoring runs the model over every trace.
The keyword baseline needs no model.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True, help="HF model id or local checkpoint path.")
    ap.add_argument("--data", required=True, help="Path to the test split JSONL.")
    ap.add_argument("--out", default="runs-eval", help="Output directory root.")
    ap.add_argument("--limit", type=int, default=None, help="Score only the first N traces (smoke test).")
    args = ap.parse_args()

    # Imported lazily so the eval *metrics* stay importable without torch.
    from agent_iam.detect.online import TraceMonitor
    from agent_iam.eval.baselines import keyword_scorer
    from agent_iam.eval.report import build_report
    from agent_iam.eval.runner import run_split, verdict_scorer

    out = Path(args.out)
    tg_scores = out / "agent_iam" / "scores.jsonl"
    kw_scores = out / "keyword" / "scores.jsonl"

    # 1. Score the trained verdict head. verdict_scorer makes 1-2 queries per trace
    #    (anomaly + pre-anomaly-safe for attacks, one random position for benigns).
    print(f"Loading TraceMonitor from {args.model} ...")
    monitor = TraceMonitor.from_pretrained(args.model)
    print(f"Scoring {args.data} -> {tg_scores}")
    summary = run_split(verdict_scorer(monitor), args.data, tg_scores, limit=args.limit)
    print(json.dumps(summary, indent=2))

    # 2. Score the keyword baseline (no model needed).
    print(f"Scoring keyword baseline -> {kw_scores}")
    run_split(keyword_scorer(), args.data, kw_scores, limit=args.limit)

    # 3. Build the side-by-side report. Headline metric is PR @ FSR <= 1%.
    report = build_report(
        [tg_scores, kw_scores],
        out_dir=out / "report",
        names=["agent_iam", "keyword"],
        slice_keys=("family", "source", "harm_category"),
    )
    print(json.dumps(report, indent=2))
    print(f"\nRead the headline table at: {out / 'report' / 'report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
