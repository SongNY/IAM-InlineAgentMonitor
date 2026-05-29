#!/usr/bin/env python3
"""Pinpoint the benign false-positives that cap PR@FSR=1%.

The headline metric is throttled by a handful of benign traces (almost all from
the ATBench source) that fire at high P(STOP). This finds them so you can decide
the fix: relabel (genuinely an attack?), add as hard negatives, or accept.

Input is a scores.jsonl produced by the eval runner (`agent_iam.eval.runner`)
on a GPU/Kaggle run — pure-Python here, no model needed.

    python scripts/inspect_atbench_fp.py runs-eval/agent_iam/scores.jsonl
    python scripts/inspect_atbench_fp.py scores.jsonl --source atbench --top 15

Prints, for the worst benign false-positives: trace_id, source, p_stop, the
queried position, predicted type/reason — and the FSR you'd get at each
candidate threshold, so you can see exactly which traces to remove to clear 1%.
"""

from __future__ import annotations

import argparse
import sys

from agent_iam.eval.runner import load_results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("scores", help="path to scores.jsonl")
    ap.add_argument("--source", default=None, help="only this source (e.g. atbench); default: all")
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args(argv)

    results = load_results(args.scores)
    benign = [r for r in results if not r.is_anomaly]
    if args.source:
        benign = [r for r in benign if r.source == args.source]
    if not benign:
        print("no benign traces matched", file=sys.stderr)
        return 1

    # p_stop per benign trace = max over its query positions (the value that
    # determines whether it false-stops at a given threshold).
    def pstop(r) -> float:
        ps = [q.p_stop for q in r.queries] if r.queries else ([r.p_stop] if r.p_stop is not None else [0.0])
        return max(ps)

    ranked = sorted(benign, key=pstop, reverse=True)
    n = len(benign)

    print(f"{n} benign traces" + (f" (source={args.source})" if args.source else "") + f"; worst {args.top} by P(STOP):\n")
    print(f"{'p_stop':>7}  {'source':<12} {'trace_id':<40} type/reason")
    for r in ranked[: args.top]:
        p = pstop(r)
        reason = (r.predicted_reason or "").replace("\n", " ")[:60]
        rtype = r.predicted_type or ""
        print(f"{p:7.3f}  {r.source:<12} {r.trace_id[:40]:<40} {rtype} {reason}")

    # How many benign would still false-stop at a few thresholds, and the FSR.
    print(f"\nFSR over these {n} benign traces at candidate thresholds:")
    for thr in (0.5, 0.8, 0.9, 0.92, 0.95, 0.99):
        fp = sum(1 for r in benign if pstop(r) >= thr)
        print(f"  tau={thr:<4}  false_stops={fp:<3}  FSR={fp / n:.3%}")
    target = max(1, int(0.01 * n))
    print(f"\nTo reach FSR<=1% you may keep at most ~{target} false-stop(s) out of {n}. "
          f"The traces above the resulting threshold are the ones to fix.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
