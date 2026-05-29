#!/usr/bin/env python3
"""Tokenize a trajectory JSONL into input_ids/labels JSONL ready for SFTTrainer.

Run AFTER scripts/build_dataset.py.

Usage:
    python scripts/tokenize_dataset.py \\
        --in  data/v0.1/train.jsonl \\
        --out data/v0.1/train.tokenized.jsonl \\
        --tokenizer Qwen/Qwen3.5-2B \\
        --max-length 4096
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traceguard.schema import Trajectory
from traceguard.tokenize import TraceTokenizer


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--tokenizer", default="Qwen/Qwen3.5-2B")
    ap.add_argument("--max-length", type=int, default=4096)
    ap.add_argument("--truncate-to-anomaly", action="store_true", default=True)
    args = ap.parse_args()

    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(args.tokenizer, trust_remote_code=True)
    trace_tok = TraceTokenizer(tok)

    n_in = n_out = n_unsafe = 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.inp.open() as fin, args.out.open("w") as fout:
        for line in fin:
            n_in += 1
            try:
                traj = Trajectory.model_validate_json(line)
            except Exception:
                continue

            # Per-step verdicts are derived inside encode_for_training from
            # the trace label (dense layout) — no verdict needs to be passed.
            if traj.label and traj.label.is_anomaly:
                n_unsafe += 1

            enc = trace_tok.encode_for_training(
                traj,
                max_length=args.max_length,
                truncate_to_anomaly=args.truncate_to_anomaly,
            )

            fout.write(json.dumps({
                "id": traj.id,
                "input_ids": enc.input_ids,
                "labels": enc.labels,
            }) + "\n")
            n_out += 1

    print(f"  in: {n_in} trajectories")
    print(f"  out: {n_out} tokenized samples ({n_unsafe} unsafe, {n_out-n_unsafe} safe)")
    print(f"  out path: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
