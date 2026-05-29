#!/usr/bin/env python3
"""Package the agent_iam repo + tokenized dataset into two zip files
ready to be uploaded as Kaggle Datasets.

Output:
    dist/agent-iam-src.zip       # the pip-installable Python package
    dist/agent-iam-data.zip      # the tokenized train/val/test JSONL

On Kaggle, add these as input datasets to your notebook, then in the
notebook setup cell:
    !pip install /kaggle/input/agent-iam-src/agent_iam-0.1.0a0-py3-none-any.whl
    # or for editable dev: !pip install -e /kaggle/input/agent-iam-src/

The tokenized data is referenced from the notebook as:
    /kaggle/input/agent-iam-data/train.tokenized.jsonl
    /kaggle/input/agent-iam-data/val.tokenized.jsonl
    /kaggle/input/agent-iam-data/test.tokenized.jsonl
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
DIST.mkdir(exist_ok=True)


def build_src_wheel() -> Path:
    """Build a wheel via `pip wheel` (no extra deps)."""
    wheelhouse = DIST / "wheels"
    if wheelhouse.exists():
        shutil.rmtree(wheelhouse)
    wheelhouse.mkdir()
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(wheelhouse), str(ROOT)],
        check=True,
    )
    # find the produced wheel
    wheels = list(wheelhouse.glob("agent_iam-*.whl"))
    if not wheels:
        raise RuntimeError("no wheel produced")
    return wheels[0]


def zip_src(wheel_path: Path) -> Path:
    """Zip a tiny dir containing the wheel + README, for Kaggle dataset upload."""
    stage = DIST / "src_stage"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    shutil.copy(wheel_path, stage / wheel_path.name)
    # also copy README, ROADMAP, PAPER_FINDINGS + the training notebook
    for f in ("README.md", "ROADMAP.md", "PAPER_FINDINGS.md"):
        p = ROOT / f
        if p.exists():
            shutil.copy(p, stage / f)
    for nb_name in ("train_kaggle3.ipynb", "train_kaggle.ipynb", "prep_qwen35_wheels.ipynb"):
        nb = ROOT / "notebooks" / nb_name
        if nb.exists():
            shutil.copy(nb, stage / nb_name)
    out = DIST / "agent-iam-src"
    if out.with_suffix(".zip").exists():
        out.with_suffix(".zip").unlink()
    shutil.make_archive(str(out), "zip", str(stage))
    return out.with_suffix(".zip")


def zip_data(version: str = "v0.18") -> Path:
    """Zip the tokenized dataset for Kaggle dataset upload."""
    data_dir = ROOT / "data" / version
    if not data_dir.exists():
        raise FileNotFoundError(f"no dataset at {data_dir} — run build_dataset.py + tokenize_dataset.py first")
    stage = DIST / "data_stage"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    for fn in ("train.tokenized.jsonl", "val.tokenized.jsonl", "test.tokenized.jsonl",
               "train.jsonl", "val.jsonl", "test.jsonl",
               "scenario_splits.json"):
        src = data_dir / fn
        if src.exists():
            shutil.copy(src, stage / fn)
    # add a README for the dataset
    (stage / "README.md").write_text(
        f"# IAM {version} dataset\n\n"
        "Tokenized agent-trace anomaly-detection dataset.\n\n"
        "## Files\n"
        "- `{train,val,test}.tokenized.jsonl` — Qwen3.5-2B tokenized; each line: "
        "`{id, input_ids, labels}` where labels=-100 outside the loss region.\n"
        "- `{train,val,test}.jsonl` — raw Trajectory JSON (for re-tokenization with a different tokenizer).\n"
        "- `scenario_splits.json` — which scenarios are in val/test (proves no leakage).\n\n"
        "## Loading in the Kaggle notebook\n\n"
        "```python\n"
        "import json\n"
        "from datasets import Dataset\n\n"
        "rows = []\n"
        "with open('/kaggle/input/agent-iam-data/train.tokenized.jsonl') as f:\n"
        "    for line in f:\n"
        "        rows.append(json.loads(line))\n"
        "ds = Dataset.from_list(rows)\n"
        "```\n"
    )
    out = DIST / "agent-iam-data"
    if out.with_suffix(".zip").exists():
        out.with_suffix(".zip").unlink()
    shutil.make_archive(str(out), "zip", str(stage))
    return out.with_suffix(".zip")


def main():
    print("→ building wheel...")
    wheel = build_src_wheel()
    print(f"  built {wheel.name}")
    src_zip = zip_src(wheel)
    print(f"  packed → {src_zip}  ({src_zip.stat().st_size/1024:.0f} KB)")

    print("→ packaging dataset...")
    data_zip = zip_data("v0.19")
    print(f"  packed → {data_zip}  ({data_zip.stat().st_size/1024:.0f} KB)")

    print()
    print(f"upload to Kaggle:")
    print(f"  1. New Dataset 'agent-iam-src'  ← upload {src_zip}")
    print(f"  2. New Dataset 'agent-iam-data' ← upload {data_zip}")
    print(f"  3. In notebook: + Add data → Your Datasets → both")


if __name__ == "__main__":
    main()
