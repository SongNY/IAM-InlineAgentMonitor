# Examples

Small, runnable-shaped examples for the two main TraceGuard workflows. Run them from the
repo root with the package installed in editable mode:

```bash
pip install -e ".[dev,eval]"
```

## `generate_data.py` — the data pipeline

Prints the exact, ordered commands that make up the data-generation pipeline
(`synthesize_scenarios.py` → `generate_traces.py` → `build_dataset.py` →
`tokenize_dataset.py`), and can run the model-free "collect" step over an existing
`runs/` directory.

```bash
python examples/generate_data.py            # print the pipeline
python examples/generate_data.py --run-collect
```

Generating new traces needs an agent backend and model API access; this example focuses on
showing the wiring. See each script's `--help` for the full flag set.

## `run_eval.py` — the eval harness

Scores a held-out split with the trained verdict head plus a keyword baseline, then builds
a side-by-side report (`report.md` / `slices.csv` / `pr_fsr.png`). The headline metric is
**PR@FSR=1%**.

```bash
python examples/run_eval.py \
    --model Sunnyu/TraceGuard-Qwen3.5-2B \
    --data data/v0.1/test.jsonl \
    --out runs-eval
```

Loading the model needs torch + transformers (and realistically a GPU); the keyword
baseline and the metrics themselves are pure-Python. Use `--limit N` for a quick smoke
test over the first N traces.

## `streaming_monitor.py` — the online agent-loop guard

A model-free demo of `StreamingMonitor` (`observe` → `guard` → `commit`) walking a
poisoned trajectory (read `.env` → grep `TOKEN` → POST to an external host); the proposed
POST gets a `STOP` before it executes. Swap in a real `TraceMonitor.from_pretrained(...)`
without changing the loop.

```bash
python examples/streaming_monitor.py
```
