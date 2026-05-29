# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0a0] — 2026-05-29

First public alpha. Open-source release of the v0.19 baseline.

### Added

- **Canonical `Trajectory` schema** (`traceguard.schema`) with an ATBench-compatible label
  space (risk source × failure mode × harm category) and a runtime `Verdict` type
  (`OK` / `WARN` / `STOP`). Framework-agnostic: data-gen backends and runtime adapters
  produce and consume the same `Trajectory`.
- **`TraceMonitor`** (`traceguard.detect.online`) — online mid-trace inference:
  `from_pretrained`, `check` (verdict-head `P(STOP)` in the dense per-step layout),
  `verdict_at`, and a legacy action-span `ppl_score`. Lazy-loaded so `import traceguard`
  stays light (no torch required for the schema/tokenizer).
- **`StreamingMonitor`** (`traceguard.runtime.stream`) — agent-loop API
  (`observe` / `guard` / `commit`) that maintains the running trace.
- **Dense per-step verdict supervision** in `TraceTokenizer` — a verdict slot after every
  decision step (OK for safe steps, STOP + type + reason at the anomaly step), which fixes
  over-flagging, with STOP loss up-weighting (`W_STOP`).
- **Eval harness** (`traceguard.eval`) — deployment-framed metrics (Prevention Rate, False
  Stop Rate), the **PR@FSR** operating-point metric, AUROC / best-F1 reference metrics,
  per-slice breakdowns, a `score`/`report` CLI, and `report.md` / `slices.csv` /
  `pr_fsr.png` output. Keyword and untrained-LM baselines included.
- **Data-generation pipeline** (`scripts/` + `traceguard.data`) — scenario synthesis,
  multi-backend trace generation (Claude Code, LangGraph, OpenHands, OpenAI ReAct), dataset
  build with leakage-free train/val/test splits, tokenization, and external-source loaders
  (ATBench, Scale AI MRT, Claude Code history, Agent3Sigma-Sweep).
- **Runtime adapters** (`traceguard.runtime.adapters`) for Claude Code and LangGraph, plus
  the `traceguard` CLI (`scan`, `serve`).
- **Kaggle training notebook** (`notebooks/train_kaggle3.ipynb`) — full-parameter
  fine-tune of Qwen3.5-2B (~2.2B params) with best-epoch selection by PR@FSR=1%.

### Results (preliminary, v0.19)

- PR@FSR=1% ≈ 0.89, AUROC ≈ 0.997 on a 269-trace eval set (130 attacks / 139 benign);
  keyword baseline ≈ 0.115, perplexity baseline ≈ 0.08.

[Unreleased]: https://github.com/songningyu/traceguard/compare/v0.1.0a0...HEAD
[0.1.0a0]: https://github.com/songningyu/traceguard/releases/tag/v0.1.0a0
