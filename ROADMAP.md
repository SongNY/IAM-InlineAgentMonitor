# IAM — 30-Day Ship Plan

> **Status — historical planning doc.** This is the original 30-day plan. The shipped
> v0.19 baseline diverged from some early "locked" choices: it is a **full fine-tune of
> Qwen3.5-2B**, not a LoRA of 0.8B. Day-by-day items below that mention "0.8B" / "LoRA"
> reflect the initial plan, not the released model. See `README.md` and `CHANGELOG.md`
> for the current state.

**Goal by D30**: arXiv preprint + HF model card + GitHub repo + pip package + dataset card,
all linked, all Apache 2.0.

Locked decisions (updated to shipped reality):
- Base model = **Qwen3.5-2B** (Unsloth build), **full-parameter fine-tune** on Kaggle GPU
  (original plan was Qwen3.5-0.8B + LoRA r=32 — superseded)
- Primary data = self-generated attack traces via `scripts/generate_traces.py`, plus
  ATBench / Scale AI MRT / Agent3Sigma-Sweep / Claude Code history
- License = Apache 2.0 throughout
- Vision (MiniCPM-V) is a **V2 path**, not V1

---

## Phase 1 — Data foundation (D1–D8)

| D | Deliverable |
|---|---|
| D1 | ✅ Repo scaffold + `Scenario` schema + 4 attack categories + 5 benign + framework-agnostic `AgentBackend` / `RuntimeAdapter` interfaces |
| D2 | ✅ First real traces via Claude Code (verified pipeline end-to-end) |
| D3 | Expand attack library to 10 categories × 5–10 seeds each ≈ 80 seed scenarios. Target classes still missing: tool-description injection, corrupted tool feedback, shell injection via args, memory poisoning, excessive agency, destructive command. |
| D4 | Multi-model run: generate traces with `--model haiku` + `--model sonnet`. Same scenarios; agents of different strength fail differently → richer label distribution. |
| D5 | Build LangGraph backend traces with Qwen2.5-7B / GLM-4-9B locally (Ollama / vLLM) — cost-free bulk generation. Target 500+ additional traces. |
| D6 | Build OpenHands backend traces. Coding-agent specific scenarios (git, npm, package install). |
| D7 | Unify all sources; dedupe; train/val/test split (no scenario leakage across splits). |
| D8 | Push v0.1 dataset card to HF as `<user>/agent-iam-attack-traces-v0.1`. Per-source license attribution. |

**Exit**: 2k–5k labeled trajectories, ≥40% with positive attack outcomes (anomaly=True). Dataset card live.

---

## Phase 2 — Training (D9–D15)

| D | Deliverable |
|---|---|
| D9 | Kaggle smoke train: Qwen3.5-0.8B + 200 samples × 1 epoch on T4 ≤ 30 min. End-to-end pipeline works. |
| D10 | Full LoRA train on the v0.1 dataset (2 epochs, ~4–6 h on T4×2 with grad accum). Save adapter. |
| D11 | Calibrate PPL threshold on val split (sweep {4, 6, 8, 10, 12, 16}); pick by Youden's J on synthesized attacks. |
| D12 | Latency benchmark: IAM-0.8B inference on T4, M-series CPU, vLLM-served. Target p50 < 100ms / step. |
| D13 | Push v0.1 model to HF: `<user>/agent-iam-0.8b`. Adapter + merged + GGUF for edge. |
| D14 | (Optional ablation) re-train without SSL pretraining objective. Compare. |
| D15 | (Optional ablation) train Qwen3.5-2B variant for sanity-check that 0.8B isn't capacity-bound. |

**Exit**: published model with calibrated threshold; ablation results showing 0.8B is sufficient.

---

## Phase 3 — Evaluation & ablations (D16–D22)

| D | Deliverable |
|---|---|
| D16 | Eval harness in `agent_iam.eval`. Score against **R-Judge**, **AgentDojo** (block rate & utility), **AgentHarm** (refusal rate, eval-only — canary checked), and our own held-out test split. |
| D17 | Baselines: zero-shot Qwen3.5-0.8B-Instruct, Qwen3.5-4B, Llama-Guard-3-1B, ShieldGemma-2B, GPT-4o-as-judge, Claude-Sonnet-as-judge. |
| D18 | Ablation A: with vs without anomaly-step truncation in training data. |
| D19 | Ablation B: action-span PPL only vs full-trace PPL vs verdict-head only. |
| D20 | Ablation C: cross-backend generalization. Train on Claude Code traces, eval on LangGraph + OpenHands traces (and rotations). This is the **headline novelty figure** — proves the canonical `Trajectory` abstraction works. |
| D21 | Online vs post-hoc: measure the fraction of detections happening *before* the critical action vs after. Target ≥70% online. |
| D22 | Pareto plot: latency × block rate × utility. |

**Exit**: paper-ready results table + 3 figures.

---

## Phase 4 — Runtime, paper, release (D23–D30)

| D | Deliverable |
|---|---|
| D23 | `agent_iam.runtime.adapters` finalize: Claude Code PreToolUse hook (binary), LangGraph callback (tested in-process), OpenHands pre-action hook stub. |
| D24 | `iam serve` HTTP sidecar + Docker image. Latency vs in-process. |
| D25 | **Live end-to-end demo**: poisoned README → real Claude Code with sidecar IAM → blocked WebFetch with `STOP` verdict and NL reason. Screencast. |
| D26 | Paper draft v0 (8pp): intro, method, data (self-generated framework-agnostic), training, results, ablations, limitations. |
| D27 | Tighten paper. Explicit positioning vs **TrajAD** (quality vs security framing), **ShieldAgent** (learned vs policy-rule), **R-Judge** (graded model vs single-model classifier), **AgentArmor** (symbolic vs distributional). |
| D28 | Internal red team: try to evade. Document evasions in §Limitations. Run a final eval with the evasions added to test set. |
| D29 | pypi `pip install agent-iam`. GitHub Actions tests. HF model + dataset card cross-links. tag `v0.1.0`. arXiv submit. |
| D30 | Workshop submission (NeurIPS SafeGenAI / ICLR SeT-LLM / SatML). HN + Twitter thread. |

---

## North-star metrics

1. **Block rate on attacks**: IAM-0.8B ≥ 85% on AgentDojo held-out; ≥ Llama-Guard-3-1B baseline.
2. **Utility preservation**: < 5% false-positive block rate on benign tasks.
3. **Mid-trace intervention rate**: ≥ 70% of detections happen *before* the critical action.
4. **Latency**: p50 < 100ms on a single GPU, < 300ms on Apple M-series CPU.
5. **Cross-backend transfer**: ≤ 15% F1 drop when training on framework A, testing on framework B.

Hit 1–3 → workshop. Hit all 5 → main-track submission.

---

## Risk register

| Risk | Mitigation |
|---|---|
| Claude Haiku refuses every attack → no positive samples | (a) use weaker LLM backend (Qwen2.5-7B via Ollama, no safety RLHF), (b) strip our `ACME-Helper` system prompt, (c) use stronger attack envelopes (encoded payloads, multi-turn) |
| Qwen3.5-0.8B can't produce coherent `<reason>` field | Two-stage: small model emits symbol+PPL; a cheap LLM (DeepSeek-flash) writes the reason only on STOP |
| Reviewer says "TrajAD already does this" | Anchor 3 axes: (i) security attacks ≠ TrajAD's quality anomalies, (ii) self-generated framework-agnostic data, (iii) online intervention with PPL gate, not post-hoc verdict head |
| Reviewer says "ShieldAgent already does this" | We're 2000× smaller (0.8B vs GPT-4o + InternVL2-2B) and self-supervised, not policy-rule |
| Kaggle GPU OOM at 4k context | Drop to 2k context, or use 4-bit base via Unsloth |
| AgentHarm contamination accidental | Hash + grep canary string in every training shard pre-upload; refuse to train if found |

---

## V2 path (deferred to ~D60–D90)

**IAM-V (Vision)** — same data pipeline, swap base model for **MiniCPM-V-4.6 (1.3B)**.
Covers visual prompt injection, browser-agent screenshot attacks, Computer Use traces.
Second paper. Don't start until V1 is shipped and stable.
