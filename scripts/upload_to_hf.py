"""Upload a trained TraceGuard checkpoint to the Hugging Face Hub.

Built for the Kaggle training notebook (the checkpoint lives at
``/kaggle/working/submission_model_best``) but works with any local folder.

Auth resolution order:
  1. ``--token`` CLI arg
  2. ``$HF_TOKEN`` env var
  3. Kaggle Secret named ``HF_TOKEN``  (notebook -> Add-ons -> Secrets)

Kaggle cell:
    !python upload_to_hf.py \
        --repo-id <user>/traceguard-2b \
        --src /kaggle/working/submission_model_best

Programmatic:
    from upload_to_hf import upload_checkpoint
    upload_checkpoint("<user>/traceguard-2b",
                      "/kaggle/working/submission_model_best")
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def resolve_token(cli_token: str | None) -> str:
    """Find an HF write token from CLI arg, env, then Kaggle Secrets."""
    if cli_token:
        return cli_token
    if os.environ.get("HF_TOKEN"):
        return os.environ["HF_TOKEN"]
    try:  # Kaggle Secrets — only present inside a Kaggle kernel
        from kaggle_secrets import UserSecretsClient

        tok = UserSecretsClient().get_secret("HF_TOKEN")
        if tok:
            return tok
    except Exception:
        pass
    raise SystemExit(
        "No HF token found. Set --token, $HF_TOKEN, or add a Kaggle Secret "
        "named HF_TOKEN (a *write* token from huggingface.co/settings/tokens)."
    )


MODEL_CARD = """\
---
license: apache-2.0
base_model: Qwen/Qwen3.5-2B
library_name: transformers
pipeline_tag: text-classification
tags:
  - agent-safety
  - guardrail
  - llm-agent
  - trace-monitoring
  - traceguard
---

# {repo_id}

TraceGuard is a small fine-tuned LM that watches an LLM agent's tool-call
trace in real time and emits a per-step verdict — **OK** (let the agent
continue) or **STOP** (block the next action) — before a critical action
executes. It is trained with dense per-step verdict supervision on agent
trajectories spanning prompt-injection, exfiltration, persistence, and
related attack families, plus benign agent runs.

## Usage

```python
from traceguard.detect.online import TraceMonitor

monitor = TraceMonitor.from_pretrained("{repo_id}")
verdict = monitor.verdict_at(trajectory, cutoff_step=k)   # {{p_stop, predicted_symbol, ...}}
if verdict["predicted_symbol"] == "STOP":
    ...  # halt the agent before step k executes
```

## Evaluation

Headline metric is **Prevention Rate at False Stop Rate <= 1%** (PR@FSR=1%):
the fraction of attacks stopped in time when at most 1 in 100 benign runs is
falsely interrupted. See the paper / repo for the full PR-vs-FSR curve and
per-family slices.

- Base model: Qwen3.5-2B (Unsloth build)
- Verdict head: per-step OK/WARN/STOP symbol over the agent trace
"""


def upload_checkpoint(
    repo_id: str,
    src: str | os.PathLike,
    token: str | None = None,
    private: bool = True,
    write_card: bool = True,
    commit_message: str = "Upload TraceGuard checkpoint",
) -> str:
    """Create the repo (if needed) and push everything under ``src``.

    Returns the repo URL. Prefers ``upload_large_folder`` (resumable,
    parallel, multi-GB friendly) and falls back to ``upload_folder`` on
    older ``huggingface_hub``.
    """
    from huggingface_hub import HfApi, create_repo

    src = Path(src)
    if not src.is_dir():
        raise SystemExit(f"Source folder not found: {src}")

    tok = resolve_token(token)
    api = HfApi(token=tok)

    create_repo(repo_id, token=tok, repo_type="model", private=private, exist_ok=True)

    if write_card:
        card = src / "README.md"
        if not card.exists():
            card.write_text(MODEL_CARD.format(repo_id=repo_id))
            print(f"  wrote model card -> {card}")

    # Skip optimizer/training-state junk if it ever lands in the folder.
    ignore = ["*.lock", ".cache*", "optimizer*", "global_step*", "*.pt", "rng_state*"]

    try:
        api.upload_large_folder(
            repo_id=repo_id,
            folder_path=str(src),
            repo_type="model",
            ignore_patterns=ignore,
        )
    except (AttributeError, ImportError):
        # Older huggingface_hub without upload_large_folder.
        api.upload_folder(
            repo_id=repo_id,
            folder_path=str(src),
            repo_type="model",
            commit_message=commit_message,
            ignore_patterns=ignore,
        )

    url = f"https://huggingface.co/{repo_id}"
    print(f"Done -> {url}")
    return url


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Upload a TraceGuard checkpoint to the HF Hub.")
    p.add_argument("--repo-id", required=True, help="e.g. <user>/traceguard-2b")
    p.add_argument("--src", default="/kaggle/working/submission_model_best",
                   help="Local checkpoint folder to upload.")
    p.add_argument("--token", default=None, help="HF write token (else env / Kaggle Secret).")
    p.add_argument("--public", action="store_true", help="Create a public repo (default private).")
    p.add_argument("--no-card", action="store_true", help="Do not auto-write a model card.")
    args = p.parse_args(argv)

    upload_checkpoint(
        repo_id=args.repo_id,
        src=args.src,
        token=args.token,
        private=not args.public,
        write_card=not args.no_card,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
