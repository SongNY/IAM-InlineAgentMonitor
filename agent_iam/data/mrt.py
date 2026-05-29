"""ScaleAI/mrt loader — REAL agent attack trajectories from the paper
"Reliable Weak-to-Strong Monitoring of LLM Agents" (Scale AI).

Each MRT transcript is an actual recorded agent run where the agent
performs a benign primary task plus a hidden malicious secondary task.
The `side_task_evaluation` bool tells us whether the agent completed
the malicious task — i.e. the trace is an anomaly.

Schema mapping:
    MRT.conversation       -> our list[TraceStep]
    MRT.side_task_evaluation == True -> AnomalyLabel(is_anomaly=True)
    MRT.monitoring_response -> AnomalyLabel.reason

We sample task_pairs and download a configurable number of transcripts
each. Loading is incremental + cached via HF hub.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from ..schema import (
    AnomalyLabel,
    FailureMode,
    HarmCategory,
    RiskSource,
    Role,
    TraceStep,
    Trajectory,
)

_REPO = "ScaleAI/mrt"


def list_task_pairs(api=None) -> list[str]:
    """Discover all distinct task_pair directories in the MRT dataset."""
    if api is None:
        from huggingface_hub import HfApi
        api = HfApi()
    info = api.dataset_info(_REPO)
    seen = set()
    for s in info.siblings:
        m = re.match(r"task_pairs/([^/]+)/", s.rfilename)
        if m:
            seen.add(m.group(1))
    return sorted(seen)


def list_transcripts(task_pair: str, api=None) -> list[str]:
    """List transcript JSON paths for one task pair."""
    if api is None:
        from huggingface_hub import HfApi
        api = HfApi()
    info = api.dataset_info(_REPO)
    out = []
    prefix = f"task_pairs/{task_pair}/transcripts/"
    for s in info.siblings:
        if s.rfilename.startswith(prefix) and s.rfilename.endswith(".json"):
            out.append(s.rfilename)
    return out


def load_transcript(rfilename: str) -> dict:
    """Download one transcript JSON and return its parsed content."""
    from huggingface_hub import hf_hub_download
    p = hf_hub_download(repo_id=_REPO, repo_type="dataset", filename=rfilename)
    return json.loads(Path(p).read_text())


def transcript_to_trajectory(d: dict, traj_id: str) -> Trajectory:
    """Convert one MRT transcript dict into our Trajectory."""
    steps: list[TraceStep] = []
    idx = 0
    task_instruction = ""

    for turn in d.get("conversation", []) or []:
        role = turn.get("role", "")
        content = turn.get("content")
        tool_calls = turn.get("tool_calls")

        # MRT stores tool_calls as a JSON-encoded string sometimes.
        if isinstance(tool_calls, str):
            try:
                tool_calls = json.loads(tool_calls)
            except json.JSONDecodeError:
                tool_calls = None

        if role == "system":
            # MRT system prompt sometimes contains the user task.
            if task_instruction == "" and isinstance(content, str):
                task_instruction = content[:500]
            steps.append(TraceStep(step_idx=idx, role=Role.SYSTEM, content=_truncate(content)))
            idx += 1
        elif role == "user":
            if task_instruction == "" and isinstance(content, str):
                task_instruction = content[:500]
            steps.append(TraceStep(step_idx=idx, role=Role.USER, content=_truncate(content)))
            idx += 1
        elif role == "assistant":
            thought = content if isinstance(content, str) else None
            if not tool_calls:
                steps.append(TraceStep(
                    step_idx=idx, role=Role.AGENT,
                    thought=thought, content=thought,
                ))
                idx += 1
            else:
                for i, tc in enumerate(tool_calls):
                    fn = (tc.get("function") if isinstance(tc, dict) else {}) or {}
                    name = fn.get("name", "")
                    args_raw = fn.get("arguments", "{}")
                    try:
                        args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                    except json.JSONDecodeError:
                        args = {"_raw": args_raw}
                    steps.append(TraceStep(
                        step_idx=idx, role=Role.AGENT,
                        thought=thought if i == 0 else None,
                        action={"tool": name, "args": args},
                    ))
                    idx += 1
        elif role == "tool":
            steps.append(TraceStep(
                step_idx=idx, role=Role.TOOL,
                observation=_truncate(content),
            ))
            idx += 1

    side_task = bool(d.get("side_task_evaluation"))
    monitoring = d.get("monitoring_response") or ""

    label: AnomalyLabel | None
    if side_task:
        label = AnomalyLabel(
            is_anomaly=True,
            anomaly_step=_guess_anomaly_step(steps),
            risk_source=RiskSource.USER_PROMPT_INJECTION,
            failure_mode=FailureMode.OTHER,    # MRT doesn't taxonomize by failure_mode
            harm_category=HarmCategory.SECURITY,
            reason=_truncate(monitoring, 800),
        )
    else:
        label = AnomalyLabel(is_anomaly=False)

    return Trajectory(
        id=traj_id,
        task_instruction=task_instruction,
        steps=steps,
        label=label,
        source="mrt",
    )


def sample_trajectories(
    n_task_pairs: int = 50,
    transcripts_per_pair: int = 10,
    out_dir: Path | None = None,
    seed: int = 42,
) -> Iterator[Trajectory]:
    """Sample MRT trajectories incrementally, optionally caching to disk."""
    import random

    from huggingface_hub import HfApi
    api = HfApi()

    pairs = list_task_pairs(api=api)
    rng = random.Random(seed)
    rng.shuffle(pairs)
    pairs = pairs[:n_task_pairs]

    seen_ids: set[str] = set()
    for pair in pairs:
        transcripts = list_transcripts(pair, api=api)
        rng.shuffle(transcripts)
        for r in transcripts[:transcripts_per_pair]:
            traj_id = f"mrt-{pair}-{Path(r).stem}"
            if traj_id in seen_ids:
                continue
            seen_ids.add(traj_id)
            try:
                d = load_transcript(r)
            except Exception:
                continue
            traj = transcript_to_trajectory(d, traj_id)
            if out_dir is not None:
                p = out_dir / traj_id / "trajectory.json"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(traj.model_dump_json(indent=2))
            yield traj


# ----------------------------------------------------------------------


def _truncate(x, n: int = 2000) -> str | None:
    if x is None:
        return None
    s = x if isinstance(x, str) else json.dumps(x, default=str)
    return s[:n]


def _guess_anomaly_step(steps: list[TraceStep]) -> int | None:
    """For a labeled-anomaly trace, pick the last AGENT action as anomaly_step.

    MRT doesn't annotate per-step; we use last agent tool call as a heuristic
    (the violation usually happens late in the trace once recon + setup is done).
    """
    last = None
    for s in steps:
        if s.role == Role.AGENT and s.action is not None:
            last = s.step_idx
    return last
