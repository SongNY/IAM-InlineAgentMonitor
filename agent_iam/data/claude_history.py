"""Loader for past Claude Code session history.

`~/.claude/projects/<encoded-dir>/<session-uuid>.jsonl` files store the complete
event log of every Claude Code session. Each line is one event of:
  - `user`: human message OR tool_result(s) from prior tool_use(s)
  - `assistant`: agent message with text + tool_use(s)
  - misc (file-history-snapshot, agent-meta, compact-summary, system) — skip

We fold consecutive events into a canonical Trajectory and chunk long sessions
into windowed sub-trajectories so we get many training samples per session.

REAL traces from REAL Claude usage are the highest-fidelity *benign*
training signal we can get — they encode legitimate tool-use patterns
that synthetic generation can't replicate.

SECURITY: every text field is run through `_scrub()` to strip credential
patterns (AWS, OpenAI, GitHub, npm tokens, generic API keys, AWS account IDs).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from ..schema import (
    AnomalyLabel,
    Role,
    TraceStep,
    Trajectory,
)

_SCRUB_PATTERNS = [
    # provider-specific tokens
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA<REDACTED-AWS>"),
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "sk-<REDACTED-OPENAI>"),
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "sk-ant-<REDACTED-ANTHROPIC>"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "ghp_<REDACTED-GITHUB>"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{30,}"), "github_pat_<REDACTED>"),
    (re.compile(r"npm_[A-Za-z0-9]{30,}"), "npm_<REDACTED-NPM>"),
    (re.compile(r"pypi-[A-Za-z0-9_-]{30,}"), "pypi-<REDACTED-PYPI>"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "glpat-<REDACTED-GITLAB>"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9_-]{20,}"), "xox<REDACTED-SLACK>"),
    # AWS account ids
    (re.compile(r"\b\d{12}\b"), "<REDACTED-12DIGIT>"),
    # generic high-entropy keys after "key/token/secret" labels
    (re.compile(r"(?i)(api[_-]?key|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9+/_-]{20,})['\"]?"),
     r"\1: <REDACTED-CREDENTIAL>"),
    # JWT-shaped tokens (eyJ... three base64 segments)
    (re.compile(r"\beyJ[A-Za-z0-9+/=_-]{20,}\.[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]+"), "<REDACTED-JWT>"),
    # private key blocks
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.DOTALL),
     "<REDACTED-PRIVATE-KEY-BLOCK>"),
]


def _scrub(text: str | None) -> str | None:
    if not text:
        return text
    out = text
    for pat, repl in _SCRUB_PATTERNS:
        out = pat.sub(repl, out)
    return out


def _scrub_args(args: dict) -> dict:
    """Recursively scrub a tool-call args dict."""
    out = {}
    for k, v in args.items():
        if isinstance(v, str):
            out[k] = _scrub(v) or ""
        elif isinstance(v, dict):
            out[k] = _scrub_args(v)
        elif isinstance(v, list):
            out[k] = [_scrub_args(x) if isinstance(x, dict) else (_scrub(x) if isinstance(x, str) else x) for x in v]
        else:
            out[k] = v
    return out


# ---------------------------------------------------------------------------


def iter_session_events(path: Path) -> Iterator[dict]:
    """Yield meaningful events (user/assistant only) from a session jsonl."""
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = d.get("type")
            if t in ("user", "assistant"):
                yield d


def events_to_steps(events: Iterator[dict]) -> list[TraceStep]:
    """Fold raw session events into a TraceStep list."""
    steps: list[TraceStep] = []
    idx = 0

    for ev in events:
        t = ev.get("type")
        msg = ev.get("message") or {}
        content = msg.get("content")

        if t == "user":
            if isinstance(content, str):
                steps.append(TraceStep(
                    step_idx=idx, role=Role.USER,
                    content=_scrub((content or "")[:2000]),
                ))
                idx += 1
            elif isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") == "tool_result":
                        inner = part.get("content", "")
                        if isinstance(inner, list):
                            inner = "".join(
                                str(x.get("text", "") if isinstance(x, dict) else x)
                                for x in inner
                            )
                        steps.append(TraceStep(
                            step_idx=idx, role=Role.TOOL,
                            observation=_scrub(str(inner)[:2000]),
                        ))
                        idx += 1
                    elif part.get("type") == "text":
                        steps.append(TraceStep(
                            step_idx=idx, role=Role.USER,
                            content=_scrub((part.get("text", "") or "")[:2000]),
                        ))
                        idx += 1

        elif t == "assistant":
            parts = content if isinstance(content, list) else [content]
            # collect text into thought; emit one step per tool_use
            current_thought = None
            tool_uses = []
            for c in parts:
                if not isinstance(c, dict):
                    continue
                if c.get("type") == "text":
                    txt = (c.get("text") or "").strip()
                    if txt:
                        current_thought = (current_thought + "\n" + txt) if current_thought else txt
                elif c.get("type") == "tool_use":
                    tool_uses.append(c)

            if not tool_uses:
                if current_thought:
                    steps.append(TraceStep(
                        step_idx=idx, role=Role.AGENT,
                        thought=_scrub(current_thought[:2000]),
                        content=_scrub(current_thought[:2000]),
                    ))
                    idx += 1
            else:
                for i, tu in enumerate(tool_uses):
                    steps.append(TraceStep(
                        step_idx=idx, role=Role.AGENT,
                        thought=_scrub((current_thought or "")[:1000]) if i == 0 else None,
                        action={
                            "tool": tu.get("name", ""),
                            "args": _scrub_args(tu.get("input") or {}),
                        },
                    ))
                    idx += 1
    return steps


def session_to_windowed_trajectories(
    path: Path,
    *,
    window_size: int = 16,
    stride: int = 12,
    min_steps: int = 4,
) -> Iterator[Trajectory]:
    """Convert one session file into multiple Trajectory windows.

    Each window is `window_size` consecutive steps; we slide by `stride`.
    Smaller window_size = more samples but less context.
    """
    events = list(iter_session_events(path))
    if not events:
        return
    steps = events_to_steps(events)
    if len(steps) < min_steps:
        return

    # extract first user message as task instruction (best effort)
    task_instruction = ""
    for s in steps:
        if s.role == Role.USER and s.content:
            task_instruction = (s.content or "")[:300]
            break

    session_id = path.stem
    project_slug = path.parent.name[-40:]   # tail of the dir name

    for start in range(0, len(steps), stride):
        window = steps[start : start + window_size]
        if len(window) < min_steps:
            break
        # re-index steps in this window
        renumbered = []
        for i, s in enumerate(window):
            renumbered.append(s.model_copy(update={"step_idx": i}))
        traj = Trajectory(
            id=f"history-{project_slug}-{session_id[:8]}-w{start:04d}",
            task_instruction=task_instruction,
            steps=renumbered,
            label=AnomalyLabel(is_anomaly=False),   # real usage = benign baseline
            source="claude_history",
        )
        yield traj


def iter_all_history(
    projects_root: Path | None = None,
    exclude_substr: list[str] | None = None,
    **window_kwargs,
) -> Iterator[Trajectory]:
    """Yield windowed Trajectories from every session file under projects_root.

    `exclude_substr`: skip dirs whose name contains any of these substrings.
    Default skips our own agent_iam data-gen runs so we don't double-count.
    """
    if projects_root is None:
        projects_root = Path.home() / ".claude" / "projects"
    if exclude_substr is None:
        exclude_substr = ["claude-agent-iam-runs", "claude-promptfoo"]

    for project_dir in sorted(projects_root.iterdir()):
        if not project_dir.is_dir():
            continue
        if any(sub in project_dir.name for sub in exclude_substr):
            continue
        for session_file in sorted(project_dir.glob("*.jsonl")):
            try:
                yield from session_to_windowed_trajectories(session_file, **window_kwargs)
            except Exception:
                continue
