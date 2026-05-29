"""OpenHands backend.

OpenHands writes a stream of `events/*.json` into its workspace dir during
a run. We invoke the headless CLI, point the workspace at our sandbox, and
parse the event files in chronological order.

Reference: https://docs.all-hands.dev/usage/headless-mode

The expected event shapes (subject to upstream changes):

    {"id": 1, "source": "user",    "action": "message", "args": {"content": "..."}}
    {"id": 2, "source": "agent",   "action": "run",     "args": {"command": "ls"}}
    {"id": 3, "source": "agent",   "action": "read",    "args": {"path": "README.md"}}
    {"id": 4, "source": "tool",    "observation": "..." }
    {"id": 5, "source": "agent",   "action": "finish",  "args": {"thought": "..."}}
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from ....schema import Role, TraceStep, Trajectory
from .base import AgentBackend, RunSpec


# Map OpenHands action names → TraceGuard canonical tool names.
_ACTION_TOOL_MAP = {
    "run": "Bash",
    "read": "Read",
    "edit": "Edit",
    "write": "Write",
    "browse": "WebFetch",
    "browse_interactive": "WebFetch",
    "search": "Grep",
    "delegate": "Delegate",
}


class OpenHandsBackend(AgentBackend):
    name = "openhands"

    def __init__(self, bin_path: str = "openhands"):
        self.bin = bin_path

    def run(self, spec: RunSpec, output_dir: Path) -> Path:
        events_dir = output_dir / "events"
        events_dir.mkdir(parents=True, exist_ok=True)

        env = os.environ.copy()
        env.update(spec.env_overrides)
        # OpenHands reads model + workspace from env / flags.
        env["WORKSPACE_BASE"] = str(spec.sandbox_dir)
        env["LLM_MODEL"] = spec.model or "anthropic/claude-haiku-4-5"

        cmd = [
            self.bin, "main",
            "--task", spec.user_prompt,
            "--max-iterations", "30",
            "--config", str(self._write_config(spec, output_dir)),
        ]
        try:
            subprocess.run(cmd, env=env, timeout=spec.timeout_s, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            pass

        # OpenHands writes events into the workspace; copy/symlink for our consumer.
        src = spec.sandbox_dir / "events"
        if src.exists() and src != events_dir:
            # consolidate per-event json files into a single jsonl for parsing
            with (output_dir / "events.jsonl").open("w") as out_fp:
                for jf in sorted(src.glob("*.json")):
                    try:
                        out_fp.write(json.dumps(json.loads(jf.read_text())) + "\n")
                    except json.JSONDecodeError:
                        continue
        return output_dir / "events.jsonl"

    def _write_config(self, spec: RunSpec, output_dir: Path) -> Path:
        cfg = {
            "system_prompt": spec.system_prompt,
            "allowed_tools": spec.allowed_tools,
            "sandbox": {
                "type": "local",
                "workspace_base": str(spec.sandbox_dir),
            },
        }
        p = output_dir / "openhands_config.json"
        p.write_text(json.dumps(cfg, indent=2))
        return p

    def parse(self, events_path: Path, task_instruction: str, traj_id: str) -> Trajectory:
        steps: list[TraceStep] = []
        idx = 0
        with events_path.open() as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                src = ev.get("source")
                act = ev.get("action")
                obs = ev.get("observation")
                args = ev.get("args") or {}
                if src == "user" and act == "message":
                    steps.append(TraceStep(
                        step_idx=idx, role=Role.USER,
                        content=args.get("content") or "",
                    ))
                    idx += 1
                elif src == "agent" and act in _ACTION_TOOL_MAP:
                    steps.append(TraceStep(
                        step_idx=idx, role=Role.AGENT,
                        thought=args.pop("thought", None),
                        action={"tool": _ACTION_TOOL_MAP[act], "args": args},
                    ))
                    idx += 1
                elif src == "tool" and obs is not None:
                    steps.append(TraceStep(
                        step_idx=idx, role=Role.TOOL, observation=obs,
                    ))
                    idx += 1
                elif src == "agent" and act == "finish":
                    steps.append(TraceStep(
                        step_idx=idx, role=Role.AGENT,
                        content=args.get("thought") or args.get("message") or "",
                    ))
                    idx += 1
        return Trajectory(
            id=traj_id, task_instruction=task_instruction,
            steps=steps, source=self.name,
        )
