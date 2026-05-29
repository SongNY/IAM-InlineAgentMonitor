"""Claude Code CLI backend: `claude -p --output-format stream-json`."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from ....schema import Trajectory
from ..streamjson import parse_stream
from .base import AgentBackend, RunSpec


class ClaudeCodeBackend(AgentBackend):
    name = "claude_code"

    def __init__(self, claude_bin: str = "claude"):
        self.claude_bin = claude_bin

    def run(self, spec: RunSpec, output_dir: Path) -> Path:
        events_path = output_dir / "events.jsonl"
        env = os.environ.copy()
        env.update(spec.env_overrides)

        cmd = [
            self.claude_bin, "-p",
            "--output-format", "stream-json",
            "--include-partial-messages",
            "--verbose",
            "--model", spec.model or "haiku",
            "--tools", ",".join(spec.allowed_tools),
            "--add-dir", str(spec.sandbox_dir),
            "--append-system-prompt", spec.system_prompt,
            "--dangerously-skip-permissions",
            "--no-session-persistence",
            "--",
            spec.user_prompt,
        ]

        with events_path.open("w") as out_fp:
            try:
                subprocess.run(
                    cmd, cwd=spec.sandbox_dir, env=env,
                    stdout=out_fp, stderr=subprocess.DEVNULL,
                    timeout=spec.timeout_s, check=False,
                )
            except subprocess.TimeoutExpired:
                pass
        return events_path

    def parse(self, events_path: Path, task_instruction: str, traj_id: str) -> Trajectory:
        events: list[dict] = []
        with events_path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return parse_stream(events, task_instruction, traj_id, source=self.name)
