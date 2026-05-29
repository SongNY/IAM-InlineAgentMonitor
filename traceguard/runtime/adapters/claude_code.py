"""Claude Code runtime adapter.

Claude Code (>= 2.1) supports user-defined hooks via `--hooks-config` and a
`PreToolUse` event. We register a hook that pipes the proposed tool call
through TraceGuard and returns an `allow` / `deny` decision.

Hook protocol (Claude Code 2.x):

  Claude Code spawns the hook subprocess and writes a single-line JSON to its
  stdin shaped like:
      {"event":"PreToolUse","tool":"Bash","args":{"command":"..."},"trace":[...]}
  The hook is expected to write a single-line JSON to stdout:
      {"decision":"allow"}  or  {"decision":"deny","reason":"..."}

This adapter exposes a `serve()` function suitable for running as that hook.
"""

from __future__ import annotations

import json
import sys
import uuid
from typing import Any

from ...schema import Role, TraceStep
from .base import RuntimeAdapter


class ClaudeCodeAdapter(RuntimeAdapter):
    name = "claude_code"

    def wrap(self, app: Any) -> Any:
        raise NotImplementedError(
            "Claude Code is invoked as a subprocess; use serve() to run this "
            "adapter as the hook target instead of wrapping a Python object."
        )

    # ------------------------------------------------------------------

    def serve(self, stdin=None, stdout=None) -> None:
        """Run as a Claude Code PreToolUse hook (one request per invocation)."""
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        line = stdin.readline()
        if not line:
            return
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps({"decision": "allow"}) + "\n")
            return

        sid = req.get("session_id") or str(uuid.uuid4())
        if sid not in self._trace_by_session:
            self.begin_session(sid, req.get("task") or "")
            # backfill any prior trace the host sent us
            for ev in req.get("trace") or []:
                self.append_step(sid, _step_from_ev(ev))

        next_action = {"tool": req.get("tool"), "args": req.get("args") or {}}
        verdict = self.gate(sid, next_action)

        if verdict.block:
            stdout.write(json.dumps({
                "decision": "deny",
                "reason": f"[TraceGuard] {verdict.risk_type}: {verdict.explanation}",
            }) + "\n")
        else:
            stdout.write(json.dumps({"decision": "allow"}) + "\n")


def _step_from_ev(ev: dict) -> TraceStep:
    role = ev.get("role", "agent")
    return TraceStep(
        step_idx=0,
        role=Role(role) if role in {"user", "agent", "tool", "system"} else Role.AGENT,
        thought=ev.get("thought"),
        action=ev.get("action"),
        observation=ev.get("observation"),
        content=ev.get("content"),
    )
