"""Parse `claude -p --output-format stream-json` into IAM's canonical schema.

claude-code stream-json events (the shapes we care about):

  {"type":"system","subtype":"init", ...}                # discard
  {"type":"user","message":{"role":"user","content":"..."}}                       # user msg
  {"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":..,"content":..}]}}  # tool result
  {"type":"assistant","message":{"content":[
       {"type":"text","text":"thought..."},
       {"type":"tool_use","id":"..","name":"Read","input":{...}}
  ]}}
  {"type":"result","subtype":"success","result":"...",...}

We fold the (text, tool_use) pairs from each assistant message into a single
agent TraceStep with thought + action. tool_result objects become tool steps.
"""

from __future__ import annotations

import json
from typing import Iterable, Iterator

from ...schema import Role, TraceStep, Trajectory


def parse_stream(events: Iterable[dict], task_instruction: str, traj_id: str, source: str = "claude_code") -> Trajectory:
    steps: list[TraceStep] = []
    idx = 0

    for ev in events:
        t = ev.get("type")
        if t == "system":
            continue
        if t == "user":
            msg = ev.get("message", {}) or {}
            content = msg.get("content")
            if isinstance(content, str):
                steps.append(TraceStep(step_idx=idx, role=Role.USER, content=content))
                idx += 1
            elif isinstance(content, list):
                for item in content:
                    if item.get("type") == "tool_result":
                        observation = item.get("content")
                        if isinstance(observation, list):
                            observation = "".join(
                                x.get("text", "") if isinstance(x, dict) else str(x)
                                for x in observation
                            )
                        steps.append(TraceStep(
                            step_idx=idx,
                            role=Role.TOOL,
                            observation=observation,
                        ))
                        idx += 1
            continue
        if t == "assistant":
            msg = ev.get("message", {}) or {}
            content = msg.get("content", []) or []
            thought_chunks: list[str] = []
            tool_uses: list[dict] = []
            for item in content:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "text":
                    thought_chunks.append(item.get("text", ""))
                elif item.get("type") == "tool_use":
                    tool_uses.append({
                        "tool": item.get("name"),
                        "args": item.get("input") or {},
                    })

            thought = "\n".join(c for c in thought_chunks if c).strip() or None
            if not tool_uses:
                # pure text response (final answer or just narration). Skip
                # empty assistant ticks (Claude Code emits these during stream).
                if thought is None:
                    continue
                steps.append(TraceStep(
                    step_idx=idx, role=Role.AGENT,
                    thought=thought, content=thought,
                ))
                idx += 1
            else:
                for tu in tool_uses:
                    steps.append(TraceStep(
                        step_idx=idx, role=Role.AGENT,
                        thought=thought,
                        action=tu,
                    ))
                    idx += 1
                    thought = None  # only attach the thought to the first action
            continue
        if t == "result":
            res = ev.get("result")
            if res:
                steps.append(TraceStep(step_idx=idx, role=Role.AGENT, content=res))
                idx += 1
            continue
        # unknown event types are ignored

    return Trajectory(
        id=traj_id,
        task_instruction=task_instruction,
        steps=steps,
        source=source,
    )


def iter_jsonl(path: str) -> Iterator[dict]:
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
