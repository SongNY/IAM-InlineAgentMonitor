"""
ATBench loader → TraceGuard canonical Trajectory schema.

ATBench (AI45Research/ATBench, Apache 2.0) is the cornerstone training source:
  - 1000 trajectories, 503 safe / 497 unsafe
  - Per-trajectory label: {label, risk_source, failure_mode, harm, reason}
  - Average 9 turns, 2084 unique tools

We map ATBench's enum strings to TraceGuard's enums where possible and fall
back to OTHER / NONE when not.
"""

from __future__ import annotations

import json
from typing import Any, Iterator

from ..schema import (
    AnomalyLabel,
    FailureMode,
    HarmCategory,
    RiskSource,
    Role,
    TraceStep,
    Trajectory,
)


_RISK_SOURCE_MAP = {
    "user_prompt_injection": RiskSource.USER_PROMPT_INJECTION,
    "tool_description_injection": RiskSource.TOOL_DESCRIPTION_INJECTION,
    "indirect_prompt_injection": RiskSource.INDIRECT_PROMPT_INJECTION,
    "corrupted_tool_feedback": RiskSource.CORRUPTED_TOOL_FEEDBACK,
    "agent_hallucination": RiskSource.AGENT_HALLUCINATION,
    "over_agency": RiskSource.OVER_AGENCY,
    "misconfigured_permission": RiskSource.MISCONFIGURED_PERMISSION,
    "ambiguous_instruction": RiskSource.AMBIGUOUS_INSTRUCTION,
}

_FAILURE_MODE_MAP = {
    "unauthorized_disclosure": FailureMode.UNAUTHORIZED_DISCLOSURE,
    "data_exfiltration": FailureMode.DATA_EXFILTRATION,
    "unauthorized_action": FailureMode.UNAUTHORIZED_ACTION,
    "destructive_action": FailureMode.DESTRUCTIVE_ACTION,
    "privilege_escalation": FailureMode.PRIVILEGE_ESCALATION,
    "provide_inaccurate_misleading_or_unverified_information": FailureMode.MISLEADING_INFORMATION,
    "provide_inaccurate_misleading_information": FailureMode.MISLEADING_INFORMATION,
    "instruction_for_harmful_activity": FailureMode.INSTRUCTION_FOR_HARM,
    "resource_exhaustion": FailureMode.RESOURCE_EXHAUSTION,
    "failed_refusal": FailureMode.FAILED_REFUSAL,
    "hallucinated_tool_use": FailureMode.HALLUCINATED_TOOL_USE,
    "chain_hijack": FailureMode.CHAIN_HIJACK,
    "side_effect_leak": FailureMode.SIDE_EFFECT_LEAK,
    "poisoned_memory": FailureMode.POISONED_MEMORY,
}


def load_atbench(split: str = "test", subset: str = "ATBench") -> Iterator[Trajectory]:
    """Yield TraceGuard `Trajectory` objects from ATBench.

    Requires `pip install datasets` and a network connection (or HF cache).
    """
    from datasets import load_dataset

    ds = load_dataset("AI45Research/ATBench", subset, split=split)
    for row in ds:
        yield _row_to_trajectory(row)


def _row_to_trajectory(row: dict) -> Trajectory:
    """Convert one ATBench row to a Trajectory.

    ATBench rows store the conversation under `contents` which is a list of
    dicts; each dict can have `role`, `content` (which may be a STRING or a
    LIST of message-part dicts each with their own role/content/tool_calls
    — OpenAI-style), and optionally `tool_used` / etc.
    """
    raw_contents = row.get("contents") or []
    # ATBench wraps the conversation in an extra list; unwrap.
    if raw_contents and isinstance(raw_contents[0], list):
        raw_contents = raw_contents[0]
    steps: list[TraceStep] = []
    idx = 0
    for msg in raw_contents:
        if not isinstance(msg, dict):
            continue
        role = _role_from_str(msg.get("role"))
        content = msg.get("content")
        # content can be a string OR a list of parts (multi-message blob).
        # Multi-part: each part is one canonical step.
        if isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    # treat as literal observation
                    steps.append(TraceStep(step_idx=idx, role=role, content=str(part)[:1000]))
                    idx += 1
                    continue
                part_role = _role_from_str(part.get("role")) if part.get("role") else role
                steps.append(TraceStep(
                    step_idx=idx,
                    role=part_role,
                    thought=part.get("thought"),
                    action=_extract_action(part),
                    observation=part.get("observation"),
                    content=str(part.get("content") or "")[:1000] or None,
                ))
                idx += 1
        else:
            steps.append(TraceStep(
                step_idx=idx,
                role=role,
                thought=msg.get("thought"),
                action=_extract_action(msg),
                observation=msg.get("observation"),
                content=str(content)[:1000] if content else None,
            ))
            idx += 1

    label_row = row.get("label", 0)
    label: AnomalyLabel | None = None
    if label_row is not None:
        anomaly_step = _find_anomaly_step(row, steps)
        label = AnomalyLabel(
            is_anomaly=bool(label_row),
            anomaly_step=anomaly_step if label_row else None,
            risk_source=_RISK_SOURCE_MAP.get(row.get("risk_source") or ""),
            failure_mode=_FAILURE_MODE_MAP.get(row.get("failure_mode") or ""),
            harm_category=_harm_from_str(row.get("harm") or row.get("harm_category")),
            reason=row.get("reason"),
        )

    instruction = ""
    first_user = next((s for s in steps if s.role == Role.USER and s.content), None)
    if first_user:
        instruction = (first_user.content or "")[:500]

    return Trajectory(
        id=str(row.get("id")),
        task_instruction=instruction,
        steps=steps,
        label=label,
        source="atbench",
    )


def _role_from_str(s: str | None) -> Role:
    if s == "user":
        return Role.USER
    if s in ("agent", "assistant"):
        return Role.AGENT
    if s == "tool":
        return Role.TOOL
    return Role.SYSTEM


def _parse_args(raw: Any) -> dict:
    """Coerce an OpenAI-style arguments blob into a dict.

    `arguments` in tool-call payloads is usually a JSON *string*; sometimes
    already a dict. Anything unparseable is wrapped so the content survives
    into the canonical render instead of being dropped.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {"_raw": raw}
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    return {"value": raw} if raw is not None else {}


def _extract_action(msg: dict) -> dict | None:
    """Normalize an ATBench message's action into `{tool, args}`.

    ATBench is OpenAI-style: actions arrive either as a `tool_calls` list
    ([{function: {name, arguments}}]) or as an `action` object. The canonical
    renderer (`TraceStep.as_canonical`) only reads `action['tool']` and
    `action['args']`, so we must map into that shape here — otherwise every
    such step renders as the empty `<action>?({})</action>` and the model
    trains/evaluates on blank actions.
    """
    tcs = msg.get("tool_calls")
    if tcs:
        first = tcs[0] if isinstance(tcs, list) and tcs else tcs
        if isinstance(first, dict):
            fn = first.get("function") if isinstance(first.get("function"), dict) else first
            name = fn.get("name") or fn.get("tool") or "?"
            return {"tool": name, "args": _parse_args(fn.get("arguments", fn.get("args", {})))}

    act = msg.get("action")
    if act:
        if isinstance(act, dict):
            name = act.get("tool") or act.get("name") or act.get("type")
            raw_args = act.get("args", act.get("arguments", act.get("input")))
            if name is None and raw_args is None:
                # Unknown shape — stash the whole dict so nothing is lost.
                return {"tool": "action", "args": act}
            return {"tool": name or "?", "args": _parse_args(raw_args)}
        if isinstance(act, str):
            # ATBench commonly stores the action as a JSON *string* encoding
            # {name, arguments}, sometimes with a bare tool-name prefix, e.g.
            #   '{"name": "get_seller_info", "arguments": {...}}'
            #   'Complete{"response": "..."}'
            s = act.strip()
            brace = s.find("{")
            if brace >= 0:
                prefix = s[:brace].strip()
                try:
                    obj = json.loads(s[brace:])
                except (json.JSONDecodeError, ValueError):
                    obj = None
                if isinstance(obj, dict):
                    name = obj.get("name") or obj.get("tool") or prefix or "?"
                    raw_args = obj.get("arguments", obj.get("args"))
                    # No explicit args key -> treat the remaining object as args.
                    if raw_args is None:
                        raw_args = {k: v for k, v in obj.items() if k not in ("name", "tool")}
                    return {"tool": name, "args": _parse_args(raw_args)}
            # Not JSON — treat the whole string as the tool token.
            return {"tool": s, "args": {}}

    return None


def _harm_from_str(s: str | None) -> HarmCategory | None:
    if not s:
        return None
    try:
        return HarmCategory(s)
    except ValueError:
        return HarmCategory.NONE


def _find_anomaly_step(row: dict, steps: list[TraceStep]) -> int | None:
    """ATBench labels at trajectory level; we heuristically pick the step where
    the unsafe action happens by looking at `reason` or last agent step."""
    # If ATBench provides explicit step index in some future version, prefer that.
    for explicit in ("anomaly_step", "violation_step", "unsafe_step"):
        if explicit in row and row[explicit] is not None:
            return int(row[explicit])
    # Fallback: last agent step (the violating action is usually terminal).
    for s in reversed(steps):
        if s.role == Role.AGENT:
            return s.step_idx
    return None
