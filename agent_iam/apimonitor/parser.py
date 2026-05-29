"""Robust, fail-closed parsing of the monitor's JSON output.

Safety-critical: ANY anomaly — API error upstream, refusal, missing/blank text,
fenced output, malformed JSON, missing or out-of-range fields — resolves to a
BLOCK verdict. A broken guard must stop the agent, never wave it through.
"""

from __future__ import annotations

import json
from typing import Any

from .types import CATEGORIES, VERDICTS, Verdict


class VerdictParser:
    def __init__(self, fail_closed_verdict: str = "block"):
        self.fail_closed_verdict = fail_closed_verdict

    def fail_closed(self, reason: str = "monitor_failure") -> Verdict:
        return Verdict(
            verdict=self.fail_closed_verdict,
            severity=3,
            category="other",
            reason=reason,
            remember=[],
        )

    def parse(self, response: Any) -> Verdict:
        try:
            if getattr(response, "stop_reason", None) == "refusal":
                return self.fail_closed("monitor_refusal")
            text = _extract_text(response)
            if not text or not text.strip():
                return self.fail_closed("empty_monitor_output")
            obj = _first_json_object(text)
            data = json.loads(obj)
            return _validate(data)
        except Exception:
            # No exception type escapes — fail closed on everything.
            return self.fail_closed("monitor_parse_error")


def _extract_text(response: Any) -> str:
    """Pull the assistant text out of an SDK Message (or a plain str/fake)."""
    if isinstance(response, str):
        return response
    content = getattr(response, "content", response)
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for block in content:
        if getattr(block, "type", None) == "text":
            parts.append(getattr(block, "text", "") or "")
        elif isinstance(block, dict) and block.get("type") == "text":
            parts.append(block.get("text", "") or "")
    return "".join(parts)


def _first_json_object(text: str) -> str:
    """Return the first balanced {...} object, ignoring code fences / prose."""
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object")
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
    raise ValueError("unbalanced JSON object")


def _validate(data: Any) -> Verdict:
    if not isinstance(data, dict):
        raise ValueError("not an object")
    verdict = data["verdict"]
    if verdict not in VERDICTS:
        raise ValueError("bad verdict")
    severity = data["severity"]
    if isinstance(severity, bool) or not isinstance(severity, int) or not (0 <= severity <= 3):
        raise ValueError("bad severity")
    category = data["category"]
    if category not in CATEGORIES:
        raise ValueError("bad category")
    reason = data["reason"]
    if not isinstance(reason, str):
        raise ValueError("bad reason")
    remember = data.get("remember", [])
    if not isinstance(remember, list) or not all(isinstance(x, str) for x in remember):
        raise ValueError("bad remember")
    return Verdict(
        verdict=verdict,
        severity=severity,
        category=category,
        reason=reason,
        remember=remember,
    )
