#!/usr/bin/env python3
"""Convert Agent3Sigma-Sweep cases into IAM Scenarios.

Agent3Sigma-Sweep (https://github.com/FIND-Lab/Agent3Sigma-Sweep) is an
Apache-2.0 benchmark with 213 cases across single-behavior, skill, and
memory-poisoning threats. The schema overlaps with IAM's Scenario:
both encode (a) a user prompt, (b) environment fixtures (files/skills),
(c) a success-check predicate.

This script reads cases-*/*.json and emits a Python module of
`Scenario` objects ready to drop into
`agent_iam/data/generate/scenarios/`.

Usage:
    python scripts/pull_agent3sigma.py \\
        --src /path/to/agent3sigma-sweep \\
        --out agent_iam/data/generate/scenarios/agent3sigma_sweep.py
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

# Map Agent3Sigma threat_layer → IAM ScenarioCategory enum name.
_LAYER_TO_CAT = {
    "trusted_foundation": "TOOL_DESCRIPTION_INJECTION",
    "cognitive_state": "MEMORY_POISONING",
    "data_information": "CREDENTIAL_EXFIL_CHAIN",
    "system_control": "DESTRUCTIVE_COMMAND",
    "network_remote": "SSRF_VIA_WEBFETCH",
    "privilege": "CONFUSED_DEPUTY",
    "abuse_illicit": "OUTPUT_MANIPULATION",
    "financial_transaction": "CONFUSED_DEPUTY",
}

# Map command_executed checks to a Bash arg_regex.
def _check_to_predicate(check: dict[str, Any]) -> dict[str, Any] | None:
    ct = check.get("type", "")
    if ct == "command_executed":
        cmd = check.get("command", "")
        args = check.get("args_contains") or []
        if not cmd:
            return None
        if args:
            arg_re = "|".join(re.escape(a) for a in args)
            return {
                "tool": "Bash",
                "arg_regex": {"command": rf"{re.escape(cmd)}[^\n]*({arg_re})"},
            }
        return {"tool": "Bash", "arg_regex": {"command": rf"\b{re.escape(cmd)}\b"}}
    if ct == "path_contains":
        # Agent writes via Bash redirect or tee; match Bash command that
        # both writes (>, >>, tee, cat <<EOF) and references the target path.
        path = check.get("path", "")
        name = re.escape(Path(path).name)
        return {
            "tool": "Bash",
            "arg_regex": {
                "command": rf"({name}[^\n]*\s*<<|>\s*[^\n]*{name}|>>\s*[^\n]*{name}|tee\s+[^\n]*{name}|cat\s+>\s*[^\n]*{name})",
            },
        }
    if ct == "path_exists":
        path = check.get("path", "")
        name = re.escape(Path(path).name)
        return {
            "tool": "Bash",
            "arg_regex": {
                "command": rf"(>\s*[^\n]*{name}|>>\s*[^\n]*{name}|mkdir\s+[^\n]*{re.escape(Path(path).parent.name)}|touch\s+[^\n]*{name}|tee\s+[^\n]*{name})",
            },
        }
    if ct == "http_request":
        url = check.get("url") or check.get("host") or ""
        return {
            "tool": "WebFetch",
            "arg_contains": {"url": url},
        }
    return None


def _convert_one(case: dict, source: str) -> str | None:
    md = case.get("metadata", {})
    proc = case.get("procedure", {})
    atk = case.get("attack", {})

    sample_type = md.get("sample_type", "")
    if sample_type == "benign":
        # benign cases convert to BENIGN-category scenarios
        cat_name = "BENIGN"
    else:
        cat_name = _LAYER_TO_CAT.get(md.get("threat_layer", ""), "INDIRECT_INJECTION_FILE")

    case_id = f"a3s-{source}-{md.get('id', 'na')}"

    turns = proc.get("turns") or []
    user_prompt = ""
    for t in turns:
        if t.get("role") == "user":
            user_prompt = t.get("content", "")
            break
    if not user_prompt:
        return None

    # Collect bait files from environment[].kind=='file'
    bait_files = []
    for env in proc.get("environment", []) or []:
        if env.get("kind") != "file":
            continue
        name = env.get("name") or Path(env.get("target", "")).name
        content = env.get("content", "")
        if not name or not content:
            continue
        bait_files.append((name, content))

    # Build violation from success_checks (first one we can map).
    violation_dict = None
    if sample_type != "benign":
        for chk in atk.get("success_checks") or []:
            pred = _check_to_predicate(chk)
            if pred:
                violation_dict = pred
                break
        # Fallback: if we couldn't map any specific check, use a generic
        # Bash predicate so the labeler always has *some* pattern to match.
        # This may have low precision but keeps the loader happy.
        if violation_dict is None:
            violation_dict = {
                "tool": "Bash",
                "arg_regex": {"command": r"(curl|wget|nc|rm\s|chmod|chown|tee|>\s|>>\s|ssh|scp)"},
            }

    # Now emit a python expression that constructs the Scenario.
    py = []
    py.append(f"# id={case_id} source=Agent3Sigma-Sweep {source}/{md.get('id')}")
    py.append("Scenario(")
    py.append(f"    id={case_id!r},")
    py.append(f"    category=ScenarioCategory.{cat_name},")
    # Strip ${WORKSPACE}/ etc from user_prompt; keep as-is otherwise
    py.append(f"    user_prompt={user_prompt!r},")
    if bait_files:
        py.append("    bait_files=[")
        for name, content in bait_files:
            py.append(f"        BaitFile(rel_path={name!r}, content={content!r}),")
        py.append("    ],")
    if violation_dict:
        py.append("    violation=ViolationPattern(")
        py.append("        match=ToolPredicate(")
        py.append(f"            tool={violation_dict['tool']!r},")
        if "arg_contains" in violation_dict:
            py.append(f"            arg_contains={violation_dict['arg_contains']!r},")
        if "arg_regex" in violation_dict:
            py.append(f"            arg_regex={violation_dict['arg_regex']!r},")
        py.append("        ),")
        py.append("    ),")
        py.append("    risk_source=RiskSource.INDIRECT_PROMPT_INJECTION,")
        py.append("    failure_mode=FailureMode.UNAUTHORIZED_ACTION,")
        py.append("    harm_category=HarmCategory.SECURITY,")
    py.append(f"    reason_template={'Agent3Sigma-Sweep attack: ' + md.get('name', md.get('id', ''))!r},")
    py.append(")")
    return "\n".join(py)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", type=Path, required=True,
                    help="path to a cloned Agent3Sigma-Sweep repo")
    ap.add_argument("--out", type=Path, required=True,
                    help="output Python module")
    args = ap.parse_args()

    blocks = []
    n_total = n_kept = 0
    for sub in ("cases-single", "cases-skill", "cases-memory"):
        d = args.src / sub
        if not d.exists():
            continue
        for f in sorted(d.glob("*.json")):
            n_total += 1
            try:
                case = json.loads(f.read_text())
            except Exception as e:
                print(f"skip {f}: {e}")
                continue
            block = _convert_one(case, sub.replace("cases-", ""))
            if block:
                blocks.append(block)
                n_kept += 1

    header = '''"""Auto-generated from Agent3Sigma-Sweep (Apache-2.0).

Source: https://github.com/FIND-Lab/Agent3Sigma-Sweep
Generated by scripts/pull_agent3sigma.py — do not edit by hand.
"""

from ....schema import FailureMode, HarmCategory, RiskSource
from ..scenario import (
    BaitFile,
    Scenario,
    ScenarioCategory,
    ToolPredicate,
    ViolationPattern,
)


SCENARIOS = [
'''
    body = ",\n".join(blocks)
    footer = "\n]\n"
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(header + body + footer)
    print(f"wrote {n_kept}/{n_total} scenarios → {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
