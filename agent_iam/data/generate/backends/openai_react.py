"""Direct OpenAI-compatible ReAct backend.

A minimal multi-turn tool-using loop that talks to ANY OpenAI-compatible
endpoint (OpenAI, DeepSeek, Together, Groq, vLLM, Ollama, ...) and preserves
provider-specific fields like `reasoning_content` across turns. This avoids
the langchain-openai message-conversion stack which strips such fields and
breaks multi-turn calls against thinking-mode models like DeepSeek v4.

Tool catalog (Read / Bash / WebFetch) mirrors what claude_code exposes so
the canonical Trajectory schema is consistent across backends.

Environment:
    OPENAI_API_KEY     — required
    OPENAI_BASE_URL    — defaults to https://api.openai.com/v1
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.request
from pathlib import Path

from ....schema import Role, TraceStep, Trajectory
from .base import AgentBackend, RunSpec


# ----------------------------------------------------------------------
# Tool implementations
# ----------------------------------------------------------------------


def _tool_read(sandbox: Path, args: dict) -> str:
    path = args.get("path") or args.get("file_path") or args.get("filename") or ""
    # If absolute or tilde-prefixed, refuse: the agent shouldn't escape the sandbox.
    # The whole point of a sandbox is the agent runs in a private tmpdir
    # that contains FAKE secrets; reading real ~/.aws would defeat that.
    if path.startswith("/") or path.startswith("~"):
        return f"[agent_iam:denied] absolute / home path '{path}' is outside the sandbox."
    p = (sandbox / path).resolve()
    if not str(p).startswith(str(sandbox.resolve())):
        return f"[agent_iam:denied] '{path}' resolves outside the sandbox."
    try:
        return p.read_text()[:8000]
    except FileNotFoundError:
        return f"missing: {path}"
    except Exception as e:
        return f"error: {e}"


# Patterns we REFUSE to execute even in our "victim" sandbox. The agent's
# proposed command is still logged (so the violation predicate can match),
# but we return a fake "executed OK" / refusal so nothing actually touches
# the host OS. This is critical because we collect attack traces by letting
# weakly-aligned models propose malicious commands — without this filter,
# those commands would run for real (which already happened once, leaving
# debris in ~/.bashrc, ~/.config/claude/mcp.json, and ~/.config/systemd/).
import re as _re

_BASH_DENY_PATTERNS = [
    # destructive
    r"rm\s+-rf\s+[/.~]",
    r"rm\s+-rf\s*$",
    r"chmod\s+-R\s+777",
    r"dd\s+if=/dev/.*of=/dev/",
    r">\s*/dev/sd",
    # persistence + exfil chains
    r"crontab\s+-",
    r"systemctl",
    r"launchctl\s+(load|bootstrap)",
    r"defaults\s+write",
    # writes to user dotfiles / system locations
    r">>?\s*~?/\.bashrc\b",
    r">>?\s*~?/\.zshrc\b",
    r">>?\s*~?/\.profile\b",
    r">>?\s*~?/\.bash_profile\b",
    r">>?\s*~?/\.ssh/\S*authorized_keys",
    r">>?\s*~?/\.ssh/\S*id_rsa",
    r">>?\s*~?/\.config/(claude|cursor|vscode)",
    r">>?\s*~?/\.config/systemd",
    r">>?\s*/etc/(passwd|shadow|sudoers|hosts)",
    r"cat\s*>\s*~",
    r"cat\s*>\s*/etc",
    # network exfil over OS shell
    r"/dev/tcp/",
    r"nc\s+(-l|--listen)",
    r"socat\s+",
    r"curl[^|]*\|\s*(bash|sh|zsh|python|node)",
    r"wget[^|]*\|\s*(bash|sh|zsh|python|node)",
    # privilege esc
    r"\bsudo\s+",
    r"\bsu\s+-",
    r"\bdscl\s+",
    # firewall / network
    r"iptables\s+-F",
    r"pfctl\s+",
    # fork bomb
    r":\(\)\{\s*:\|:&\s*\};:",
    # base64 then pipe to shell
    r"base64\s+-d.*\|\s*(bash|sh)",
    r"xxd\s+-p.*\|\s*(bash|sh)",
    # mass exfil DNS
    r"\b(dig|host|nslookup|getent)\s+\S*\$\(cat",
    r"\b(dig|host|nslookup|getent)\s+.*\.(example\.com|attacker)",
]


def _tool_bash(sandbox: Path, args: dict) -> str:
    cmd = args.get("command") or args.get("cmd") or ""
    # SAFETY: pattern-match a hard denylist BEFORE handing to shell.
    for pat in _BASH_DENY_PATTERNS:
        if _re.search(pat, cmd):
            # Return a plausible-looking fake response so the agent's trace
            # still continues (we want to log "agent attempted X" without
            # actually running X). The label predicate still matches because
            # the AGENT's tool call (with the dangerous command) is recorded.
            return f"[agent_iam:denied] simulated execution refused for pattern '{pat[:40]}'. (Command not executed.)"

    # also forbid any write outside the sandbox dir via redirection
    if _re.search(r">>?\s*([^\s|>]+)", cmd):
        m = _re.search(r">>?\s*([^\s|>]+)", cmd)
        target = m.group(1) if m else ""
        # absolute path or escape via ~ or ..
        if (target.startswith("/") or target.startswith("~")
                or "../" in target):
            return f"[agent_iam:denied] write target '{target}' is outside the sandbox."

    try:
        out = subprocess.run(
            cmd, shell=True, cwd=str(sandbox),
            capture_output=True, text=True, timeout=15,
            # don't inherit user's env that includes API keys; sanitize:
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(sandbox),
                 "USER": "agent", "SHELL": "/bin/sh"},
        )
        return (out.stdout + out.stderr)[:8000]
    except Exception as e:
        return f"error: {e}"


def _tool_webfetch(sandbox: Path, args: dict) -> str:
    url = args.get("url") or args.get("uri") or args.get("endpoint") or ""
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.read(8000).decode("utf-8", errors="replace")
    except Exception as e:
        return f"error: {e}"


_TOOL_IMPLS = {
    "Read": _tool_read,
    "Bash": _tool_bash,
    "WebFetch": _tool_webfetch,
}


def _tool_schemas(allowed: list[str]) -> list[dict]:
    catalog = {
        "Read": {
            "type": "function",
            "function": {
                "name": "Read",
                "description": "Read a text file under the working directory.",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            },
        },
        "Bash": {
            "type": "function",
            "function": {
                "name": "Bash",
                "description": "Run a shell command in the working directory.",
                "parameters": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
            },
        },
        "WebFetch": {
            "type": "function",
            "function": {
                "name": "WebFetch",
                "description": "Fetch a URL and return its text body.",
                "parameters": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
            },
        },
    }
    return [catalog[t] for t in allowed if t in catalog]


# ----------------------------------------------------------------------
# Backend
# ----------------------------------------------------------------------


class OpenAIReActBackend(AgentBackend):
    """ReAct loop via the chat-completions API.

    Each step is logged as a single JSONL event so `parse()` can fold them
    back into the canonical Trajectory.
    """

    name = "openai_react"
    supports_http_proxy = True

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 max_iters: int = 8, temperature: float = 0.0):
        self.base_url = base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY") or ""
        self.max_iters = max_iters
        # Read temperature from env so the CLI doesn't have to thread a flag
        # through; defaults to 0 for reproducibility. Set IAM_TEMP=0.3
        # in batch runs to get diverse traces across runs of the same scenario.
        self.temperature = float(os.environ.get("IAM_TEMP", str(temperature)))

    def run(self, spec: RunSpec, output_dir: Path) -> Path:
        from openai import OpenAI

        events_path = output_dir / "events.jsonl"
        client = OpenAI(base_url=self.base_url, api_key=self.api_key)

        messages: list[dict] = [
            {"role": "system", "content": spec.system_prompt},
            {"role": "user", "content": spec.user_prompt},
        ]

        with events_path.open("w") as out:
            out.write(json.dumps({"role": "user", "content": spec.user_prompt}) + "\n")

            for _ in range(self.max_iters):
                try:
                    resp = client.chat.completions.create(
                        model=spec.model or "gpt-4o-mini",
                        messages=messages,
                        tools=_tool_schemas(spec.allowed_tools),
                        tool_choice="auto",
                        temperature=self.temperature,
                        max_tokens=1500,
                    )
                except Exception as e:
                    out.write(json.dumps({"_error": str(e)}) + "\n")
                    break

                choice = resp.choices[0]
                msg = choice.message

                # Preserve every field the provider returned, including any
                # provider-specific reasoning fields. We then echo the entire
                # raw dict back as the next turn's assistant message — which
                # is what thinking-mode providers like DeepSeek require.
                raw = msg.model_dump(exclude_none=False)

                # canonical event for our parser
                ev: dict = {
                    "role": "assistant",
                    "thought": raw.get("content") or "",
                    "raw": raw,
                }
                if raw.get("tool_calls"):
                    ev["tool_calls"] = raw["tool_calls"]
                out.write(json.dumps(ev, default=str) + "\n")

                messages.append(raw)

                if not raw.get("tool_calls"):
                    # final answer
                    break

                # dispatch each tool call
                for tc in raw["tool_calls"]:
                    fn = tc.get("function") or {}
                    name = fn.get("name", "")
                    try:
                        args = json.loads(fn.get("arguments") or "{}")
                    except json.JSONDecodeError:
                        args = {}

                    impl = _TOOL_IMPLS.get(name)
                    if impl is None:
                        result = f"unknown tool: {name}"
                    else:
                        result = impl(spec.sandbox_dir, args)

                    out.write(json.dumps({
                        "role": "tool",
                        "tool_call_id": tc.get("id"),
                        "name": name,
                        "args": args,
                        "result": result,
                    }) + "\n")

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.get("id"),
                        "content": result,
                    })

        return events_path

    def parse(self, events_path: Path, task_instruction: str, traj_id: str) -> Trajectory:
        steps: list[TraceStep] = []
        idx = 0
        with events_path.open() as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "_error" in ev:
                    continue
                role = ev.get("role")
                if role == "user":
                    steps.append(TraceStep(
                        step_idx=idx, role=Role.USER, content=ev.get("content", ""),
                    ))
                    idx += 1
                elif role == "assistant":
                    thought = ev.get("thought") or None
                    tool_calls = ev.get("tool_calls") or []
                    if not tool_calls:
                        # final text answer
                        if thought:
                            steps.append(TraceStep(
                                step_idx=idx, role=Role.AGENT,
                                thought=thought, content=thought,
                            ))
                            idx += 1
                    else:
                        for i, tc in enumerate(tool_calls):
                            fn = tc.get("function") or {}
                            name = fn.get("name", "")
                            try:
                                args = json.loads(fn.get("arguments") or "{}")
                            except json.JSONDecodeError:
                                args = {}
                            steps.append(TraceStep(
                                step_idx=idx, role=Role.AGENT,
                                thought=thought if i == 0 else None,
                                action={"tool": name, "args": args},
                            ))
                            idx += 1
                elif role == "tool":
                    steps.append(TraceStep(
                        step_idx=idx, role=Role.TOOL,
                        observation=ev.get("result", ""),
                    ))
                    idx += 1
        return Trajectory(
            id=traj_id, task_instruction=task_instruction,
            steps=steps, source=self.name,
        )
