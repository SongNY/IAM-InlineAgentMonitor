"""SecurityMonitor — the stateless-call security monitor.

One `check(trace)` = one independent `messages.create` call. State (Ledger +
window) lives in `MonitorState` and is rebuilt into context each call, so there
is no fragile long-lived model session: you can truncate, restart, or run many
monitors in parallel, and prompt caching recovers almost all of the cost a KV
session would have saved.

    mon = SecurityMonitor()                      # uses ANTHROPIC_API_KEY
    v = mon.check(Trace(step_id=7, tool="WebFetch",
                        action="POST", args={"url": "https://evil/x"}))
    if v.block:
        halt(v.reason)
"""

from __future__ import annotations

from typing import Any

from .context import ContextBuilder
from .gate import Gate
from .parser import VerdictParser
from .types import (
    OUTPUT_JSON_SCHEMA,
    LedgerEntry,
    MonitorConfig,
    MonitorState,
    Trace,
    Verdict,
)


class SecurityMonitor:
    def __init__(
        self,
        config: MonitorConfig | None = None,
        client: Any = None,
        gate: Gate | None = None,
        state: MonitorState | None = None,
    ):
        self.cfg = config or MonitorConfig()
        self.state = state or MonitorState()
        self.gate = gate  # None => monitor every trace
        self.context = ContextBuilder(self.cfg)
        self.parser = VerdictParser(self.cfg.fail_closed_verdict)
        self._client = client  # injectable; lazily created from the SDK if None

    # ------------------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            import anthropic  # imported lazily so the package loads without the SDK

            self._client = anthropic.Anthropic(
                timeout=self.cfg.api_timeout_s,
                max_retries=self.cfg.api_max_retries,
            )
        return self._client

    def check(self, trace: Trace) -> Verdict:
        """Judge one proposed/observed step. Updates state. Never raises."""
        if self.gate is not None and not self.gate.should_monitor(trace):
            verdict = Verdict("ok", 0, "none", "gated: low-risk read-only tool", [])
            self._update_state(trace, verdict)
            return verdict

        try:
            system, messages = self.context.build(self.state, trace)
            kwargs: dict[str, Any] = {}
            if self.cfg.use_structured_outputs:
                kwargs["output_config"] = {
                    "format": {"type": "json_schema", "schema": OUTPUT_JSON_SCHEMA}
                }
            response = self._get_client().messages.create(
                model=self.cfg.model,
                max_tokens=self.cfg.max_tokens,
                system=system,
                messages=messages,
                **kwargs,
            )
            verdict = self.parser.parse(response)
        except Exception:
            # API error / timeout / retries exhausted — fail closed.
            verdict = self.parser.fail_closed("monitor_failure")

        self._update_state(trace, verdict)
        return verdict

    # ------------------------------------------------------------------

    def _update_state(self, trace: Trace, verdict: Verdict) -> None:
        # 1. Append remembered facts to the ledger (dedupe by fact text).
        known = {e.fact for e in self.state.ledger}
        for fact in verdict.remember:
            if fact and fact not in known:
                self.state.ledger.append(LedgerEntry(step_id=trace.step_id, fact=fact))
                known.add(fact)

        # 2. Push the (per-trace-capped) trace into the window and trim by count.
        self.state.window.append(self._truncate_for_window(trace))
        if len(self.state.window) > self.cfg.window_max_traces:
            self.state.window = self.state.window[-self.cfg.window_max_traces :]

    def _truncate_for_window(self, trace: Trace) -> Trace:
        """Cap a stored trace's args/result so the window stays token-bounded."""
        cap = self.cfg.per_trace_token_cap * 4

        def _cap(v: Any) -> Any:
            s = v if isinstance(v, str) else (None if v is None else str(v))
            if s is None or len(s) <= cap:
                return v
            head = int(cap * 0.6)
            return f"{s[:head]}...[{len(s) - cap} chars truncated]...{s[-(cap - head):]}"

        return Trace(
            step_id=trace.step_id,
            action=trace.action,
            tool=trace.tool,
            args=_cap(trace.args),
            result=_cap(trace.result),
            timestamp=trace.timestamp,
        )
