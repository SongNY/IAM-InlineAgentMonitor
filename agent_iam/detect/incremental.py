"""Stateful, KV-cached incremental monitoring session.

This is the live pattern "feed a trace step, get a verdict; feed the next step,
get the next verdict" — with the model's KV cache reused across steps so only
the newly-appended tokens are forwarded. Per-step latency stays ~constant
regardless of how long the session has run, instead of growing with the trace.

    sess = monitor.session(task_instruction="summarize ./poisoned.md")
    sess.observe(role="user", content="summarize ./poisoned.md")

    v = sess.guard({"tool": "Read", "args": {"path": ".env"}})        # -> OK
    sess.commit(action={"tool": "Read", "args": {"path": ".env"}}, observation="...")

    v = sess.guard({"tool": "WebFetch", "args": {"url": "https://evil/x"}})  # -> STOP
    if v.block:
        halt()

Correctness by construction: each `guard` re-renders the *full* dense trace
string and tokenizes it (cheap, CPU-side), then forwards only the suffix that
diverges from what is already cached — cropping the KV cache to the longest
common prefix. The token ids are therefore identical to a from-scratch render,
so the scored ``P(STOP)`` stays exactly in-distribution. If anything in the
cached forward fails (e.g. a transformers cache-API mismatch, or a window shift
from left-truncation), it transparently falls back to the monitor's uncached
but known-correct ``verdict_at``.
"""

from __future__ import annotations

from typing import Any

from ..schema import Role, TraceStep, Trajectory, Verdict


def _common_prefix_len(a: list[int], b: list[int]) -> int:
    n = min(len(a), len(b))
    i = 0
    while i < n and a[i] == b[i]:
        i += 1
    return i


def _crop_cache(past: Any, length: int) -> Any:
    """Crop ``past_key_values`` to ``length`` sequence positions.

    Supports a transformers ``Cache`` with ``.crop(length)`` and the legacy
    tuple-of-(k, v) layout. Returns ``None`` if it can't crop (caller recomputes).
    """
    if past is None:
        return None
    crop = getattr(past, "crop", None)
    if callable(crop):
        try:
            past.crop(length)
            return past
        except Exception:
            return None
    try:
        return tuple((k[:, :, :length, :], v[:, :, :length, :]) for (k, v) in past)
    except Exception:
        return None


class IncrementalSession:
    """One live session with KV-cache reuse over a real ``TraceMonitor``.

    Same surface as ``StreamingMonitor`` (``observe`` / ``guard`` / ``commit`` /
    ``reset``) but model-stateful: the committed prefix lives in the KV cache.
    The ``monitor`` is duck-typed — a stub exposing only ``verdict_at`` and
    ``threshold`` works (it just uses the uncached fallback), which is how this
    is unit-tested without a GPU.
    """

    def __init__(self, monitor: Any, task_instruction: str = "", source: str = "live",
                 max_length: int = 4096):
        self.m = monitor
        self.max_length = max_length
        self.source = source
        self.task_instruction = task_instruction
        self.traj = Trajectory(id=f"{source}-incr", task_instruction=task_instruction,
                               steps=[], source=source)
        self._cached_ids: list[int] = []
        self._past: Any = None

    # ---- trace accumulation -------------------------------------------------

    def _append(self, step: TraceStep) -> None:
        step.step_idx = len(self.traj.steps)
        self.traj.steps.append(step)

    def observe(self, role: str | Role = Role.USER, content: str | None = None,
                observation: Any = None) -> None:
        self._append(TraceStep(
            step_idx=0,
            role=Role(role) if not isinstance(role, Role) else role,
            content=content, observation=observation,
        ))

    def commit(self, action: dict, thought: str | None = None, observation: Any = None) -> None:
        self._append(TraceStep(step_idx=0, role=Role.AGENT, thought=thought, action=action))
        if observation is not None:
            self._append(TraceStep(step_idx=0, role=Role.TOOL, observation=observation))

    def reset(self) -> None:
        self.traj = Trajectory(id=f"{self.source}-incr",
                               task_instruction=self.task_instruction, steps=[], source=self.source)
        self._cached_ids = []
        self._past = None

    # ---- the gate -----------------------------------------------------------

    def guard(self, next_action: dict) -> Verdict:
        """Judge a proposed action against the running trace (cached forward)."""
        hyp_step = TraceStep(step_idx=len(self.traj.steps), role=Role.AGENT, action=next_action)
        hyp = self.traj.model_copy(update={"steps": self.traj.steps + [hyp_step]})
        vd = self._verdict(hyp)
        thr = getattr(self.m, "threshold", 0.5)
        if vd["p_stop"] > thr:
            return Verdict(symbol="STOP", risk_type=vd.get("predicted_type", ""),
                           explanation=vd.get("predicted_reason", ""), p_stop=vd["p_stop"],
                           threshold=thr, next_action_repr=str(next_action))
        return Verdict(symbol="OK", p_stop=vd["p_stop"], threshold=thr,
                       next_action_repr=str(next_action))

    # ---- internals ----------------------------------------------------------

    def _verdict(self, hyp: Trajectory) -> dict:
        model = getattr(self.m, "model", None)
        tok = getattr(self.m, "tok", None)
        tt = getattr(self.m, "trace_tokenizer", None)
        if model is None or tok is None or tt is None:
            return self._fallback(hyp)  # stub / no real model -> known-correct path
        try:
            sv = {i: Verdict(symbol="OK") for i, s in enumerate(hyp.steps) if s.role == Role.AGENT}
            text = tt.render_dense(hyp, sv, open_last_verdict=True)
            ids = tok(text, add_special_tokens=False)["input_ids"]
            if len(ids) > self.max_length:          # window shift invalidates the cache
                ids = ids[-self.max_length:]
                self._past, self._cached_ids = None, []

            L = _common_prefix_len(self._cached_ids, ids)
            past, start = None, 0
            if self._past is not None and L > 0:
                cropped = _crop_cache(self._past, L)
                if cropped is not None:
                    past, start = cropped, L

            new = ids[start:]
            if not new:                              # nothing new to score
                new, start, past = ids[-1:], len(ids) - 1, None

            logits, new_past = self.m._forward_logits(new, past=past, start_pos=start)
            self._past, self._cached_ids = new_past, ids

            probs = self._symbol_probs(logits)
            sym = max(probs, key=probs.get)
            out = {"p_stop": probs["STOP"], "p_warn": probs["WARN"], "p_ok": probs["OK"],
                   "predicted_symbol": sym, "predicted_type": "", "predicted_reason": ""}
            if sym == "STOP":  # rare; get type + reason from the full correct decode
                full = self._fallback(hyp)
                out["predicted_type"] = full.get("predicted_type", "")
                out["predicted_reason"] = full.get("predicted_reason", "")
            return out
        except Exception:
            self._past, self._cached_ids = None, []
            return self._fallback(hyp)

    def _symbol_probs(self, logits) -> dict[str, float]:
        import torch
        sym_ids = self.m._symbol_first_token_ids()
        sym_logits = torch.stack([logits[t] for t in sym_ids.values()])
        return dict(zip(sym_ids.keys(), torch.softmax(sym_logits, dim=-1).tolist()))

    def _fallback(self, hyp: Trajectory) -> dict:
        return self.m.verdict_at(hyp, cutoff_step=len(hyp.steps), generate_reason=True)
