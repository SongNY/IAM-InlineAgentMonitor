"""
Online TraceMonitor: PPL-based mid-trace intervention.

Usage inside an agent executor loop:

    monitor = TraceMonitor.from_pretrained("Sunnyu/TraceGuard-Qwen3.5-2B")

    for step in agent_iter:
        verdict = monitor.check(trace_so_far, next_action=step.proposed_action)
        if verdict.block:
            raise SecurityError(verdict.risk_type, verdict.explanation)
        actual = step.execute()
        trace_so_far.append(...)
"""

from __future__ import annotations

import math
from typing import Any

import torch

from ..schema import Trajectory, TraceStep, Role, Verdict
from ..tokenize import TraceTokenizer


class TraceMonitor:
    def __init__(
        self,
        model,
        tokenizer,
        threshold: float = 0.5,             # P(STOP) threshold for check(); calibrate per deployment
        device: str | None = None,
    ):
        self.model = model
        # TraceTokenizer mutates `tokenizer` in place, adding TraceGuard's
        # special tokens; `self.tok` is the same (now-extended) object.
        self.trace_tokenizer = TraceTokenizer(tokenizer)
        self.tok = tokenizer

        # Resize the model's embedding matrix if the tokenizer now has more
        # tokens than the model knows about. Without this, loading a base HF
        # model (e.g. the `untrained_lm` baseline) and feeding it the new
        # special-token IDs raises an embedding index error. A trained
        # TraceGuard checkpoint already has these rows, so the sizes match
        # and this is a no-op.
        try:
            emb = self.model.get_input_embeddings()
            if emb is not None and emb.num_embeddings < len(self.tok):
                self.model.resize_token_embeddings(len(self.tok))
        except (AttributeError, NotImplementedError):
            pass

        self.threshold = threshold
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.model.eval()

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_pretrained(cls, model_id: str, **kwargs):
        from transformers import AutoModelForCausalLM, AutoTokenizer

        tok = AutoTokenizer.from_pretrained(model_id)
        model = AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.bfloat16)
        return cls(model=model, tokenizer=tok, **kwargs)

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    @torch.inference_mode()
    def check(
        self,
        trace_so_far: Trajectory,
        next_action: dict[str, Any],
    ) -> Verdict:
        """Return a Verdict for `next_action` given the prior trace.

        Production path (dense verdict head): renders the trace in the dense
        per-step layout — an OK verdict after every prior decision step, then
        the proposed action with an OPEN verdict — and reads
        P(<symbol>STOP</symbol>) from the next-token logits. Prior decision
        steps are OK because if any earlier step had been STOP, execution
        would have halted there (so this matches the dense training prefix).
        Only generates type/reason when P(STOP) crosses the threshold.
        """
        hyp_step = TraceStep(
            step_idx=len(trace_so_far.steps),
            role=Role.AGENT,
            action=next_action,
        )
        hyp_traj = trace_so_far.model_copy(update={"steps": trace_so_far.steps + [hyp_step]})

        sv = {
            i: Verdict(symbol="OK")
            for i, s in enumerate(hyp_traj.steps)
            if s.role == Role.AGENT
        }
        text = self.trace_tokenizer.render_dense(hyp_traj, sv, open_last_verdict=True)
        vd = self._verdict_from_text(text, generate_reason=True)

        if vd["p_stop"] > self.threshold:
            return Verdict(
                symbol="STOP",
                risk_type=vd["predicted_type"],
                explanation=vd["predicted_reason"],
                p_stop=vd["p_stop"],
                threshold=self.threshold,
                next_action_repr=str(next_action),
            )
        return Verdict(
            symbol="OK",
            p_stop=vd["p_stop"],
            threshold=self.threshold,
            next_action_repr=str(next_action),
        )

    @torch.inference_mode()
    def ppl_score(
        self,
        trace_so_far: Trajectory,
        next_action: dict[str, Any],
    ) -> float:
        """Legacy action-span perplexity for the proposed action.

        Higher PPL = more anomalous. Retained so `monitor_scorer` can run as a
        baseline against the verdict-head P(STOP) approach. Not used by the
        production `check()` path anymore.
        """
        hyp_step = TraceStep(
            step_idx=len(trace_so_far.steps),
            role=Role.AGENT,
            action=next_action,
        )
        hyp_traj = trace_so_far.model_copy(update={"steps": trace_so_far.steps + [hyp_step]})
        text = self.trace_tokenizer.render(hyp_traj)
        enc = self.tok(text, return_tensors="pt").to(self.device)
        with self._autocast():
            out = self.model(**enc)
        return self._action_span_ppl(enc["input_ids"][0], out.logits[0])

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _action_span_ppl(self, input_ids: torch.Tensor, logits: torch.Tensor) -> float:
        """PPL restricted to tokens inside the last <action> ... </action> span."""
        from ..tokenize import _span_mask  # type: ignore

        mask = _span_mask(input_ids.tolist(), self.tok, "<action>", "</action>")
        # Locate the LAST <action>...</action> span (the hypothetical action).
        # _span_mask marks only the tokens strictly *inside* the tags, so the
        # last True index is the final in-span content token.
        last_true = None
        for i in range(len(mask) - 1, -1, -1):
            if mask[i]:
                last_true = i
                break
        if last_true is None:
            return 0.0
        start = last_true
        while start > 0 and mask[start - 1]:
            start -= 1

        # End is exclusive and stops right after the last in-span token, so
        # the closing </action> / </step> and anything after the action don't
        # leak into the PPL (they're predictable structural tokens that would
        # otherwise dilute the anomaly signal and skew STOP/OK decisions).
        end = last_true + 1
        # shift for next-token loss
        shift_logits = logits[start - 1 : end - 1]
        shift_labels = input_ids[start:end]
        loss = torch.nn.functional.cross_entropy(
            shift_logits, shift_labels, reduction="mean"
        )
        return float(math.exp(loss.item()))

    @torch.inference_mode()
    def _generate_verdict(self, prefix: str) -> tuple[str, str]:
        prompt = prefix + "\n<verdict>"
        enc = self.tok(prompt, return_tensors="pt").to(self.device)
        out = self.model.generate(
            **enc,
            max_new_tokens=128,
            do_sample=False,
            pad_token_id=self.tok.eos_token_id,
        )
        decoded = self.tok.decode(out[0][enc["input_ids"].shape[1] :])
        risk_type = _between(decoded, "<type>", "</type>")
        reason = _between(decoded, "<reason>", "</reason>")
        return risk_type, reason

    # ------------------------------------------------------------------
    # Verdict-head scoring (matches training-time supervision)
    # ------------------------------------------------------------------

    def _autocast(self):
        # bf16 autocast on cuda; safe-noop on cpu via the AMP entrypoint.
        dev = self.device
        if isinstance(dev, str) and dev.startswith("cuda"):
            return torch.autocast(device_type="cuda", dtype=torch.bfloat16)
        return torch.amp.autocast(device_type="cpu", dtype=torch.bfloat16)

    def _symbol_first_token_ids(self) -> dict[str, int]:
        # Cache the first-token id of each verdict symbol string. We only
        # need the first token for the next-token logit comparison; if the
        # symbol is multi-token (rare for short uppercase strings in BPE),
        # comparing first tokens is a reasonable proxy.
        if not hasattr(self, "_sym_first_ids"):
            self._sym_first_ids = {
                s: self.tok.encode(s, add_special_tokens=False)[0]
                for s in ("OK", "WARN", "STOP")
            }
        return self._sym_first_ids

    @torch.inference_mode()
    def _verdict_from_text(
        self,
        text: str,
        generate_reason: bool = True,
        max_reason_tokens: int = 96,
        max_length: int = 4096,
    ) -> dict[str, Any]:
        """Score a verdict from a prompt that ends with ``<verdict><symbol>``.

        Reads the next-token logits, softmaxes over the first tokens of
        {OK, WARN, STOP}, and (if STOP is argmax and generate_reason) greedily
        decodes <type>/<reason>. Shared by `check` and `verdict_at`.

        Left-truncates to ``max_length`` (keeps the TAIL) so the open
        ``<verdict><symbol>`` at the end always survives and the model sees a
        bounded recent-context window — matching the dense training-time
        truncation.

        Returns: p_stop, p_warn, p_ok, predicted_symbol, predicted_type,
        predicted_reason.
        """
        ids = self.tok(text, add_special_tokens=False)["input_ids"]
        if len(ids) > max_length:
            ids = ids[-max_length:]
        enc = {
            "input_ids": torch.tensor([ids], device=self.device),
            "attention_mask": torch.ones(1, len(ids), dtype=torch.long, device=self.device),
        }
        with self._autocast():
            out = self.model(**enc)
        next_logits = out.logits[0, -1].float()

        sym_ids = self._symbol_first_token_ids()
        sym_logits = torch.stack([next_logits[t] for t in sym_ids.values()])
        probs = dict(zip(sym_ids.keys(), torch.softmax(sym_logits, dim=-1).tolist()))
        predicted_symbol = max(probs, key=probs.get)

        predicted_type = ""
        predicted_reason = ""
        if generate_reason and predicted_symbol == "STOP":
            # Reuse the left-truncated ids + the just-chosen "STOP" + the
            # closing </symbol>, then let the model decode <type>/<reason>.
            cont_ids = ids + self.tok.encode("STOP</symbol>", add_special_tokens=False)
            cont_enc = {
                "input_ids": torch.tensor([cont_ids], device=self.device),
                "attention_mask": torch.ones(1, len(cont_ids), dtype=torch.long, device=self.device),
            }
            cont_out = self.model.generate(
                **cont_enc,
                max_new_tokens=max_reason_tokens,
                do_sample=False,
                pad_token_id=self.tok.pad_token_id or self.tok.eos_token_id,
            )
            decoded = self.tok.decode(cont_out[0][len(cont_ids):])
            predicted_type = _between(decoded, "<type>", "</type>")
            predicted_reason = _between(decoded, "<reason>", "</reason>")

        return {
            "p_stop": probs["STOP"],
            "p_warn": probs["WARN"],
            "p_ok": probs["OK"],
            "predicted_symbol": predicted_symbol,
            "predicted_type": predicted_type,
            "predicted_reason": predicted_reason,
        }

    @torch.inference_mode()
    def verdict_at(
        self,
        traj: Trajectory,
        cutoff_step: int,
        generate_reason: bool = True,
        max_reason_tokens: int = 96,
    ) -> dict[str, Any]:
        """Score the verdict at a cutoff, in the dense per-step layout.

        The model sees ``traj.steps[:cutoff_step]`` rendered densely — each
        prior decision step carries an OK verdict, and the LAST decision step
        in that prefix has its verdict opened at ``<verdict><symbol>`` for the
        model to complete. This matches the dense training format (so the
        scored P(STOP) is in-distribution). If the prefix has no decision step
        there is nothing to score and we return a degenerate OK.

        Returns the same dict as `_verdict_from_text`.
        """
        truncated = traj.model_copy(update={"steps": traj.steps[:cutoff_step]})
        sv = {
            i: Verdict(symbol="OK")
            for i, s in enumerate(truncated.steps)
            if s.role == Role.AGENT
        }
        if not sv:
            return {
                "p_stop": 0.0, "p_warn": 0.0, "p_ok": 1.0,
                "predicted_symbol": "OK",
                "predicted_type": "", "predicted_reason": "",
            }
        text = self.trace_tokenizer.render_dense(truncated, sv, open_last_verdict=True)
        return self._verdict_from_text(
            text, generate_reason=generate_reason, max_reason_tokens=max_reason_tokens
        )

    @torch.inference_mode()
    def embed_text(self, text: str) -> torch.Tensor:
        """Mean-pooled, L2-normalized last-hidden-state embedding of ``text``.

        Uses the trained model so embeddings reflect the verdict-supervision
        signal — relevant for reason similarity since the model has seen
        many label.reason strings during training.

        Calls the inner transformer (``self.model.model``) directly when
        available so we (a) skip the ~500MB lm_head matmul and (b) get
        ``last_hidden_state`` as a single tensor instead of holding all 24
        intermediate layer outputs via ``output_hidden_states=True``.
        Falls back to the full forward path when the inner module isn't
        exposed (e.g. some Unsloth wrapper variants).
        """
        if not text:
            hidden = self.model.config.hidden_size
            return torch.zeros(hidden, device=self.device)
        enc = self.tok(
            text, return_tensors="pt", add_special_tokens=False, truncation=True,
            max_length=256,
        ).to(self.device)

        inner = getattr(self.model, "model", None)
        with self._autocast():
            if inner is not None:
                out = inner(**enc)
                last = (
                    out.last_hidden_state[0].float()
                    if hasattr(out, "last_hidden_state")
                    else out[0][0].float()
                )
            else:
                out = self.model(**enc, output_hidden_states=True)
                last = out.hidden_states[-1][0].float()

        mask = enc["attention_mask"][0].float().unsqueeze(-1)   # [seq, 1]
        pooled = (last * mask).sum(0) / mask.sum().clamp(min=1)
        return torch.nn.functional.normalize(pooled, dim=-1)


def _between(s: str, lo: str, hi: str) -> str:
    a = s.find(lo)
    if a < 0:
        return ""
    a += len(lo)
    b = s.find(hi, a)
    return s[a:b] if b > a else s[a:].strip()
