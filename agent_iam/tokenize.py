"""
Canonical tokenization for agent trajectories.

We render a trajectory into a single token stream that a causal LM can be
trained on with two objectives:

    1. Self-supervised next-action prediction on `<action ...>` spans (the
       distribution-learning objective).

    2. Supervised verdict generation in a **dense per-step** layout: a
       verdict slot is emitted after every *decision step* (an AGENT step
       with an action — the points where the monitor runs in deployment):

           <step ...></step>
           <verdict><symbol>OK</symbol></verdict>
           ...
           <step ...></step>                       # the anomaly step
           <verdict><symbol>STOP</symbol><type>...</type><reason>...</reason></verdict>

       Safe decision steps are supervised with OK (symbol only); the anomaly
       step with STOP + type + reason. This matches deployment, where the
       monitor makes an OK/STOP call at every step — so the model learns
       "don't stop here" as well as "stop here". Loss is masked outside the
       action and verdict spans.

Special control tokens (added to the tokenizer):
    <task> </task>
    <step idx=N role=R>  </step>
    <thought>  </thought>
    <action tool=T>  </action>
    <observation>  </observation>
    <content>  </content>
    <verdict>  </verdict>
    <symbol> </symbol>
    <type> </type>
    <reason> </reason>
"""

from __future__ import annotations

from dataclasses import dataclass

from .schema import Role, Trajectory, Verdict

SPECIAL_TOKENS = [
    "<task>", "</task>",
    "<step>", "</step>",
    "<thought>", "</thought>",
    "<action>", "</action>",
    "<observation>", "</observation>",
    "<content>", "</content>",
    "<verdict>", "</verdict>",
    "<symbol>", "</symbol>",
    "<type>", "</type>",
    "<reason>", "</reason>",
]


@dataclass
class EncodedSample:
    """Encoded sample with masks for the two training objectives."""

    input_ids: list[int]
    labels: list[int]                    # -100 outside the loss span
    action_token_mask: list[bool]        # True on tokens inside <action> ... </action>
    verdict_token_mask: list[bool]       # True on tokens inside <verdict> ... </verdict>


class TraceTokenizer:
    """Wraps a HF tokenizer with our trajectory rendering + masking logic."""

    def __init__(self, hf_tokenizer):
        self.tok = hf_tokenizer
        self._add_special_tokens()

    def _add_special_tokens(self) -> None:
        added = self.tok.add_special_tokens(
            {"additional_special_tokens": SPECIAL_TOKENS}
        )
        if added > 0:
            # caller is responsible for resizing model embeddings
            pass

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def render(self, traj: Trajectory, verdict: Verdict | None = None) -> str:
        """Legacy single-verdict render: trajectory + one verdict at the end.

        Kept for backward compatibility (tests, ad-hoc use). The training and
        deployment paths use `render_dense`.
        """
        head = f"<task>{traj.task_instruction}</task>"
        body = "\n".join(s.as_canonical() for s in traj.steps)
        text = head + "\n" + body
        if verdict is not None:
            text += (
                "\n<verdict>"
                f"<symbol>{verdict.symbol}</symbol>"
                f"<type>{verdict.risk_type}</type>"
                f"<reason>{verdict.explanation}</reason>"
                "</verdict>"
            )
        return text

    # ------------------------------------------------------------------
    # Dense per-step verdict rendering
    # ------------------------------------------------------------------

    @staticmethod
    def _is_decision_step(step) -> bool:
        """A decision point: any AGENT step (the points where the agent acts,
        whether via a tool call OR a content/reasoning response). The monitor
        evaluates every agent turn in deployment, so every agent step gets a
        verdict slot. Requiring an action would miss content-based anomalies
        (e.g. MRT traces whose harm is in the agent's response, not a tool
        call) — those traces have agent steps with action=None and would
        otherwise get zero STOP supervision."""
        return step.role == Role.AGENT

    @staticmethod
    def _render_verdict(v: Verdict) -> str:
        if v.symbol == "STOP":
            return (
                "<verdict>"
                f"<symbol>STOP</symbol>"
                f"<type>{v.risk_type}</type>"
                f"<reason>{v.explanation}</reason>"
                "</verdict>"
            )
        # OK / WARN: symbol only — no type/reason supervised on safe steps.
        return f"<verdict><symbol>{v.symbol}</symbol></verdict>"

    def derive_step_verdicts(self, traj: Trajectory) -> dict[int, Verdict]:
        """Map decision-step index -> Verdict, derived from the trace label.

        OK for every decision step, except the anomaly's decision step which
        gets STOP + type(failure_mode) + reason. No per-step annotation is
        needed — it all comes from the single trace-level AnomalyLabel.

        Resolving WHICH decision step gets STOP (mirrors metrics.prevented):
          - anomaly_step is itself a decision step  -> that step
          - anomaly_step is a non-decision step     -> last decision step at
            or before it
          - anomaly_step is None (anomaly not pinpointed, e.g. MRT)
            -> the last decision step (flag by end of trace)
        Without this, ~3% of anomalies (anomaly_step=None) would get all-OK
        verdicts and zero STOP supervision.
        """
        label = traj.label
        is_anom = bool(label and label.is_anomaly)
        decision_idxs = [i for i, s in enumerate(traj.steps) if self._is_decision_step(s)]

        stop_idx: int | None = None
        if is_anom and decision_idxs:
            anom = label.anomaly_step
            if anom is None:
                stop_idx = decision_idxs[-1]
            elif anom in set(decision_idxs):
                stop_idx = anom
            else:
                prior = [i for i in decision_idxs if i <= anom]
                stop_idx = prior[-1] if prior else decision_idxs[-1]

        out: dict[int, Verdict] = {}
        for i in decision_idxs:
            if i == stop_idx:
                out[i] = Verdict(
                    symbol="STOP",
                    risk_type=(label.failure_mode.value if label.failure_mode else "unknown"),
                    explanation=label.reason or "",
                )
            else:
                out[i] = Verdict(symbol="OK")
        return out

    def render_dense(
        self,
        traj: Trajectory,
        step_verdicts: dict[int, Verdict],
        open_last_verdict: bool = False,
    ) -> str:
        """Render with a verdict slot after each decision step.

        `step_verdicts`: {step_idx: Verdict} for decision steps only.
        `open_last_verdict`: if True, the LAST decision step's verdict is left
            open, ending the string at ``<verdict><symbol>`` so a model can
            complete the symbol (inference / scoring). Earlier decision steps
            still get their full (closed) verdicts.
        """
        decision_idxs = [i for i in range(len(traj.steps)) if i in step_verdicts]
        last_decision = decision_idxs[-1] if decision_idxs else None

        parts = [f"<task>{traj.task_instruction}</task>"]
        for i, s in enumerate(traj.steps):
            parts.append(s.as_canonical())
            if i in step_verdicts:
                if open_last_verdict and i == last_decision:
                    # Open the verdict and stop — we're scoring the decision at
                    # this (last) decision step; any steps after it are not part
                    # of that decision's context and would also produce malformed
                    # text after the dangling "<verdict><symbol>".
                    parts.append("<verdict><symbol>")
                    break
                parts.append(self._render_verdict(step_verdicts[i]))
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Encoding for training
    # ------------------------------------------------------------------

    def encode_for_training(
        self,
        traj: Trajectory,
        max_length: int = 4096,
        truncate_to_anomaly: bool = True,
    ) -> EncodedSample:
        """Encode a trajectory in the dense per-step verdict layout.

        Per-step verdicts are derived from the trace's AnomalyLabel (see
        `derive_step_verdicts`) — no `verdict` argument is needed. If
        `truncate_to_anomaly` is True, steps **after** the anomaly step are
        dropped: STOP is terminal, so the model is trained to intervene at the
        critical action and never sees post-anomaly steps.

        Supervision (labels != -100) covers the action spans (SSL next-action)
        and every verdict span (the dense OK/STOP decisions). `_span_mask`
        already handles multiple `<verdict>` spans, so no masking change is
        needed for the dense layout.
        """
        if (truncate_to_anomaly and traj.label and traj.label.is_anomaly
                and traj.label.anomaly_step is not None):
            cutoff = traj.label.anomaly_step
            traj = traj.model_copy(update={"steps": traj.steps[: cutoff + 1]})

        step_verdicts = self.derive_step_verdicts(traj)
        text = self.render_dense(traj, step_verdicts, open_last_verdict=False)
        enc = self.tok(text, add_special_tokens=False)
        input_ids = enc["input_ids"]
        if len(input_ids) > max_length:
            # LEFT-truncate: keep the TAIL. The dense layout puts the terminal
            # STOP verdict at the end, so HF's default right-truncation would
            # drop exactly the label we need (~4% of long attacks lost their
            # STOP otherwise). Keeping the tail preserves the anomaly + its
            # verdict and matches a deployment monitor's bounded recent-context
            # window. A partial span at the new start is simply left
            # unsupervised by _span_mask (depth never opens).
            input_ids = input_ids[-max_length:]

        action_mask = _span_mask(input_ids, self.tok, "<action>", "</action>")
        verdict_mask = _span_mask(input_ids, self.tok, "<verdict>", "</verdict>")

        labels = [
            tok if (action_mask[i] or verdict_mask[i]) else -100
            for i, tok in enumerate(input_ids)
        ]

        return EncodedSample(
            input_ids=input_ids,
            labels=labels,
            action_token_mask=action_mask,
            verdict_token_mask=verdict_mask,
        )


def _span_mask(input_ids: list[int], tok, open_str: str, close_str: str) -> list[bool]:
    """Return per-token boolean mask: True where the token sits between open/close."""
    open_ids = tok.encode(open_str, add_special_tokens=False)
    close_ids = tok.encode(close_str, add_special_tokens=False)
    mask = [False] * len(input_ids)
    depth = 0
    i = 0
    while i < len(input_ids):
        if _match(input_ids, i, open_ids):
            depth += 1
            for j in range(i, i + len(open_ids)):
                mask[j] = False  # don't include the tag tokens themselves
            i += len(open_ids)
            continue
        if _match(input_ids, i, close_ids):
            depth = max(0, depth - 1)
            for j in range(i, i + len(close_ids)):
                mask[j] = False
            i += len(close_ids)
            continue
        if depth > 0:
            mask[i] = True
        i += 1
    return mask


def _match(seq: list[int], i: int, pat: list[int]) -> bool:
    if i + len(pat) > len(seq):
        return False
    return seq[i : i + len(pat)] == pat
