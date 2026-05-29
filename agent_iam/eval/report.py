"""Render evaluation reports from one or more scores.jsonl files.

Emits:
  - report.md   — human-readable summary, headline metric + per-slice tables
  - slices.csv  — machine-readable per-slice numbers
  - pr_fsr.png  — PR vs FSR curve with every scorer overlaid (optional;
                  silently skipped if matplotlib isn't available)

Each scores.jsonl is treated as one "scorer" (a row in the headline table).
The display name is the parent directory of the jsonl by default, e.g.
`runs-eval/<name>/scores.jsonl` becomes `<name>`.
"""

from __future__ import annotations

import csv
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .metrics import (
    Sweep,
    TraceResult,
    auroc,
    best_f1,
    pr_at_fsr,
    slice_by,
    sweep,
)
from .runner import load_results


@dataclass
class ScorerReport:
    name: str
    n_traces: int
    n_attacks: int
    n_benign: int
    auroc: float
    pr_at_fsr_001: float
    pr_at_fsr_005: float
    pr_at_fsr_010: float
    best_f1: float
    best_f1_threshold: float | None
    sweep: Sweep
    results: list[TraceResult]


def evaluate_one(name: str, results: list[TraceResult]) -> ScorerReport:
    s = sweep(results)
    n_attacks = sum(1 for r in results if r.is_anomaly)
    f1 = best_f1(s, results)
    return ScorerReport(
        name=name,
        n_traces=len(results),
        n_attacks=n_attacks,
        n_benign=len(results) - n_attacks,
        auroc=auroc(results),
        pr_at_fsr_001=pr_at_fsr(s, 0.01).pr,
        pr_at_fsr_005=pr_at_fsr(s, 0.05).pr,
        pr_at_fsr_010=pr_at_fsr(s, 0.10).pr,
        best_f1=f1.f1,
        best_f1_threshold=f1.threshold,
        sweep=s,
        results=results,
    )


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def render_markdown(reports: Sequence[ScorerReport], slice_keys: Sequence[str]) -> str:
    if not reports:
        return "# Evaluation report\n\n_No scorers given._\n"

    ref = reports[0]
    lines: list[str] = []
    lines.append("# IAM evaluation report\n")
    lines.append(
        f"Dataset: {ref.n_traces} traces "
        f"({ref.n_attacks} attacks / {ref.n_benign} benign).\n"
    )

    lines.append("## Headline\n")
    lines.append("Primary metric: **Prevention Rate at False Stop Rate ≤ 1%**.\n")
    lines.append("| Scorer | PR @ FSR=1% | PR @ FSR=5% | PR @ FSR=10% | AUROC | Best F1 |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for r in reports:
        lines.append(
            f"| {r.name} | {_fmt(r.pr_at_fsr_001)} | {_fmt(r.pr_at_fsr_005)} | "
            f"{_fmt(r.pr_at_fsr_010)} | {_fmt(r.auroc)} | {_fmt(r.best_f1)} |"
        )
    lines.append("")

    for key in slice_keys:
        lines.append(f"## Per-{key}\n")
        lines.append(_render_slice_table(reports, key))
        lines.append("")

    return "\n".join(lines) + "\n"


def _render_slice_table(reports: Sequence[ScorerReport], key: str) -> str:
    # Union of slice names across all scorers
    all_slices: dict[str, dict[str, str]] = {}
    counts: dict[str, tuple[int, int]] = {}
    for r in reports:
        for name, m in slice_by(r.results, key).items():
            counts.setdefault(name, (m.n_attacks, m.n_benign))
            all_slices.setdefault(name, {})
            all_slices[name][r.name] = _fmt(m.pr_at_fsr_001.pr)

    if not all_slices:
        return "_(no slices)_"

    header = ["slice", "n_attacks", "n_benign", *(r.name for r in reports)]
    sep = ["---"] + ["---:"] * (len(header) - 1)
    out = ["| " + " | ".join(header) + " |", "| " + " | ".join(sep) + " |"]
    for slice_name in sorted(all_slices.keys()):
        a, b = counts[slice_name]
        warn = " ⚠" if (a < 3 or b < 3) else ""
        row = [
            f"{slice_name}{warn}",
            str(a),
            str(b),
            *(all_slices[slice_name].get(r.name, "—") for r in reports),
        ]
        out.append("| " + " | ".join(row) + " |")
    out.append("\nPR @ FSR ≤ 1% per slice. ⚠ marks slices with <3 attacks or <3 benigns (numbers are noisy).\n")
    return "\n".join(out)


def _fmt(x: float) -> str:
    if x != x:  # NaN
        return "n/a"
    return f"{x:.3f}"


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


def render_csv(reports: Sequence[ScorerReport], slice_keys: Sequence[str], out_path: str | Path) -> None:
    rows: list[dict] = []
    for r in reports:
        rows.append({
            "scorer": r.name, "slice_key": "ALL", "slice": "ALL",
            "n_attacks": r.n_attacks, "n_benign": r.n_benign,
            "pr_at_fsr_001": _csv_num(r.pr_at_fsr_001),
            "pr_at_fsr_005": _csv_num(r.pr_at_fsr_005),
            "pr_at_fsr_010": _csv_num(r.pr_at_fsr_010),
            "auroc": _csv_num(r.auroc),
            "best_f1": _csv_num(r.best_f1),
        })
        for key in slice_keys:
            for name, m in slice_by(r.results, key).items():
                rows.append({
                    "scorer": r.name, "slice_key": key, "slice": name,
                    "n_attacks": m.n_attacks, "n_benign": m.n_benign,
                    "pr_at_fsr_001": _csv_num(m.pr_at_fsr_001.pr),
                    "pr_at_fsr_005": _csv_num(m.pr_at_fsr_005.pr),
                    "pr_at_fsr_010": "",
                    "auroc": _csv_num(m.auroc),
                    "best_f1": "",
                })

    fields = ["scorer", "slice_key", "slice", "n_attacks", "n_benign",
              "pr_at_fsr_001", "pr_at_fsr_005", "pr_at_fsr_010", "auroc", "best_f1"]
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def _csv_num(x: float) -> str:
    if x != x:
        return ""
    return f"{x:.4f}"


# ---------------------------------------------------------------------------
# Plot
# ---------------------------------------------------------------------------


def render_plot(reports: Sequence[ScorerReport], out_path: str | Path) -> bool:
    """Save the PR-vs-FSR overlay. Returns True if plot was written, False
    if matplotlib isn't available (silently skipped)."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    fig, ax = plt.subplots(figsize=(6, 5))
    for r in reports:
        # Filter to points where both metrics are finite
        xy = [(fsr, pr) for fsr, pr in zip(r.sweep.fsr, r.sweep.pr) if fsr == fsr and pr == pr]
        xy.sort()
        if not xy:
            continue
        xs, ys = zip(*xy)
        ax.plot(xs, ys, marker="o", markersize=3, label=r.name)
    ax.set_xlabel("False Stop Rate (FSR) on benign traces")
    ax.set_ylabel("Prevention Rate (PR) on attack traces")
    ax.set_title("IAM — PR vs FSR")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    ax.axvline(0.01, color="gray", linestyle=":", linewidth=1, label="FSR=1%")
    ax.axvline(0.05, color="gray", linestyle="--", linewidth=1, label="FSR=5%")
    ax.grid(alpha=0.3)
    ax.legend(loc="lower right", fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return True


# ---------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------


def build_report(
    score_paths: Sequence[str | Path],
    out_dir: str | Path,
    slice_keys: Sequence[str] = ("family", "source", "harm_category"),
    names: Sequence[str] | None = None,
) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    reports: list[ScorerReport] = []
    for i, path in enumerate(score_paths):
        path = Path(path)
        name = names[i] if (names and i < len(names)) else path.parent.name or path.stem
        results = load_results(path)
        reports.append(evaluate_one(name, results))

    md_text = render_markdown(reports, slice_keys)
    (out_dir / "report.md").write_text(md_text)
    render_csv(reports, slice_keys, out_dir / "slices.csv")
    plotted = render_plot(reports, out_dir / "pr_fsr.png")

    return {
        "scorers": [r.name for r in reports],
        "out_dir": str(out_dir),
        "files": {
            "markdown": str(out_dir / "report.md"),
            "csv": str(out_dir / "slices.csv"),
            "plot": str(out_dir / "pr_fsr.png") if plotted else None,
        },
    }
