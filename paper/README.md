# TraceGuard paper draft

Build the PDF with a vanilla TeX Live install (no custom `.sty` files needed) by
running `make` in this directory, which executes `pdflatex -> bibtex -> pdflatex
x2` to resolve the natbib citations; use `make clean` to remove build artifacts.

**Status:** this is a preliminary draft. All quantitative results come from a
single v0.19 training run and are labeled accordingly; several cells are still
open and marked with `% TODO` LaTeX comments or red `[TODO: ...]` placeholders
in the rendered PDF (latency, ablations, per-family table, quantitative
cross-backend transfer, and unverified bibliographic details in
`references.bib`). Resolve those before submission.
