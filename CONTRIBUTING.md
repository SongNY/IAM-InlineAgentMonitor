# Contributing to IAM

Thanks for your interest in improving IAM. This is a research project under active
development, so contributions of all kinds are welcome — bug fixes, new attack scenarios,
adapters for additional agent frameworks, and documentation.

## Dev setup

IAM targets Python 3.10+.

```bash
git clone https://github.com/songningyu/agent-iam
cd agent-iam
pip install -e ".[dev,eval]"
```

`import agent_iam` is intentionally light (schema + tokenizer, no torch). Install the
relevant extras for the area you're touching: `train`, `eval`, `runtime`, or `all`.

## Running tests and lint

```bash
pytest -q          # unit tests (tests/)
ruff check .       # lint
ruff check --fix . # auto-fix what's fixable
```

CI runs the same `ruff check .` and `pytest -q` across Python 3.10 / 3.11 / 3.12. Please
make sure both pass locally before opening a PR.

## Pull request conventions

- Keep PRs focused — one logical change per PR.
- Add or update tests for any behavior change (see `tests/` for the existing style).
- Run `ruff check .` and `pytest -q` before pushing.
- Write a clear PR description: what changed and why.
- New attack scenarios go under `agent_iam/data/generate/scenarios/` and must carry a
  violation predicate the auto-labeler can match.

## Don't commit data or runs

The following are intentionally gitignored — never commit them:

- `data/` — the ~1.6 GB dataset (tracked out-of-band, not in git)
- `runs/`, `runs-*/` — experiment run outputs and generated traces
- `*.log`, `logs-*/`, `dist/`, `build/`
- red-team outputs under `promptfoo-redteam/` (only the `*.yaml` configs are tracked)

If you generate traces or train a model locally, keep those artifacts out of the commit.
Training data may contain credential-shaped strings; the loaders scrub known patterns, but
do not add raw traces to version control.

## License

By contributing, you agree that your contributions are licensed under the Apache License
2.0, the same license as the project.
