"""Minimal CLI: `traceguard scan <jsonl>` and `traceguard serve`."""

from __future__ import annotations

import json

import click


@click.group()
def main():
    """TraceGuard — trace anomaly detection for LLM agents."""


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--model", default="Sunnyu/TraceGuard-Qwen3.5-2B")
@click.option("--threshold", default=8.0, type=float)
def scan(path: str, model: str, threshold: float):
    """Run TraceGuard over each trajectory in a JSONL file."""
    from .detect.online import TraceMonitor
    from .schema import Trajectory

    monitor = TraceMonitor.from_pretrained(model, threshold=threshold)
    with open(path) as f:
        for line in f:
            traj = Trajectory.model_validate_json(line)
            for i in range(1, len(traj.steps)):
                prefix = traj.model_copy(update={"steps": traj.steps[:i]})
                nxt = traj.steps[i].action
                if nxt is None:
                    continue
                verdict = monitor.check(prefix, next_action=nxt)
                if verdict.symbol != "OK":
                    click.echo(json.dumps({
                        "traj_id": traj.id,
                        "step": i,
                        **verdict.model_dump(),
                    }))


@main.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8788, type=int)
@click.option("--model", default="Sunnyu/TraceGuard-Qwen3.5-2B")
def serve(host: str, port: int, model: str):
    """Run TraceGuard as a sidecar HTTP service."""
    import uvicorn
    from fastapi import FastAPI

    from .detect.online import TraceMonitor
    from .schema import Trajectory

    app = FastAPI(title="TraceGuard")
    monitor = TraceMonitor.from_pretrained(model)

    @app.post("/check")
    def check(payload: dict):
        traj = Trajectory.model_validate(payload["trace"])
        return monitor.check(traj, next_action=payload["next_action"]).model_dump()

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
