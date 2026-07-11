"""Experiment tracking (spec §7 — MLflow/W&B + DVC).

Tracking is pluggable behind a tiny protocol so eval runs can be recorded
locally (append-only JSON, the offline default) or shipped to MLflow when that
server is available — without the eval code caring which. Dataset versioning
(DVC) is an ops concern layered on the labels file, out of scope for the code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol


class Tracker(Protocol):
    def log_run(
        self, name: str, params: dict[str, Any], metrics: dict[str, float]
    ) -> None: ...


class NullTracker:
    """Discards runs. Default when no tracking is configured."""

    def log_run(self, name: str, params: dict[str, Any], metrics: dict[str, float]) -> None:
        return None


class LocalJsonTracker:
    """Appends each run to a local JSONL file (offline, always available)."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log_run(self, name: str, params: dict[str, Any], metrics: dict[str, float]) -> None:
        record = {"name": name, "params": params, "metrics": metrics}
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def runs(self) -> list[dict[str, Any]]:
        if not self._path.exists():
            return []
        return [
            json.loads(line)
            for line in self._path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]


class MlflowTracker:  # pragma: no cover - requires the mlflow server/lib
    """Logs to MLflow. Optional; imported lazily so it's never a hard dep."""

    def __init__(self, experiment: str = "attack-engine-evals") -> None:
        import mlflow

        self._mlflow = mlflow
        mlflow.set_experiment(experiment)

    def log_run(self, name: str, params: dict[str, Any], metrics: dict[str, float]) -> None:
        with self._mlflow.start_run(run_name=name):
            self._mlflow.log_params(params)
            self._mlflow.log_metrics(metrics)
