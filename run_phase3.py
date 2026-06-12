"""Command-line entry point for the authorized Phase 3 scanning pipeline."""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys
from pathlib import Path


def _restart_with_project_venv() -> None:
    """Use the existing project virtual environment when invoked by bare Python."""

    candidates = [
        Path(".venv/Scripts/python.exe"),
        Path(".venv/bin/python"),
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.resolve() != Path(sys.executable).resolve():
            raise SystemExit(subprocess.call([str(candidate), *sys.argv]))


try:
    import yaml  # noqa: F401
except ModuleNotFoundError:
    _restart_with_project_venv()

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    _restart_with_project_venv()

try:
    from rich.console import Console
    from rich.table import Table
except ModuleNotFoundError:
    class Table:
        """Minimal text fallback when Rich is unavailable."""

        def __init__(self, title: str) -> None:
            self.title = title
            self.rows: list[tuple[str, str]] = []

        def add_column(self, *args: object, **kwargs: object) -> None:
            return None

        def add_row(self, name: str, value: str) -> None:
            self.rows.append((name, value))

        def __str__(self) -> str:
            rows = [self.title]
            rows.extend(f"{name}: {value}" for name, value in self.rows)
            return "\n".join(rows)

    class Console:
        """Minimal console fallback when Rich is unavailable."""

        def __init__(self, stderr: bool = False) -> None:
            self.stderr = stderr

        def print(self, value: object) -> None:
            print(value)

from app.orchestrator import PipelineArtifacts, run_phase3


load_dotenv()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Phase 3 vulnerability scanning for an authorized enum input."
    )
    parser.add_argument("--enum", required=True, dest="enum_path", type=Path)
    parser.add_argument("--out", required=True, dest="output_dir", type=Path)
    parser.add_argument("--config", default=Path("config.yaml"), type=Path)
    return parser.parse_args()


def print_summary(artifacts: PipelineArtifacts) -> None:
    output = artifacts.vulnerability_output
    table = Table(title=f"Phase 3 Summary: {output.scan_id}")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Total findings", str(output.summary.total))
    table.add_row("Critical", str(output.summary.critical))
    table.add_row("High", str(output.summary.high))
    table.add_row("Medium", str(output.summary.medium))
    table.add_row("Low", str(output.summary.low))

    console = Console()
    console.print(table)
    console.print(f"vuln.json: {artifacts.vuln_path}")
    console.print(f"report.md: {artifacts.report_path}")
    console.print(f"log: {artifacts.log_path}")
    console.print(f"triage vuln.json: {artifacts.pi_vuln_path}")
    console.print(f"pipeline log: {artifacts.pi_log_path}")


def main() -> int:
    args = parse_args()
    try:
        artifacts = asyncio.run(
            run_phase3(args.enum_path, args.output_dir, args.config)
        )
    except Exception as exc:
        Console(stderr=True).print(f"[red]Phase 3 failed safely:[/red] {exc}")
        return 1

    print_summary(artifacts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
