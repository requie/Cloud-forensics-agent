"""Command line entry point for running synthetic incident simulations."""
from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .scenarios import advanced_persistent_access_scenario
from .workflows import analyze_evidence, collect_evidence, generate_reports

LOGGER = logging.getLogger(__name__)


@dataclass
class SimulationResult:
    case_id: str
    output_dir: Path
    collected_evidence: Dict[str, Any]
    analysis_results: Dict[str, Any]
    report_paths: Dict[str, Optional[str]]


def run_incident_simulation(output_dir: Optional[str | Path] = None) -> SimulationResult:
    """Execute the full agent workflow against a synthetic dataset."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    base_output_dir = Path(output_dir or (Path.cwd() / "simulation_output"))
    base_output_dir.mkdir(parents=True, exist_ok=True)

    evidence_data = advanced_persistent_access_scenario()
    case_id = evidence_data["metadata"]["case_id"]
    LOGGER.info("Running simulation for case %s", case_id)

    collected = collect_evidence(evidence_data, base_output_dir)
    analysis = analyze_evidence(collected, base_output_dir)
    reports = generate_reports(collected, analysis, base_output_dir)

    return SimulationResult(
        case_id=case_id,
        output_dir=base_output_dir,
        collected_evidence=collected,
        analysis_results=analysis,
        report_paths=reports,
    )


def _format_summary(result: SimulationResult) -> str:
    stats = result.collected_evidence["metadata"]["statistics"]
    total_events = sum(stats.values())
    timeline_findings = len(result.analysis_results.get("timeline", {}).get("findings", []))
    lines = [
        f"Simulation completed for case {result.case_id}",
        f"Evidence stored in: {result.output_dir / 'evidence'}",
        f"Total events processed: {total_events}",
        f"Timeline findings: {timeline_findings}",
        "Generated reports:",
    ]
    for name, path in result.report_paths.items():
        if path:
            lines.append(f"  - {name.upper()}: {path}")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run a synthetic incident simulation")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory to store collected evidence, analysis results, and reports.",
    )
    args = parser.parse_args(argv)

    result = run_incident_simulation(args.output_dir)
    summary = _format_summary(result)
    print(summary)

    summary_path = result.output_dir / f"simulation_summary_{result.case_id}.json"
    with summary_path.open("w", encoding="utf-8") as fh:
        json.dump(
            {
                "case_id": result.case_id,
                "output_dir": str(result.output_dir),
                "statistics": result.collected_evidence["metadata"]["statistics"],
                "reports": result.report_paths,
            },
            fh,
            indent=2,
        )
    LOGGER.info("Wrote summary to %s", summary_path)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI invocation
    raise SystemExit(main())
