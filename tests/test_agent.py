#!/usr/bin/env python3
"""Integration tests for the Cloud Forensics AI Agent."""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

# Ensure the repository root is on the import path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock Azure dependencies that are optional in the test environment
from unittest.mock import MagicMock

sys.modules.setdefault("azure.identity", MagicMock())
sys.modules.setdefault("azure.mgmt.compute", MagicMock())
sys.modules.setdefault("azure.mgmt.monitor", MagicMock())
sys.modules.setdefault("azure.mgmt.storage", MagicMock())
sys.modules.setdefault("azure.storage.blob", MagicMock())

from simulations.incident_simulation import main as simulation_main, run_incident_simulation
from simulations.scenarios import advanced_persistent_access_scenario
from simulations.workflows import analyze_evidence, collect_evidence, generate_reports

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def output_dir(tmp_path_factory) -> str:
    """Temporary directory for artifacts generated during the tests."""
    return str(tmp_path_factory.mktemp("cfaa"))


@pytest.fixture(scope="module")
def evidence_data() -> Dict[str, Any]:
    """Provide synthetic evidence that mimics a cross-cloud compromise."""
    return advanced_persistent_access_scenario()


@pytest.fixture(scope="module")
def collected_evidence(evidence_data: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
    """Collect evidence once for the test module to speed up execution."""
    return collect_evidence(evidence_data, output_dir)


@pytest.fixture(scope="module")
def analysis_results(collected_evidence: Dict[str, Any], output_dir: str) -> Dict[str, Any]:
    """Run the analysis workflow a single time for the suite."""
    return analyze_evidence(collected_evidence, output_dir)


def test_data_collection(collected_evidence: Dict[str, Any],
                         evidence_data: Dict[str, Any],
                         output_dir: str) -> None:
    """Verify that evidence collection persists the generated dataset."""
    case_id = collected_evidence["metadata"]["case_id"]
    evidence_file = Path(output_dir) / "evidence" / f"collected_evidence_{case_id}.json"

    assert evidence_file.exists(), "Collected evidence file should be written to disk"
    assert collected_evidence["metadata"] == evidence_data["metadata"]

    for key in ["aws_cloudtrail", "aws_s3_logs", "azure_activity_logs", "gcp_audit_logs"]:
        assert key in collected_evidence
        assert collected_evidence[key] == evidence_data[key]


def test_analysis_outputs(analysis_results: Dict[str, Any]) -> None:
    """Ensure every analyzer produces structured output for reporting."""
    expected_keys = {"timeline", "pattern_detection", "anomaly_detection", "metadata"}
    assert expected_keys.issubset(analysis_results.keys())

    timeline = analysis_results["timeline"]
    assert timeline.get("timeline"), "Timeline analyzer should produce chronological events"
    assert isinstance(timeline.get("summary"), str) and timeline["summary"], "Timeline summary should be populated"

    pattern_detection = analysis_results["pattern_detection"]
    assert "detected_patterns" in pattern_detection

    anomaly_detection = analysis_results["anomaly_detection"]
    assert "statistical_anomalies" in anomaly_detection


def test_reporting_pipeline(collected_evidence: Dict[str, Any],
                            analysis_results: Dict[str, Any],
                            output_dir: str) -> None:
    """Validate that all report formats are emitted for the simulation."""
    report_paths = generate_reports(collected_evidence, analysis_results, output_dir)

    html_path = Path(report_paths["html"])
    json_path = Path(report_paths["json"])

    assert html_path.exists() and html_path.stat().st_size > 0
    assert json.loads(json_path.read_text())

    pdf_path = report_paths.get("pdf")
    if pdf_path:
        assert Path(pdf_path).exists()


def test_cli_entry_point(tmp_path) -> None:
    """Smoke-test the CLI wrapper that runs the full simulation."""
    result = run_incident_simulation(tmp_path)
    assert result.report_paths["html"]

    exit_code = simulation_main(["--output-dir", str(tmp_path)])
    assert exit_code == 0

    summary_files = sorted(tmp_path.glob("simulation_summary_*.json"))
    assert summary_files, "CLI run should emit a simulation summary JSON file"
    summary = json.loads(summary_files[-1].read_text())
    assert "case_id" in summary
    assert set(summary["reports"].keys()) >= {"html", "json", "pdf"}


if __name__ == "__main__":
    sys.exit(simulation_main())
