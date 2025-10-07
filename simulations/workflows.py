"""Reusable workflows that exercise the Cloud Forensics agent end-to-end."""
from __future__ import annotations

import copy
import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional

from datetime import datetime

import boto3
from unittest.mock import MagicMock

from data_collection_modules.core.base_collector import BaseCollector
from data_collection_modules.providers.aws.aws_collectors import (
    CloudTrailCollector,
    S3BucketCollector,
)
from data_collection_modules.utils.evidence_utils import create_evidence_container

from analysis_modules.anomaly_detection.anomaly_detector import AnomalyDetector
from analysis_modules.core.base_analyzer import BaseAnalyzer
from analysis_modules.pattern_detection.pattern_detector import PatternDetector
from analysis_modules.timeline.timeline_analyzer import TimelineAnalyzer

from reporting_modules.core.base_reporter import BaseReporter
from reporting_modules.html.html_reporter import HTMLReporter
from reporting_modules.json.json_reporter import JSONReporter
from reporting_modules.pdf.pdf_reporter import PDFReporter

LOGGER = logging.getLogger(__name__)


def _parse_iso8601(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    raise TypeError(f"Unsupported timestamp value: {value!r}")


class _AzureMockCollector(BaseCollector):
    def __init__(self, case_id: str, evidence_storage_path: str, subscription_id: str) -> None:
        super().__init__(case_id, evidence_storage_path)
        self.subscription_id = subscription_id

    def collect(self, evidence_data: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
        self.start_collection()
        try:
            events_path = self.save_evidence(evidence_data, "azure_activity_logs", "test_logs")
            return {"events": list(evidence_data), "metadata_path": events_path}
        finally:
            self.end_collection()


class _GCPMockCollector(BaseCollector):
    def __init__(self, case_id: str, evidence_storage_path: str, project_id: str) -> None:
        super().__init__(case_id, evidence_storage_path)
        self.project_id = project_id

    def collect(self, evidence_data: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
        self.start_collection()
        try:
            events_path = self.save_evidence(evidence_data, "gcp_audit_logs", "test_logs")
            return {"events": list(evidence_data), "metadata_path": events_path}
        finally:
            self.end_collection()


@contextmanager
def _mock_boto3_session(cloudtrail_events: Any, s3_objects: Any):
    original_session = boto3.Session

    def _session_factory(*_args, **_kwargs):  # type: ignore[override]
        mock_session = MagicMock()

        def _client_factory(service_name: str, **_client_kwargs):
            if service_name == "cloudtrail":
                cloudtrail = MagicMock()
                cloudtrail.describe_trails.return_value = {"trailList": [{"Name": "test-trail"}]}
                cloudtrail.lookup_events.return_value = {"Events": cloudtrail_events}
                return cloudtrail
            if service_name == "s3":
                s3 = MagicMock()
                s3.list_objects.return_value = {"Contents": s3_objects}
                return s3
            return MagicMock()

        mock_session.client.side_effect = _client_factory
        return mock_session

    boto3.Session = _session_factory
    try:
        yield
    finally:
        boto3.Session = original_session


def collect_evidence(evidence_data: Mapping[str, Any], output_dir: os.PathLike[str] | str) -> Dict[str, Any]:
    """Run the evidence collection workflow against synthetic data."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    case_id = evidence_data["metadata"]["case_id"]
    evidence_output_dir = output_path / "evidence"
    evidence_output_dir.mkdir(exist_ok=True)

    container_path = create_evidence_container(
        evidence_data=evidence_data,
        metadata=evidence_data["metadata"],
        output_path=str(evidence_output_dir / f"evidence_container_{case_id}"),
    )
    LOGGER.info("Created evidence container at %s", container_path)

    os.environ.setdefault("AWS_ACCESS_KEY_ID", "test_access_key")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test_secret_key")
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

    with _mock_boto3_session(
        evidence_data["aws_cloudtrail"],
        [{"Key": "test-object"}],
    ):
        cloudtrail_collector = CloudTrailCollector(
            case_id=case_id,
            evidence_storage_path=str(evidence_output_dir),
            region="us-east-1",
        )
        cloudtrail_collector.collect(
            start_time=_parse_iso8601(evidence_data["metadata"]["time_range"]["start"]),
            end_time=_parse_iso8601(evidence_data["metadata"]["time_range"]["end"]),
            trail_name=None,
        )

        s3_collector = S3BucketCollector(
            case_id=case_id,
            evidence_storage_path=str(evidence_output_dir),
            region="us-east-1",
        )
        s3_collector.collect(bucket_name="company-financial-data")

    azure_collector = _AzureMockCollector(
        case_id=case_id,
        evidence_storage_path=str(evidence_output_dir),
        subscription_id="00000000-0000-0000-0000-000000000000",
    )
    azure_result = azure_collector.collect(evidence_data["azure_activity_logs"])

    gcp_collector = _GCPMockCollector(
        case_id=case_id,
        evidence_storage_path=str(evidence_output_dir),
        project_id="company-project",
    )
    gcp_result = gcp_collector.collect(evidence_data["gcp_audit_logs"])

    collected_evidence = {
        "aws_cloudtrail": list(evidence_data["aws_cloudtrail"]),
        "aws_s3_logs": list(evidence_data["aws_s3_logs"]),
        "azure_activity_logs": list(azure_result["events"]),
        "gcp_audit_logs": list(gcp_result["events"]),
        "metadata": dict(evidence_data["metadata"]),
    }

    evidence_file = evidence_output_dir / f"collected_evidence_{case_id}.json"
    with evidence_file.open("w", encoding="utf-8") as fh:
        json.dump(collected_evidence, fh, indent=2)

    return collected_evidence


def analyze_evidence(collected_evidence: Mapping[str, Any], output_dir: os.PathLike[str] | str) -> Dict[str, Any]:
    """Run all analyzers against the collected evidence."""
    analysis_output_dir = Path(output_dir) / "analysis"
    analysis_output_dir.mkdir(parents=True, exist_ok=True)

    case_id = collected_evidence["metadata"]["case_id"]

    analyzers: Dict[str, BaseAnalyzer] = {
        "timeline": TimelineAnalyzer(case_id=case_id, analysis_output_path=str(analysis_output_dir)),
        "pattern_detection": PatternDetector(case_id=case_id, analysis_output_path=str(analysis_output_dir)),
        "anomaly_detection": AnomalyDetector(case_id=case_id, analysis_output_path=str(analysis_output_dir)),
    }

    results: Dict[str, Any] = {}
    for key, analyzer in analyzers.items():
        LOGGER.info("Running %s analyzer", key)
        try:
            results[key] = analyzer.analyze(collected_evidence)
        except Exception as exc:  # pragma: no cover - defensive logging
            LOGGER.exception("Analyzer %s failed: %s", key, exc)
            raise

    results["metadata"] = {
        "case_id": case_id,
        "analysis_output_dir": str(analysis_output_dir),
    }

    return results


def _sanitize_analysis_for_reporting(analysis_results: MutableMapping[str, Any]) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, result in analysis_results.items():
        if isinstance(result, Mapping):
            clone = copy.deepcopy(result)
            report_payload = clone.get("report")
            if isinstance(report_payload, Mapping):
                clone["report"] = json.dumps(report_payload, indent=2)
            sanitized[key] = clone
        else:
            sanitized[key] = result
    return sanitized


def generate_reports(
    collected_evidence: Mapping[str, Any],
    analysis_results: MutableMapping[str, Any],
    output_dir: os.PathLike[str] | str,
) -> Dict[str, Optional[str]]:
    """Generate HTML, JSON, and PDF reports from analysis results."""
    report_output_dir = Path(output_dir) / "reports"
    report_output_dir.mkdir(parents=True, exist_ok=True)

    case_id = collected_evidence["metadata"]["case_id"]

    sanitized_results = _sanitize_analysis_for_reporting(analysis_results)

    case_info = {
        "case_id": case_id,
        "title": "Synthetic multi-cloud breach",
        "description": "Simulated cross-cloud credential abuse resulting in data exfiltration.",
    }

    investigator_info = {
        "name": "Simulation Runner",
        "organization": "Cloud Forensics Team",
        "email": "incident-response@example.com",
    }

    reporters: Dict[str, BaseReporter] = {
        "html": HTMLReporter(case_id=case_id, report_output_path=str(report_output_dir)),
        "json": JSONReporter(case_id=case_id, report_output_path=str(report_output_dir)),
    }

    for reporter in reporters.values():
        reporter.set_case_information(case_info)
        reporter.set_investigator_information(investigator_info)

    html_report_path = reporters["html"].generate_report(
        analysis_results=sanitized_results,
        evidence_metadata=collected_evidence["metadata"],
    )
    json_report_path = reporters["json"].generate_report(
        analysis_results=sanitized_results,
        evidence_metadata=collected_evidence["metadata"],
    )

    pdf_report_path: Optional[str] = None
    try:
        pdf_reporter = PDFReporter(case_id=case_id, report_output_path=str(report_output_dir))
        pdf_reporter.set_case_information(case_info)
        pdf_reporter.set_investigator_information(investigator_info)
        pdf_report_path = pdf_reporter.generate_report(
            analysis_results=sanitized_results,
            evidence_metadata=collected_evidence["metadata"],
        )
    except Exception as exc:  # pragma: no cover - PDF generation may require system deps
        LOGGER.warning("PDF report generation failed: %s", exc)

    return {"html": html_report_path, "json": json_report_path, "pdf": pdf_report_path}


__all__ = ["collect_evidence", "analyze_evidence", "generate_reports"]
