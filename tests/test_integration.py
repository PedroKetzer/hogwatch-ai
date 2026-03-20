"""End-to-end integration tests: scenario file → parse → detect → timeline → report.

These tests run the full pipeline (minus LLM) against real scenario data files
to catch regressions that unit tests on individual rules would miss — e.g.
parser changes that silently break detection, or timeline/report generation
failing on real data shapes.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import pytest

from core.detector import run_detection
from core.models import Severity
from core.parser import load_scenario
from core.report import generate_report
from core.timeline import build_timeline

DATA_DIR = Path(_PROJECT_ROOT) / "data"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_pipeline(scenario_file: str):
    """Run parse → detect → timeline → report (no LLM) and return all artifacts."""
    path = DATA_DIR / scenario_file
    metadata, events = load_scenario(path)
    findings = run_detection(events)
    timeline = build_timeline(events, findings)
    report = generate_report(metadata, timeline, findings, investigation=None)
    return metadata, events, findings, timeline, report


def _finding_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def _finding_by_id(findings, rule_id: str):
    return [f for f in findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# Scenario 1 — AWS SSRF → S3 Exfiltration (real CloudTrail data)
# ---------------------------------------------------------------------------

class TestScenario1E2E:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.metadata, self.events, self.findings, self.timeline, self.report = (
            _run_pipeline("scenario_1.json")
        )

    def test_parses_all_events(self):
        assert len(self.events) == 103

    def test_events_are_sorted_by_timestamp(self):
        timestamps = [e.timestamp for e in self.events]
        assert timestamps == sorted(timestamps)

    def test_all_events_are_cloudtrail(self):
        assert all(e.event_type == "cloudtrail" for e in self.events)

    def test_detects_credential_theft(self):
        assert "AWS-001" in _finding_ids(self.findings)

    def test_detects_assume_role_burst(self):
        assert "AWS-002" in _finding_ids(self.findings)

    def test_detects_s3_enumeration_chain(self):
        assert "AWS-003" in _finding_ids(self.findings)

    def test_detects_recon_burst(self):
        assert "AWS-004" in _finding_ids(self.findings)

    def test_detects_full_attack_chain(self):
        assert "AWS-CHAIN" in _finding_ids(self.findings)
        chain = _finding_by_id(self.findings, "AWS-CHAIN")[0]
        assert chain.severity == Severity.CRITICAL

    def test_chain_is_critical(self):
        chain = _finding_by_id(self.findings, "AWS-CHAIN")[0]
        assert chain.severity == Severity.CRITICAL

    def test_timeline_length_matches_events(self):
        assert len(self.timeline) == len(self.events)

    def test_timeline_has_suspicious_entries(self):
        suspicious = [e for e in self.timeline if e.is_suspicious]
        assert len(suspicious) > 0

    def test_timeline_relative_time_starts_at_zero(self):
        assert self.timeline[0].relative_time == "T+0s"

    def test_report_contains_required_sections(self):
        assert "# Incident Report" in self.report
        assert "## Executive Summary" in self.report
        assert "## Timeline" in self.report
        assert "## Detection Findings" in self.report
        assert "## Recommended Actions" in self.report

    def test_report_mentions_mitre_techniques(self):
        assert "T1078.004" in self.report
        assert "T1530" in self.report

    def test_report_contains_all_finding_rule_ids(self):
        for f in self.findings:
            assert f.rule_id in self.report


# ---------------------------------------------------------------------------
# Scenario 2 — PostHog API Key Compromise (synthetic)
# ---------------------------------------------------------------------------

class TestScenario2E2E:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.metadata, self.events, self.findings, self.timeline, self.report = (
            _run_pipeline("scenario_2.json")
        )

    def test_parses_all_events(self):
        assert len(self.events) == 7

    def test_detects_script_user_agent(self):
        assert "PH-001" in _finding_ids(self.findings)

    def test_detects_scope_escalation(self):
        assert "PH-004" in _finding_ids(self.findings)
        finding = _finding_by_id(self.findings, "PH-004")[0]
        assert finding.severity == Severity.CRITICAL

    def test_detects_batch_export(self):
        assert "PH-006" in _finding_ids(self.findings)

    def test_detects_full_chain(self):
        assert "PH-CHAIN" in _finding_ids(self.findings)

    def test_report_mentions_attacker_bucket(self):
        assert "attacker-bucket-ext" in self.report or "PH-006" in self.report


# ---------------------------------------------------------------------------
# Parametrized: every scenario file loads and produces findings
# ---------------------------------------------------------------------------

_ALL_SCENARIOS = sorted(DATA_DIR.glob("scenario_*.json"))


@pytest.mark.parametrize(
    "scenario_path",
    _ALL_SCENARIOS,
    ids=[p.name for p in _ALL_SCENARIOS],
)
class TestAllScenariosSmoke:
    """Smoke tests that apply to every scenario: the pipeline must not crash
    and must produce non-empty findings, a valid timeline, and a report."""

    def test_pipeline_runs_without_error(self, scenario_path):
        metadata, events, findings, timeline, report = _run_pipeline(scenario_path.name)
        assert len(events) > 0

    def test_produces_at_least_one_finding(self, scenario_path):
        _, events, findings, _, _ = _run_pipeline(scenario_path.name)
        assert len(findings) > 0, f"{scenario_path.name} produced no findings"

    def test_timeline_length_matches_events(self, scenario_path):
        _, events, findings, timeline, _ = _run_pipeline(scenario_path.name)
        assert len(timeline) == len(events)

    def test_report_is_valid_markdown(self, scenario_path):
        _, events, findings, timeline, report = _run_pipeline(scenario_path.name)
        assert report.startswith("# Incident Report")
        assert "## Detection Findings" in report
        assert report.strip().endswith("*Generated by hogwatch-ai*")

    def test_findings_have_mitre_mapping(self, scenario_path):
        _, _, findings, _, _ = _run_pipeline(scenario_path.name)
        for f in findings:
            assert f.mitre_technique, f"{f.rule_id} missing MITRE technique"

    def test_all_findings_appear_in_report(self, scenario_path):
        _, _, findings, _, report = _run_pipeline(scenario_path.name)
        for f in findings:
            assert f.rule_id in report, f"{f.rule_id} missing from report"
