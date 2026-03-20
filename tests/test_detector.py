"""Unit tests for core.detector detection rules and correlation chains."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root (where core/ lives) is on sys.path so that
# ``from core.models import ...`` works regardless of how pytest is invoked.
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from datetime import datetime, timedelta

import pytest

from core.models import NormalizedEvent, Severity
from core.detector import run_detection


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

_BASE_TS = datetime(2026, 3, 19, 12, 0, 0)


def _cloudtrail_event(
    event_name: str = "DescribeInstances",
    *,
    timestamp: datetime | None = None,
    actor: str = "arn:aws:sts::123456789012:assumed-role/MyRole/i-abc123",
    source: str = "ec2.amazonaws.com",
    user_identity_type: str = "AssumedRole",
    session_issuer_arn: str = "arn:aws:iam::123456789012:role/MyRole",
    source_ip: str = "ec2.amazonaws.com",
    extra_context: dict | None = None,
) -> NormalizedEvent:
    ctx = {
        "userIdentityType": user_identity_type,
        "sessionIssuerArn": session_issuer_arn,
        "sourceIPAddress": source_ip,
    }
    if extra_context:
        ctx.update(extra_context)
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="cloudtrail",
        event_name=event_name,
        source=source,
        actor=actor,
        context=ctx,
    )


def _activity_log_event(
    event_name: str = "login",
    *,
    timestamp: datetime | None = None,
    actor: str = "pedro",
    target: str = "",
    context: dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="activity_log",
        event_name=event_name,
        source="activity_log",
        actor=actor,
        target=target,
        context=context or {},
    )


def _rate_limit_event(
    *,
    timestamp: datetime | None = None,
    count: int = 100,
    baseline: int = 10,
    path: str = "/api/event",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="rate_limit",
        event_name="rate_limit_exceeded",
        source="rate_limiter",
        context={"count": count, "baseline": baseline, "path": path},
    )


def _structlog_event(
    event_name: str = "query_executed",
    *,
    timestamp: datetime | None = None,
    path: str = "/api/projects/1/persons/",
    access_method: str = "personal_api_key",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="structlog",
        event_name=event_name,
        source="structlog",
        context={
            "path": path,
            "query_tag": {"access_method": access_method},
        },
    )


def _find(findings, rule_id: str):
    """Return all findings matching *rule_id*."""
    return [f for f in findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# AWS-001: Stolen EC2 credentials used from external IP
# ---------------------------------------------------------------------------


class TestAWS001:
    def test_assumed_role_from_external_ip_triggers(self):
        events = [
            _cloudtrail_event(
                "GetCallerIdentity",
                source_ip="198.51.100.42",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-001")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1078.004"

    def test_assumed_role_from_ec2_does_not_trigger(self):
        events = [
            _cloudtrail_event(
                "GetCallerIdentity",
                source_ip="ec2.amazonaws.com",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-001")
        assert len(matches) == 0

    def test_empty_source_ip_does_not_trigger(self):
        events = [
            _cloudtrail_event(
                "GetCallerIdentity",
                source_ip="",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-001")
        assert len(matches) == 0

    def test_non_assumed_role_from_external_ip_does_not_trigger(self):
        events = [
            _cloudtrail_event(
                "GetCallerIdentity",
                source_ip="198.51.100.42",
                user_identity_type="IAMUser",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-001")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# AWS-002: AssumeRole burst (>3 in 5min)
# ---------------------------------------------------------------------------


class TestAWS002:
    def test_four_assume_roles_within_5min_triggers(self):
        events = [
            _cloudtrail_event(
                "AssumeRole",
                timestamp=_BASE_TS + timedelta(seconds=i * 30),
                source_ip="ec2.amazonaws.com",
            )
            for i in range(4)
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-002")
        assert len(matches) == 1
        assert matches[0].severity == Severity.MEDIUM

    def test_three_assume_roles_does_not_trigger(self):
        events = [
            _cloudtrail_event(
                "AssumeRole",
                timestamp=_BASE_TS + timedelta(seconds=i * 30),
                source_ip="ec2.amazonaws.com",
            )
            for i in range(3)
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-002")
        assert len(matches) == 0

    def test_four_assume_roles_outside_5min_does_not_trigger(self):
        events = [
            _cloudtrail_event(
                "AssumeRole",
                timestamp=_BASE_TS + timedelta(minutes=i * 3),
                source_ip="ec2.amazonaws.com",
            )
            for i in range(4)
        ]
        # Total span is 9 minutes, exceeding the 5 min window
        findings = run_detection(events)
        matches = _find(findings, "AWS-002")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# AWS-003: S3 exfiltration chain
# ---------------------------------------------------------------------------


class TestAWS003:
    def test_full_s3_chain_triggers(self):
        events = [
            _cloudtrail_event("ListBuckets", timestamp=_BASE_TS),
            _cloudtrail_event(
                "ListObjects", timestamp=_BASE_TS + timedelta(seconds=10)
            ),
            _cloudtrail_event(
                "GetObject", timestamp=_BASE_TS + timedelta(seconds=20)
            ),
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-003")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1530"

    def test_partial_chain_list_only_does_not_trigger(self):
        events = [
            _cloudtrail_event("ListBuckets"),
            _cloudtrail_event("ListObjects"),
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-003")
        assert len(matches) == 0

    def test_single_get_object_does_not_trigger(self):
        events = [_cloudtrail_event("GetObject")]
        findings = run_detection(events)
        matches = _find(findings, "AWS-003")
        assert len(matches) == 0

    def test_non_assumed_role_s3_chain_does_not_trigger(self):
        events = [
            _cloudtrail_event(
                "ListBuckets", user_identity_type="IAMUser"
            ),
            _cloudtrail_event(
                "ListObjects", user_identity_type="IAMUser"
            ),
            _cloudtrail_event(
                "GetObject", user_identity_type="IAMUser"
            ),
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-003")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# AWS-004: Recon burst (>10 Describe* in 60s)
# ---------------------------------------------------------------------------


class TestAWS004:
    def test_eleven_describe_calls_in_60s_triggers(self):
        events = [
            _cloudtrail_event(
                "DescribeInstances",
                timestamp=_BASE_TS + timedelta(seconds=i * 5),
            )
            for i in range(11)
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-004")
        assert len(matches) == 1
        assert matches[0].severity == Severity.MEDIUM
        assert matches[0].mitre_technique == "T1580"

    def test_ten_describe_calls_does_not_trigger(self):
        events = [
            _cloudtrail_event(
                "DescribeInstances",
                timestamp=_BASE_TS + timedelta(seconds=i * 5),
            )
            for i in range(10)
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-004")
        assert len(matches) == 0

    def test_eleven_describe_calls_spread_over_120s_does_not_trigger(self):
        events = [
            _cloudtrail_event(
                "DescribeInstances",
                timestamp=_BASE_TS + timedelta(seconds=i * 12),
            )
            for i in range(11)
        ]
        # Span is 120s; no sliding window of 60s contains >10 events
        findings = run_detection(events)
        matches = _find(findings, "AWS-004")
        assert len(matches) == 0

    def test_various_describe_events_count(self):
        names = [
            "DescribeInstances",
            "DescribeVpcs",
            "DescribeSubnets",
            "DescribeSecurityGroups",
            "DescribeRouteTables",
            "DescribeNetworkInterfaces",
            "DescribeVolumes",
            "DescribeSnapshots",
            "DescribeImages",
            "DescribeKeyPairs",
            "DescribeAddresses",
        ]
        events = [
            _cloudtrail_event(
                name,
                timestamp=_BASE_TS + timedelta(seconds=i * 2),
            )
            for i, name in enumerate(names)
        ]
        findings = run_detection(events)
        matches = _find(findings, "AWS-004")
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# PH-001: Script user-agent login
# ---------------------------------------------------------------------------


class TestPH001:
    @pytest.mark.parametrize(
        "ua",
        [
            "python-requests/2.28.0",
            "curl/7.86.0",
            "HTTPie/3.2.1",
            "Wget/1.21",
            "Go-http-client/2.0",
        ],
    )
    def test_script_user_agents_trigger(self, ua: str):
        events = [
            _activity_log_event(
                "login",
                context={"user_agent": ua, "ip": "203.0.113.5"},
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-001")
        assert len(matches) == 1
        assert matches[0].severity == Severity.MEDIUM

    def test_normal_browser_ua_does_not_trigger(self):
        events = [
            _activity_log_event(
                "login",
                context={
                    "user_agent": (
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0.0.0 Safari/537.36"
                    ),
                    "ip": "203.0.113.5",
                },
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-001")
        assert len(matches) == 0

    def test_non_login_event_does_not_trigger(self):
        events = [
            _activity_log_event(
                "page_view",
                context={"user_agent": "python-requests/2.28.0"},
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-001")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# PH-003: Rate limit spike (>5x baseline)
# ---------------------------------------------------------------------------


class TestPH003:
    def test_spike_above_5x_triggers(self):
        events = [_rate_limit_event(count=60, baseline=10)]
        findings = run_detection(events)
        matches = _find(findings, "PH-003")
        assert len(matches) == 1
        assert matches[0].severity == Severity.LOW
        assert matches[0].mitre_technique == "T1499"

    def test_exactly_5x_does_not_trigger(self):
        events = [_rate_limit_event(count=50, baseline=10)]
        findings = run_detection(events)
        matches = _find(findings, "PH-003")
        assert len(matches) == 0

    def test_below_5x_does_not_trigger(self):
        events = [_rate_limit_event(count=30, baseline=10)]
        findings = run_detection(events)
        matches = _find(findings, "PH-003")
        assert len(matches) == 0

    def test_zero_baseline_does_not_trigger(self):
        events = [_rate_limit_event(count=100, baseline=0)]
        findings = run_detection(events)
        matches = _find(findings, "PH-003")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# PH-004: API key scope escalation to wildcard
# ---------------------------------------------------------------------------


class TestPH004:
    def test_scope_escalation_to_wildcard_triggers(self):
        events = [
            _activity_log_event(
                "updated",
                target="PersonalAPIKey",
                context={
                    "api_key_mask": "phx_...k9Zm",
                    "changes": [
                        {
                            "field": "scopes",
                            "before": ["read"],
                            "after": ["*"],
                        }
                    ],
                },
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-004")
        assert len(matches) == 1
        assert matches[0].severity == Severity.CRITICAL
        assert matches[0].mitre_technique == "T1098"

    def test_no_scope_change_does_not_trigger(self):
        events = [
            _activity_log_event(
                "updated",
                target="PersonalAPIKey",
                context={
                    "api_key_mask": "phx_...k9Zm",
                    "changes": [
                        {
                            "field": "scopes",
                            "before": ["read"],
                            "after": ["read"],
                        }
                    ],
                },
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-004")
        assert len(matches) == 0

    def test_scope_change_without_wildcard_does_not_trigger(self):
        events = [
            _activity_log_event(
                "updated",
                target="PersonalAPIKey",
                context={
                    "api_key_mask": "phx_...k9Zm",
                    "changes": [
                        {
                            "field": "scopes",
                            "before": ["read"],
                            "after": ["read", "write"],
                        }
                    ],
                },
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-004")
        assert len(matches) == 0

    def test_already_wildcard_does_not_trigger(self):
        events = [
            _activity_log_event(
                "updated",
                target="PersonalAPIKey",
                context={
                    "api_key_mask": "phx_...k9Zm",
                    "changes": [
                        {
                            "field": "scopes",
                            "before": ["*"],
                            "after": ["*"],
                        }
                    ],
                },
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-004")
        assert len(matches) == 0

    def test_non_scope_field_change_does_not_trigger(self):
        events = [
            _activity_log_event(
                "updated",
                target="PersonalAPIKey",
                context={
                    "api_key_mask": "phx_...k9Zm",
                    "changes": [
                        {
                            "field": "label",
                            "before": "old_name",
                            "after": "new_name",
                        }
                    ],
                },
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-004")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# PH-005: Sensitive data query via API key
# ---------------------------------------------------------------------------


class TestPH005:
    def test_persons_query_via_api_key_triggers(self):
        events = [
            _structlog_event(
                path="/api/projects/1/persons/",
                access_method="personal_api_key",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-005")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1530"

    def test_persons_query_via_session_does_not_trigger(self):
        events = [
            _structlog_event(
                path="/api/projects/1/persons/",
                access_method="session",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-005")
        assert len(matches) == 0

    def test_non_sensitive_path_via_api_key_does_not_trigger(self):
        events = [
            _structlog_event(
                path="/api/projects/1/events/",
                access_method="personal_api_key",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-005")
        assert len(matches) == 0

    @pytest.mark.parametrize(
        "path",
        [
            "/api/projects/1/persons/",
            "/api/projects/1/person/abc-123",
            "/api/projects/1/cohorts/42",
        ],
    )
    def test_all_sensitive_paths_trigger(self, path: str):
        events = [
            _structlog_event(path=path, access_method="personal_api_key")
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-005")
        assert len(matches) == 1


# ---------------------------------------------------------------------------
# PH-006: Batch export to external S3 bucket
# ---------------------------------------------------------------------------


class TestPH006:
    def test_export_to_non_posthog_bucket_triggers(self):
        events = [
            _activity_log_event(
                "created",
                target="BatchExport",
                context={
                    "bucket_name": "attacker-exfil-bucket",
                    "prefix": "dump/",
                    "region": "us-east-1",
                },
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-006")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1537"

    def test_export_to_posthog_bucket_does_not_trigger(self):
        events = [
            _activity_log_event(
                "created",
                target="BatchExport",
                context={
                    "bucket_name": "posthog-prod-exports",
                    "prefix": "data/",
                    "region": "eu-west-1",
                },
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-006")
        assert len(matches) == 0

    def test_empty_bucket_does_not_trigger(self):
        events = [
            _activity_log_event(
                "created",
                target="BatchExport",
                context={"bucket_name": "", "prefix": "", "region": ""},
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PH-006")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# AWS-CHAIN: AWS-001 + AWS-003 -> CRITICAL chain
# ---------------------------------------------------------------------------


class TestAWSChain:
    def test_aws001_plus_aws003_produces_critical_chain(self):
        events = [
            # AWS-001: AssumedRole from external IP
            _cloudtrail_event(
                "GetCallerIdentity",
                timestamp=_BASE_TS,
                source_ip="198.51.100.42",
            ),
            # AWS-003: full S3 chain
            _cloudtrail_event(
                "ListBuckets",
                timestamp=_BASE_TS + timedelta(seconds=30),
                source_ip="198.51.100.42",
            ),
            _cloudtrail_event(
                "ListObjects",
                timestamp=_BASE_TS + timedelta(seconds=60),
                source_ip="198.51.100.42",
            ),
            _cloudtrail_event(
                "GetObject",
                timestamp=_BASE_TS + timedelta(seconds=90),
                source_ip="198.51.100.42",
            ),
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "AWS-CHAIN")
        assert len(chain_matches) == 1
        assert chain_matches[0].severity == Severity.CRITICAL
        assert chain_matches[0].mitre_technique == "T1078.004 \u2192 T1530"

    def test_aws001_alone_does_not_produce_chain(self):
        events = [
            _cloudtrail_event(
                "GetCallerIdentity",
                source_ip="198.51.100.42",
            )
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "AWS-CHAIN")
        assert len(chain_matches) == 0

    def test_aws003_alone_does_not_produce_chain(self):
        events = [
            _cloudtrail_event("ListBuckets"),
            _cloudtrail_event("ListObjects"),
            _cloudtrail_event("GetObject"),
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "AWS-CHAIN")
        assert len(chain_matches) == 0


# ---------------------------------------------------------------------------
# PH-CHAIN: PH-001 + PH-004 + PH-006 -> CRITICAL chain
# ---------------------------------------------------------------------------


class TestPHChain:
    def test_ph001_ph004_ph006_produces_critical_chain(self):
        events = [
            # PH-001: script user-agent login
            _activity_log_event(
                "login",
                timestamp=_BASE_TS,
                context={
                    "user_agent": "python-requests/2.28.0",
                    "ip": "203.0.113.5",
                },
            ),
            # PH-004: scope escalation to wildcard
            _activity_log_event(
                "updated",
                timestamp=_BASE_TS + timedelta(minutes=1),
                target="PersonalAPIKey",
                context={
                    "api_key_mask": "phx_...k9Zm",
                    "changes": [
                        {
                            "field": "scopes",
                            "before": ["read"],
                            "after": ["*"],
                        }
                    ],
                },
            ),
            # PH-006: batch export to external bucket
            _activity_log_event(
                "created",
                timestamp=_BASE_TS + timedelta(minutes=5),
                target="BatchExport",
                context={
                    "bucket_name": "attacker-exfil-bucket",
                    "prefix": "dump/",
                    "region": "us-east-1",
                },
            ),
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "PH-CHAIN")
        assert len(chain_matches) == 1
        assert chain_matches[0].severity == Severity.CRITICAL
        assert chain_matches[0].mitre_technique == "T1552 \u2192 T1098 \u2192 T1537"

    def test_ph001_and_ph004_without_ph006_does_not_produce_chain(self):
        events = [
            _activity_log_event(
                "login",
                context={
                    "user_agent": "python-requests/2.28.0",
                    "ip": "203.0.113.5",
                },
            ),
            _activity_log_event(
                "updated",
                target="PersonalAPIKey",
                context={
                    "api_key_mask": "phx_...k9Zm",
                    "changes": [
                        {
                            "field": "scopes",
                            "before": ["read"],
                            "after": ["*"],
                        }
                    ],
                },
            ),
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "PH-CHAIN")
        assert len(chain_matches) == 0

    def test_ph006_alone_does_not_produce_chain(self):
        events = [
            _activity_log_event(
                "created",
                target="BatchExport",
                context={
                    "bucket_name": "attacker-exfil-bucket",
                    "prefix": "dump/",
                    "region": "us-east-1",
                },
            ),
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "PH-CHAIN")
        assert len(chain_matches) == 0


# ---------------------------------------------------------------------------
# New helper factories for additional event types
# ---------------------------------------------------------------------------


def _temporal_event(
    event_name: str = "workflow_started",
    *,
    timestamp: datetime | None = None,
    workflow_id: str = "batch-export-abc",
    bucket_name: str = "",
    prefix: str = "",
    attempt: int = 1,
    activity_type: str = "",
    workflow_run_id: str = "run-123",
) -> NormalizedEvent:
    ctx: dict = {
        "workflow_id": workflow_id,
        "prefix": prefix,
        "attempt": attempt,
        "activity_type": activity_type,
        "workflow_run_id": workflow_run_id,
    }
    if bucket_name:
        ctx["bucket_name"] = bucket_name
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="temporal_workflow",
        event_name=event_name,
        source="temporal",
        context=ctx,
    )


def _celery_event(
    *,
    timestamp: datetime | None = None,
    task_name: str = "posthog.tasks.process_event",
    worker: str = "posthog-worker-01",
    status: str = "SUCCESS",
    kwargs: dict | None = None,
    retries: int = 0,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="celery_task",
        event_name="task_event",
        source="celery",
        context={
            "task_name": task_name,
            "worker": worker,
            "status": status,
            "kwargs": kwargs or {},
            "retries": retries,
        },
    )


def _otel_event(
    span_name: str = "clickhouse_query",
    *,
    timestamp: datetime | None = None,
    service_name: str = "posthog-web",
    db_system: str = "clickhouse",
    db_statement: str = "SELECT count() FROM events",
    result_rows: int = 100,
    execution_time_ms: int = 50,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="otel_span",
        event_name=span_name,
        source="otel",
        context={
            "service_name": service_name,
            "db.system": db_system,
            "db.statement": db_statement,
            "clickhouse.result_rows": result_rows,
            "clickhouse.execution_time_ms": execution_time_ms,
            "span_name": span_name,
        },
    )


def _exception_event(
    *,
    timestamp: datetime | None = None,
    exception_type: str = "ValueError",
    exception_message: str = "invalid input",
    source_ip: str = "203.0.113.10",
    path: str = "/api/event",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="exception",
        event_name="exception",
        source="sentry",
        context={
            "exception_type": exception_type,
            "exception_message": exception_message,
            "source_ip": source_ip,
            "path": path,
        },
    )


def _http_request_event(
    *,
    timestamp: datetime | None = None,
    method: str = "GET",
    path: str = "/api/event",
    source_ip: str = "203.0.113.10",
    user_agent: str = "Mozilla/5.0",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="http_request",
        event_name="http_request",
        source="nginx",
        context={
            "method": method,
            "path": path,
            "source_ip": source_ip,
            "user_agent": user_agent,
        },
    )


def _plugin_event(
    event_name: str = "plugin_install",
    *,
    timestamp: datetime | None = None,
    plugin_name: str = "my-plugin",
    plugin_source: str = "npm",
    plugin_source_url: str = "https://npmjs.com/my-plugin",
    outbound_url: str = "",
    env_vars_accessed: list | None = None,
) -> NormalizedEvent:
    ctx: dict = {
        "plugin_name": plugin_name,
        "plugin_source": plugin_source,
        "plugin_source_url": plugin_source_url,
    }
    if outbound_url:
        ctx["outbound_url"] = outbound_url
    if env_vars_accessed is not None:
        ctx["env_vars_accessed"] = env_vars_accessed
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="plugin_server",
        event_name=event_name,
        source="plugin_server",
        context=ctx,
    )


def _prometheus_event(
    *,
    timestamp: datetime | None = None,
    metric_name: str = "http_requests_total",
    labels: dict | None = None,
    value: float = 100.0,
    baseline_value: float = 10.0,
    anomaly_ratio: float = 10.0,
    alert_name: str = "",
    pod: str = "posthog-web-abc123",
) -> NormalizedEvent:
    ctx: dict = {
        "metric_name": metric_name,
        "labels": labels or {},
        "value": value,
        "baseline_value": baseline_value,
        "anomaly_ratio": anomaly_ratio,
        "pod": pod,
    }
    if alert_name:
        ctx["alert_name"] = alert_name
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="prometheus_metric",
        event_name="metric_alert",
        source="prometheus",
        context=ctx,
    )


def _mcp_event(
    *,
    timestamp: datetime | None = None,
    tool_name: str = "get_events",
    client_id: str = "client-abc",
    source_ip: str = "203.0.113.10",
    session_token_hash: str = "hash-abc123",
    response_size_bytes: int = 1000,
    duration_ms: int = 100,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp or _BASE_TS,
        event_type="mcp_request",
        event_name="mcp_tool_call",
        source="mcp",
        context={
            "tool_name": tool_name,
            "client_id": client_id,
            "source_ip": source_ip,
            "session_token_hash": session_token_hash,
            "response_size_bytes": response_size_bytes,
            "duration_ms": duration_ms,
        },
    )


# ---------------------------------------------------------------------------
# TW-001: Temporal workflow external bucket
# ---------------------------------------------------------------------------


class TestTW001:
    def test_external_bucket_triggers(self):
        events = [
            _temporal_event(
                "batch_export_started",
                bucket_name="attacker-bucket",
                prefix="dump/",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "TW-001")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1537"

    def test_allowlisted_bucket_does_not_trigger(self):
        events = [
            _temporal_event(
                "batch_export_started",
                bucket_name="posthog-prod-exports",
                prefix="data/",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "TW-001")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# TW-002: Temporal excessive retries
# ---------------------------------------------------------------------------


class TestTW002:
    def test_attempt_above_3_triggers(self):
        events = [
            _temporal_event(
                "activity_retry",
                attempt=4,
                activity_type="export_batch",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "TW-002")
        assert len(matches) == 1
        assert matches[0].severity == Severity.MEDIUM
        assert matches[0].mitre_technique == "T1078"

    def test_attempt_3_or_less_does_not_trigger(self):
        events = [
            _temporal_event(
                "activity_retry",
                attempt=3,
                activity_type="export_batch",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "TW-002")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# TW-003: Temporal workflow history deletion
# ---------------------------------------------------------------------------


class TestTW003:
    def test_workflow_history_deletion_triggers(self):
        events = [
            _temporal_event(
                "workflow_history_deletion",
                workflow_id="wf-123",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "TW-003")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1070.004"

    def test_other_event_name_does_not_trigger(self):
        events = [
            _temporal_event(
                "workflow_started",
                workflow_id="wf-123",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "TW-003")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# TW-CHAIN: TW-001 + TW-003 -> CRITICAL chain
# ---------------------------------------------------------------------------


class TestTWChain:
    def test_tw001_plus_tw003_produces_critical_chain(self):
        events = [
            _temporal_event(
                "batch_export_started",
                timestamp=_BASE_TS,
                bucket_name="attacker-bucket",
                prefix="dump/",
            ),
            _temporal_event(
                "workflow_history_deletion",
                timestamp=_BASE_TS + timedelta(minutes=5),
                workflow_id="wf-123",
            ),
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "TW-CHAIN")
        assert len(chain_matches) == 1
        assert chain_matches[0].severity == Severity.CRITICAL
        assert chain_matches[0].mitre_technique == "T1537 \u2192 T1070.004"

    def test_tw001_alone_does_not_produce_chain(self):
        events = [
            _temporal_event(
                "batch_export_started",
                bucket_name="attacker-bucket",
            )
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "TW-CHAIN")
        assert len(chain_matches) == 0


# ---------------------------------------------------------------------------
# CT-001: Unknown Celery worker
# ---------------------------------------------------------------------------


class TestCT001:
    def test_unknown_worker_triggers(self):
        events = [
            _celery_event(
                worker="rogue-worker-42",
                task_name="posthog.tasks.process_event",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "CT-001")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1053.005"

    def test_expected_worker_does_not_trigger(self):
        events = [
            _celery_event(
                worker="posthog-worker-01",
                task_name="posthog.tasks.process_event",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "CT-001")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# CT-002: Task retry storm
# ---------------------------------------------------------------------------


class TestCT002:
    def test_four_retries_in_5min_triggers(self):
        events = [
            _celery_event(
                timestamp=_BASE_TS + timedelta(seconds=i * 30),
                task_name="posthog.tasks.ingest",
                status="RETRY",
            )
            for i in range(4)
        ]
        findings = run_detection(events)
        matches = _find(findings, "CT-002")
        assert len(matches) == 1
        assert matches[0].severity == Severity.MEDIUM
        assert matches[0].mitre_technique == "T1059"

    def test_three_retries_does_not_trigger(self):
        events = [
            _celery_event(
                timestamp=_BASE_TS + timedelta(seconds=i * 30),
                task_name="posthog.tasks.ingest",
                status="RETRY",
            )
            for i in range(3)
        ]
        findings = run_detection(events)
        matches = _find(findings, "CT-002")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# CT-003: Sensitive task execution
# ---------------------------------------------------------------------------


class TestCT003:
    def test_delete_person_task_triggers(self):
        events = [
            _celery_event(
                task_name="posthog.tasks.delete_person_data",
                status="SUCCESS",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "CT-003")
        assert len(matches) == 1
        assert matches[0].severity == Severity.CRITICAL
        assert matches[0].mitre_technique == "T1531"

    def test_normal_task_does_not_trigger(self):
        events = [
            _celery_event(
                task_name="posthog.tasks.process_event",
                status="SUCCESS",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "CT-003")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# CT-004 (chain): CT-001 + CT-003 -> CRITICAL chain
# ---------------------------------------------------------------------------


class TestCT004Chain:
    def test_ct001_plus_ct003_produces_critical_chain(self):
        events = [
            _celery_event(
                timestamp=_BASE_TS,
                worker="rogue-worker-42",
                task_name="posthog.tasks.delete_person_data",
                status="SUCCESS",
            ),
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "CT-004")
        assert len(chain_matches) == 1
        assert chain_matches[0].severity == Severity.CRITICAL
        assert chain_matches[0].mitre_technique == "T1053.005 \u2192 T1531"

    def test_ct001_alone_does_not_produce_chain(self):
        events = [
            _celery_event(
                worker="rogue-worker-42",
                task_name="posthog.tasks.process_event",
            )
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "CT-004")
        assert len(chain_matches) == 0


# ---------------------------------------------------------------------------
# OT-001: Bulk ClickHouse extraction
# ---------------------------------------------------------------------------


class TestOT001:
    def test_over_100k_rows_triggers(self):
        events = [
            _otel_event(
                result_rows=150_000,
                db_statement="SELECT * FROM events",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "OT-001")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1213"

    def test_100k_rows_does_not_trigger(self):
        events = [
            _otel_event(
                result_rows=100_000,
                db_statement="SELECT * FROM events",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "OT-001")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# OT-002: Sensitive table with broad SELECT
# ---------------------------------------------------------------------------


class TestOT002:
    def test_select_star_on_person_triggers(self):
        events = [
            _otel_event(
                db_statement="SELECT * FROM person WHERE id = 1",
                result_rows=10,
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "OT-002")
        assert len(matches) == 1
        assert matches[0].severity == Severity.MEDIUM
        assert matches[0].mitre_technique == "T1530"

    def test_non_sensitive_table_does_not_trigger(self):
        events = [
            _otel_event(
                db_statement="SELECT * FROM events WHERE timestamp > now()",
                result_rows=10,
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "OT-002")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# OT-003: Unexpected service name
# ---------------------------------------------------------------------------


class TestOT003:
    def test_unexpected_service_triggers(self):
        events = [
            _otel_event(
                service_name="rogue-service",
                db_statement="SELECT 1",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "OT-003")
        assert len(matches) == 1
        assert matches[0].severity == Severity.MEDIUM
        assert matches[0].mitre_technique == "T1071.001"

    def test_posthog_service_does_not_trigger(self):
        events = [
            _otel_event(
                service_name="posthog-web",
                db_statement="SELECT 1",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "OT-003")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# OT-004 (chain): OT-001 + OT-002 -> CRITICAL chain
# ---------------------------------------------------------------------------


class TestOT004Chain:
    def test_ot001_plus_ot002_produces_critical_chain(self):
        events = [
            _otel_event(
                timestamp=_BASE_TS,
                result_rows=200_000,
                db_statement="SELECT * FROM person WHERE 1=1",
            ),
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "OT-004")
        assert len(chain_matches) == 1
        assert chain_matches[0].severity == Severity.CRITICAL
        assert chain_matches[0].mitre_technique == "T1213 \u2192 T1530"

    def test_ot001_alone_does_not_produce_chain(self):
        events = [
            _otel_event(
                result_rows=200_000,
                db_statement="SELECT count() FROM events",
            )
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "OT-004")
        assert len(chain_matches) == 0


# ---------------------------------------------------------------------------
# EM-001: Exception spike from same IP
# ---------------------------------------------------------------------------


class TestEM001:
    def test_six_exceptions_in_2min_triggers(self):
        events = [
            _exception_event(
                timestamp=_BASE_TS + timedelta(seconds=i * 10),
                source_ip="198.51.100.50",
            )
            for i in range(6)
        ]
        findings = run_detection(events)
        matches = _find(findings, "EM-001")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1190"

    def test_five_exceptions_does_not_trigger(self):
        events = [
            _exception_event(
                timestamp=_BASE_TS + timedelta(seconds=i * 10),
                source_ip="198.51.100.50",
            )
            for i in range(5)
        ]
        findings = run_detection(events)
        matches = _find(findings, "EM-001")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# EM-002: SQL injection signature
# ---------------------------------------------------------------------------


class TestEM002:
    def test_union_select_in_exception_triggers(self):
        events = [
            _exception_event(
                exception_message="ERROR: UNION SELECT * FROM users --",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "EM-002")
        assert len(matches) == 1
        assert matches[0].severity == Severity.CRITICAL
        assert matches[0].mitre_technique == "T1059.001"

    def test_normal_exception_does_not_trigger(self):
        events = [
            _exception_event(
                exception_message="ValueError: invalid literal for int()",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "EM-002")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# EM-003: Internal endpoint from external IP
# ---------------------------------------------------------------------------


class TestEM003:
    def test_internal_endpoint_from_external_ip_triggers(self):
        events = [
            _http_request_event(
                path="/_internal/healthcheck",
                source_ip="198.51.100.50",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "EM-003")
        assert len(matches) == 1
        assert matches[0].severity == Severity.MEDIUM
        assert matches[0].mitre_technique == "T1046"

    def test_internal_endpoint_from_localhost_does_not_trigger(self):
        events = [
            _http_request_event(
                path="/_internal/healthcheck",
                source_ip="127.0.0.1",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "EM-003")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# PS-001: Plugin from non-official source
# ---------------------------------------------------------------------------


class TestPS001:
    def test_non_official_source_triggers(self):
        events = [
            _plugin_event(
                "plugin_install",
                plugin_name="evil-plugin",
                plugin_source="npm",
                plugin_source_url="https://npmjs.com/evil-plugin",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PS-001")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1195.002"

    def test_official_source_does_not_trigger(self):
        events = [
            _plugin_event(
                "plugin_install",
                plugin_name="good-plugin",
                plugin_source="official",
                plugin_source_url="",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PS-001")
        assert len(matches) == 0

    def test_posthog_github_does_not_trigger(self):
        events = [
            _plugin_event(
                "plugin_install",
                plugin_name="posthog-plugin",
                plugin_source="github",
                plugin_source_url="https://github.com/PostHog/posthog-plugin",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PS-001")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# PS-002: Plugin outbound to external domain
# ---------------------------------------------------------------------------


class TestPS002:
    def test_outbound_to_external_domain_triggers(self):
        events = [
            _plugin_event(
                "plugin_http_call",
                plugin_name="my-plugin",
                outbound_url="https://evil-server.com/exfil",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PS-002")
        assert len(matches) == 1
        assert matches[0].severity == Severity.CRITICAL
        assert matches[0].mitre_technique == "T1041"

    def test_outbound_to_posthog_does_not_trigger(self):
        events = [
            _plugin_event(
                "plugin_http_call",
                plugin_name="my-plugin",
                outbound_url="https://app.posthog.com/api/event",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PS-002")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# PS-003: Plugin accessing env vars
# ---------------------------------------------------------------------------


class TestPS003:
    def test_env_vars_accessed_triggers(self):
        events = [
            _plugin_event(
                "plugin_env_access",
                plugin_name="my-plugin",
                env_vars_accessed=["DATABASE_URL", "SECRET_KEY"],
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PS-003")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1552.001"

    def test_empty_env_vars_does_not_trigger(self):
        events = [
            _plugin_event(
                "plugin_env_access",
                plugin_name="my-plugin",
                env_vars_accessed=[],
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PS-003")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# PS-004 (chain): PS-001 + PS-002 -> CRITICAL chain
# ---------------------------------------------------------------------------


class TestPS004Chain:
    def test_ps001_plus_ps002_produces_critical_chain(self):
        events = [
            _plugin_event(
                "plugin_install",
                timestamp=_BASE_TS,
                plugin_name="evil-plugin",
                plugin_source="npm",
                plugin_source_url="https://npmjs.com/evil-plugin",
            ),
            _plugin_event(
                "plugin_http_call",
                timestamp=_BASE_TS + timedelta(minutes=2),
                plugin_name="evil-plugin",
                outbound_url="https://evil-server.com/exfil",
            ),
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "PS-004")
        assert len(chain_matches) == 1
        assert chain_matches[0].severity == Severity.CRITICAL
        assert chain_matches[0].mitre_technique == "T1195.002 \u2192 T1041"

    def test_ps001_alone_does_not_produce_chain(self):
        events = [
            _plugin_event(
                "plugin_install",
                plugin_name="evil-plugin",
                plugin_source="npm",
                plugin_source_url="https://npmjs.com/evil-plugin",
            )
        ]
        findings = run_detection(events)
        chain_matches = _find(findings, "PS-004")
        assert len(chain_matches) == 0


# ---------------------------------------------------------------------------
# PM-001: Auth failure metric spike
# ---------------------------------------------------------------------------


class TestPM001:
    def test_401_with_anomaly_ratio_above_10_triggers(self):
        events = [
            _prometheus_event(
                metric_name="http_requests_total",
                labels={"status": "401"},
                value=500.0,
                baseline_value=10.0,
                anomaly_ratio=50.0,
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PM-001")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1110.004"

    def test_401_with_anomaly_ratio_10_does_not_trigger(self):
        events = [
            _prometheus_event(
                metric_name="http_requests_total",
                labels={"status": "401"},
                value=100.0,
                baseline_value=10.0,
                anomaly_ratio=10.0,
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PM-001")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# PM-002: Network egress anomaly
# ---------------------------------------------------------------------------


class TestPM002:
    def test_anomaly_ratio_above_5_triggers(self):
        events = [
            _prometheus_event(
                metric_name="container_network_transmit_bytes_total",
                value=100_000_000.0,
                baseline_value=10_000_000.0,
                anomaly_ratio=10.0,
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PM-002")
        assert len(matches) == 1
        assert matches[0].severity == Severity.CRITICAL
        assert matches[0].mitre_technique == "T1041"

    def test_anomaly_ratio_5_does_not_trigger(self):
        events = [
            _prometheus_event(
                metric_name="container_network_transmit_bytes_total",
                value=50_000_000.0,
                baseline_value=10_000_000.0,
                anomaly_ratio=5.0,
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PM-002")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# PM-003: Resource abuse (CPU)
# ---------------------------------------------------------------------------


class TestPM003:
    def test_cpu_anomaly_ratio_above_10_triggers(self):
        events = [
            _prometheus_event(
                metric_name="container_cpu_usage_seconds_total",
                value=80.0,
                baseline_value=4.0,
                anomaly_ratio=20.0,
                pod="posthog-worker-xyz",
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "PM-003")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1496"


# ---------------------------------------------------------------------------
# MCP-001: Session token reuse from different IPs
# ---------------------------------------------------------------------------


class TestMCP001:
    def test_same_token_two_ips_triggers(self):
        events = [
            _mcp_event(
                timestamp=_BASE_TS,
                session_token_hash="token-xyz",
                source_ip="198.51.100.10",
                client_id="client-1",
            ),
            _mcp_event(
                timestamp=_BASE_TS + timedelta(seconds=30),
                session_token_hash="token-xyz",
                source_ip="203.0.113.20",
                client_id="client-2",
            ),
        ]
        findings = run_detection(events)
        matches = _find(findings, "MCP-001")
        assert len(matches) == 1
        assert matches[0].severity == Severity.MEDIUM
        assert matches[0].mitre_technique == "T1550.001"

    def test_same_token_same_ip_does_not_trigger(self):
        events = [
            _mcp_event(
                timestamp=_BASE_TS,
                session_token_hash="token-xyz",
                source_ip="198.51.100.10",
                client_id="client-1",
            ),
            _mcp_event(
                timestamp=_BASE_TS + timedelta(seconds=30),
                session_token_hash="token-xyz",
                source_ip="198.51.100.10",
                client_id="client-1",
            ),
        ]
        findings = run_detection(events)
        matches = _find(findings, "MCP-001")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# MCP-002: Rapid tool calls
# ---------------------------------------------------------------------------


class TestMCP002:
    def test_six_calls_in_2min_triggers(self):
        events = [
            _mcp_event(
                timestamp=_BASE_TS + timedelta(seconds=i * 15),
                tool_name="get_events",
                client_id="client-abc",
            )
            for i in range(6)
        ]
        findings = run_detection(events)
        matches = _find(findings, "MCP-002")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1119"

    def test_five_calls_does_not_trigger(self):
        events = [
            _mcp_event(
                timestamp=_BASE_TS + timedelta(seconds=i * 15),
                tool_name="get_events",
                client_id="client-abc",
            )
            for i in range(5)
        ]
        findings = run_detection(events)
        matches = _find(findings, "MCP-002")
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# MCP-003: Heavy extraction on sensitive tool
# ---------------------------------------------------------------------------


class TestMCP003:
    def test_sensitive_tool_large_response_triggers(self):
        events = [
            _mcp_event(
                tool_name="get_persons",
                response_size_bytes=2_000_000,
                duration_ms=500,
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "MCP-003")
        assert len(matches) == 1
        assert matches[0].severity == Severity.HIGH
        assert matches[0].mitre_technique == "T1530"

    def test_sensitive_tool_small_response_does_not_trigger(self):
        events = [
            _mcp_event(
                tool_name="get_persons",
                response_size_bytes=500,
                duration_ms=50,
            )
        ]
        findings = run_detection(events)
        matches = _find(findings, "MCP-003")
        assert len(matches) == 0
