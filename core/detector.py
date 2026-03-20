from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Callable

from core.models import Finding, NormalizedEvent, Severity

# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

_RULES: dict[str, dict] = {}


def register_rule(rule_id: str, *, severity: str, mitre: str):
    """Decorator to register a detection rule."""

    def decorator(fn: Callable[[list[NormalizedEvent]], list[Finding]]):
        _RULES[rule_id] = {
            "fn": fn,
            "severity": severity,
            "mitre": mitre,
        }
        return fn

    return decorator


def run_detection(events: list[NormalizedEvent]) -> list[Finding]:
    """Run all registered rules against events, then correlate."""
    findings: list[Finding] = []
    for rule_id, rule in _RULES.items():
        results = rule["fn"](events)
        findings.extend(results)

    # Correlation pass
    findings.extend(_correlate(findings))
    return findings


# ---------------------------------------------------------------------------
# AWS Rules
# ---------------------------------------------------------------------------


@register_rule("AWS-001", severity="high", mitre="T1078.004")
def detect_stolen_ec2_credentials(events: list[NormalizedEvent]) -> list[Finding]:
    """EC2 role credentials used from external IP (not ec2.amazonaws.com)."""
    findings = []
    for e in events:
        if e.event_type != "cloudtrail":
            continue
        ctx = e.context
        if (
            ctx.get("userIdentityType") == "AssumedRole"
            and ctx.get("sessionIssuerArn")
            and ctx.get("sourceIPAddress") != "ec2.amazonaws.com"
            and ctx.get("sourceIPAddress") != ""
        ):
            findings.append(
                Finding(
                    rule_id="AWS-001",
                    severity=Severity.HIGH,
                    title="EC2 role credentials used from external IP",
                    description=(
                        f"AssumedRole '{e.actor}' used from IP {ctx['sourceIPAddress']} "
                        f"instead of ec2.amazonaws.com. "
                        f"Event: {e.event_name} at {e.timestamp.isoformat()}"
                    ),
                    events=[e],
                    mitre_technique="T1078.004",
                )
            )
    return findings


@register_rule("AWS-002", severity="medium", mitre="T1550.001")
def detect_assume_role_burst(events: list[NormalizedEvent]) -> list[Finding]:
    """AssumeRole burst (>3 in 5min) from service."""
    assume_events = [
        e
        for e in events
        if e.event_type == "cloudtrail"
        and e.event_name == "AssumeRole"
        and e.context.get("sourceIPAddress") == "ec2.amazonaws.com"
    ]
    if len(assume_events) <= 3:
        return []

    window = timedelta(minutes=5)
    # Check 5min sliding window
    for i, start_event in enumerate(assume_events):
        window_end = start_event.timestamp + window
        window_events = [
            e for e in assume_events[i:] if e.timestamp <= window_end
        ]
        if len(window_events) > 3:
            return [
                Finding(
                    rule_id="AWS-002",
                    severity=Severity.MEDIUM,
                    title="AssumeRole burst from service",
                    description=(
                        f"{len(window_events)} AssumeRole calls from ec2.amazonaws.com "
                        f"within {(window_events[-1].timestamp - start_event.timestamp).total_seconds():.0f}s"
                    ),
                    events=window_events,
                    mitre_technique="T1550.001",
                )
            ]
    return []


@register_rule("AWS-003", severity="high", mitre="T1530")
def detect_s3_exfiltration_chain(events: list[NormalizedEvent]) -> list[Finding]:
    """ListBuckets + ListObjects + GetObject chain by assumed role."""
    s3_events = [
        e
        for e in events
        if e.event_type == "cloudtrail"
        and e.context.get("userIdentityType") == "AssumedRole"
        and e.event_name in ("ListBuckets", "ListObjects", "GetObject")
    ]

    seen = {e.event_name for e in s3_events}
    if seen >= {"ListBuckets", "ListObjects", "GetObject"}:
        return [
            Finding(
                rule_id="AWS-003",
                severity=Severity.HIGH,
                title="S3 enumeration and exfiltration chain",
                description=(
                    f"Assumed role performed ListBuckets → ListObjects → GetObject "
                    f"({len(s3_events)} total S3 events)"
                ),
                events=s3_events,
                mitre_technique="T1530",
            )
        ]
    return []


@register_rule("AWS-004", severity="medium", mitre="T1580")
def detect_recon_burst(events: list[NormalizedEvent]) -> list[Finding]:
    """>10 Describe* calls in 60s."""
    describe_events = [
        e
        for e in events
        if e.event_type == "cloudtrail" and e.event_name.startswith("Describe")
    ]
    if len(describe_events) <= 10:
        return []

    # Check 60s sliding window
    for i, start_event in enumerate(describe_events):
        window_end = start_event.timestamp + timedelta(seconds=60)
        window_events = [
            e for e in describe_events[i:] if e.timestamp <= window_end
        ]
        if len(window_events) > 10:
            return [
                Finding(
                    rule_id="AWS-004",
                    severity=Severity.MEDIUM,
                    title="EC2 reconnaissance burst",
                    description=(
                        f"{len(window_events)} Describe* calls within 60s "
                        f"starting at {start_event.timestamp.isoformat()}"
                    ),
                    events=window_events,
                    mitre_technique="T1580",
                )
            ]
    return []


# ---------------------------------------------------------------------------
# PostHog Rules
# ---------------------------------------------------------------------------

_SCRIPT_USER_AGENTS = ("python-requests", "curl", "httpie", "wget", "go-http-client")


@register_rule("PH-001", severity="medium", mitre="T1078")
def detect_script_user_agent_login(events: list[NormalizedEvent]) -> list[Finding]:
    """Login with script user-agent."""
    findings = []
    for e in events:
        if e.event_type != "activity_log" or e.event_name != "login":
            continue
        ua = e.context.get("user_agent", "").lower()
        if any(script_ua in ua for script_ua in _SCRIPT_USER_AGENTS):
            findings.append(
                Finding(
                    rule_id="PH-001",
                    severity=Severity.MEDIUM,
                    title="Login with script user-agent",
                    description=(
                        f"Login detected with user-agent '{e.context.get('user_agent')}' "
                        f"from IP {e.context.get('ip', 'unknown')}"
                    ),
                    events=[e],
                    mitre_technique="T1078",
                )
            )
    return findings


_KNOWN_IPS: set[str] = {"10.0.1.50", "10.0.1.51", "192.168.1.100"}


@register_rule("PH-002", severity="medium", mitre="T1552")
def detect_api_key_unusual_ip(events: list[NormalizedEvent]) -> list[Finding]:
    """API key usage from IP not in known list."""
    findings = []
    for e in events:
        if e.event_type != "activity_log" or e.event_name != "login":
            continue
        if e.context.get("access_method") != "personal_api_key":
            continue
        ip = e.context.get("ip", "")
        if ip and ip not in _KNOWN_IPS:
            findings.append(
                Finding(
                    rule_id="PH-002",
                    severity=Severity.MEDIUM,
                    title="API key used from unknown IP",
                    description=(
                        f"Personal API key {e.context.get('api_key_mask', '???')} "
                        f"used from IP {ip} which is not in the known IP list"
                    ),
                    events=[e],
                    mitre_technique="T1552",
                )
            )
    return findings


@register_rule("PH-003", severity="low", mitre="T1499")
def detect_rate_limit_spike(events: list[NormalizedEvent]) -> list[Finding]:
    """Rate limit spike (>5x baseline)."""
    findings = []
    for e in events:
        if e.event_type != "rate_limit":
            continue
        count = e.context.get("count", 0)
        baseline = e.context.get("baseline", 1)
        if baseline > 0 and count > 5 * baseline:
            findings.append(
                Finding(
                    rule_id="PH-003",
                    severity=Severity.LOW,
                    title="Rate limit spike detected",
                    description=(
                        f"Rate limit exceeded: {count} requests vs baseline {baseline} "
                        f"({count / baseline:.1f}x) on path {e.context.get('path', 'unknown')}"
                    ),
                    events=[e],
                    mitre_technique="T1499",
                )
            )
    return findings


@register_rule("PH-004", severity="critical", mitre="T1098")
def detect_api_key_scope_escalation(events: list[NormalizedEvent]) -> list[Finding]:
    """API key scope escalation (any → * or adding write scopes)."""
    findings = []
    for e in events:
        if e.event_type != "activity_log" or e.event_name != "updated":
            continue
        if e.target != "PersonalAPIKey":
            continue
        for change in e.context.get("changes", []):
            if change.get("field") != "scopes":
                continue
            after = change.get("after", [])
            before = change.get("before", [])
            if "*" in after and "*" not in before:
                findings.append(
                    Finding(
                        rule_id="PH-004",
                        severity=Severity.CRITICAL,
                        title="API key scope escalated to wildcard",
                        description=(
                            f"API key {e.context.get('api_key_mask', '???')} "
                            f"scopes changed from {before} to {after}"
                        ),
                        events=[e],
                        mitre_technique="T1098",
                    )
                )
    return findings


@register_rule("PH-005", severity="high", mitre="T1530")
def detect_sensitive_data_query(events: list[NormalizedEvent]) -> list[Finding]:
    """Query on persons/sensitive endpoint via API key."""
    sensitive_paths = ("/persons/", "/person/", "/cohorts/")
    findings = []
    for e in events:
        if e.event_type != "structlog" or e.event_name != "query_executed":
            continue
        path = e.context.get("path", "")
        qt = e.context.get("query_tag", {})
        if (
            any(sp in path for sp in sensitive_paths)
            and qt.get("access_method") == "personal_api_key"
        ):
            findings.append(
                Finding(
                    rule_id="PH-005",
                    severity=Severity.HIGH,
                    title="Sensitive data query via API key",
                    description=(
                        f"PersonsQuery executed on {path} "
                        f"via personal_api_key"
                    ),
                    events=[e],
                    mitre_technique="T1530",
                )
            )
    return findings


@register_rule("PH-006", severity="high", mitre="T1537")
def detect_batch_export_external(events: list[NormalizedEvent]) -> list[Finding]:
    """Batch export to non-allowlisted S3 destination."""
    findings = []
    for e in events:
        if e.event_type != "activity_log" or e.event_name != "created":
            continue
        if e.target != "BatchExport":
            continue
        bucket = e.context.get("bucket_name", "")
        if bucket and not bucket.startswith("posthog-"):
            findings.append(
                Finding(
                    rule_id="PH-006",
                    severity=Severity.HIGH,
                    title="Batch export to external S3 bucket",
                    description=(
                        f"Batch export created to s3://{bucket}/"
                        f"{e.context.get('prefix', '')} "
                        f"(region: {e.context.get('region', 'unknown')})"
                    ),
                    events=[e],
                    mitre_technique="T1537",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Temporal Workflow Rules
# ---------------------------------------------------------------------------

_ALLOWED_BUCKET_PREFIXES = ("posthog-",)


@register_rule("TW-001", severity="high", mitre="T1537")
def detect_temporal_external_bucket(events: list[NormalizedEvent]) -> list[Finding]:
    """Batch export workflow targeting non-allowlisted bucket."""
    # First pass: group events by bucket_name to deduplicate findings.
    bucket_events: dict[str, list[NormalizedEvent]] = {}
    for e in events:
        if e.event_type != "temporal_workflow":
            continue
        bucket = e.context.get("bucket_name", "")
        if not bucket:
            continue
        if not any(bucket.startswith(p) for p in _ALLOWED_BUCKET_PREFIXES):
            bucket_events.setdefault(bucket, []).append(e)

    # Second pass: one Finding per unique bucket with all related events attached.
    findings = []
    for bucket, related in bucket_events.items():
        first = related[0]
        event_count = len(related)
        findings.append(
            Finding(
                rule_id="TW-001",
                severity=Severity.HIGH,
                title="Batch export workflow targeting non-allowlisted bucket",
                description=(
                    f"Workflow {first.context.get('workflow_id', '?')} exports to "
                    f"s3://{bucket}/{first.context.get('prefix', '')} "
                    f"which does not match allowed prefixes {_ALLOWED_BUCKET_PREFIXES} "
                    f"({event_count} event{'s' if event_count != 1 else ''} reference this bucket)"
                ),
                events=related,
                mitre_technique="T1537",
            )
        )
    return findings


@register_rule("TW-002", severity="medium", mitre="T1078")
def detect_temporal_excessive_retries(events: list[NormalizedEvent]) -> list[Finding]:
    """Workflow with >3 activity retries (unusual retry pattern)."""
    findings = []
    for e in events:
        if e.event_type != "temporal_workflow":
            continue
        attempt = e.context.get("attempt", 1)
        if isinstance(attempt, int) and attempt > 3:
            findings.append(
                Finding(
                    rule_id="TW-002",
                    severity=Severity.MEDIUM,
                    title="Unusual workflow activity retry count",
                    description=(
                        f"Activity {e.context.get('activity_type', '?')} on workflow "
                        f"{e.context.get('workflow_id', '?')} is on attempt #{attempt} "
                        f"(threshold: 3)"
                    ),
                    events=[e],
                    mitre_technique="T1078",
                )
            )
    return findings


@register_rule("TW-003", severity="high", mitre="T1070.004")
def detect_temporal_workflow_deletion(events: list[NormalizedEvent]) -> list[Finding]:
    """Workflow deletion/cleanup activity detected (evidence tampering)."""
    findings = []
    for e in events:
        if e.event_type != "temporal_workflow":
            continue
        if e.event_name == "workflow_history_deletion" or e.context.get(
            "activity_type", ""
        ) == "delete_workflow_history":
            findings.append(
                Finding(
                    rule_id="TW-003",
                    severity=Severity.HIGH,
                    title="Workflow history deletion detected",
                    description=(
                        f"Workflow history deletion requested for "
                        f"{e.context.get('workflow_id', '?')} "
                        f"(run: {e.context.get('workflow_run_id', '?')}). "
                        f"This may indicate evidence tampering."
                    ),
                    events=[e],
                    mitre_technique="T1070.004",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Celery Task Rules
# ---------------------------------------------------------------------------

_EXPECTED_WORKER_PATTERN = "posthog-worker-"


@register_rule("CT-001", severity="high", mitre="T1053.005")
def detect_unknown_worker(events: list[NormalizedEvent]) -> list[Finding]:
    """Task submitted from unknown/unexpected worker hostname."""
    findings = []
    for e in events:
        if e.event_type != "celery_task":
            continue
        worker = e.context.get("worker", "")
        if worker and not worker.startswith(_EXPECTED_WORKER_PATTERN):
            findings.append(
                Finding(
                    rule_id="CT-001",
                    severity=Severity.HIGH,
                    title="Task from unknown worker hostname",
                    description=(
                        f"Task {e.context.get('task_name', '?')} executed by worker "
                        f"'{worker}' which does not match expected pattern "
                        f"'{_EXPECTED_WORKER_PATTERN}*'. "
                        f"Status: {e.context.get('status')} at {e.timestamp.isoformat()}"
                    ),
                    events=[e],
                    mitre_technique="T1053.005",
                )
            )
    return findings


@register_rule("CT-002", severity="medium", mitre="T1059")
def detect_task_retry_storm(events: list[NormalizedEvent]) -> list[Finding]:
    """Task retry storm — same task_name with >3 retries within 5 minutes."""
    celery_events = [e for e in events if e.event_type == "celery_task"]
    if not celery_events:
        return []

    # Group retry/failure events by task_name
    by_task: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in celery_events:
        status = e.context.get("status", "")
        if status in ("RETRY", "FAILURE"):
            task_name = e.context.get("task_name", "")
            by_task[task_name].append(e)

    findings = []
    window = timedelta(minutes=5)
    for task_name, task_events in by_task.items():
        if len(task_events) <= 3:
            continue
        task_events.sort(key=lambda ev: ev.timestamp)
        first = task_events[0].timestamp
        last = task_events[-1].timestamp
        if last - first <= window:
            findings.append(
                Finding(
                    rule_id="CT-002",
                    severity=Severity.MEDIUM,
                    title="Task retry storm detected",
                    description=(
                        f"{len(task_events)} retries/failures for '{task_name}' "
                        f"within {(last - first).total_seconds():.0f}s"
                    ),
                    events=task_events,
                    mitre_technique="T1059",
                )
            )
    return findings


_SENSITIVE_TASK_SUBSTRINGS = ("delete_person", "export_all", "modify_permissions")


@register_rule("CT-003", severity="critical", mitre="T1531")
def detect_sensitive_task_execution(events: list[NormalizedEvent]) -> list[Finding]:
    """Sensitive task execution from non-scheduled origin."""
    findings = []
    for e in events:
        if e.event_type != "celery_task":
            continue
        task_name = e.context.get("task_name", "")
        if any(sub in task_name for sub in _SENSITIVE_TASK_SUBSTRINGS):
            findings.append(
                Finding(
                    rule_id="CT-003",
                    severity=Severity.CRITICAL,
                    title="Sensitive task execution detected",
                    description=(
                        f"Sensitive task '{task_name}' executed on worker "
                        f"'{e.context.get('worker', '?')}' with args "
                        f"{e.context.get('kwargs', {})}. "
                        f"Status: {e.context.get('status')} at {e.timestamp.isoformat()}"
                    ),
                    events=[e],
                    mitre_technique="T1531",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# OTel Trace Rules
# ---------------------------------------------------------------------------

_BULK_ROW_THRESHOLD = 100_000

_OT_SENSITIVE_TABLES = ("person", "person_distinct_id")


@register_rule("OT-001", severity="high", mitre="T1213")
def detect_bulk_ch_extraction(events: list[NormalizedEvent]) -> list[Finding]:
    """ClickHouse query returning >100k rows (bulk data extraction)."""
    findings = []
    for e in events:
        if e.event_type != "otel_span":
            continue
        if e.context.get("db.system") != "clickhouse":
            continue
        result_rows = e.context.get("clickhouse.result_rows", 0)
        if isinstance(result_rows, (int, float)) and result_rows > _BULK_ROW_THRESHOLD:
            findings.append(
                Finding(
                    rule_id="OT-001",
                    severity=Severity.HIGH,
                    title="Bulk ClickHouse data extraction detected",
                    description=(
                        f"ClickHouse query returned {result_rows} rows "
                        f"(threshold: {_BULK_ROW_THRESHOLD}) in "
                        f"{e.context.get('clickhouse.execution_time_ms', '?')}ms. "
                        f"Query: {e.context.get('db.statement', '?')[:120]}"
                    ),
                    events=[e],
                    mitre_technique="T1213",
                )
            )
    return findings


@register_rule("OT-002", severity="medium", mitre="T1530")
def detect_sensitive_table_query(events: list[NormalizedEvent]) -> list[Finding]:
    """Query targeting sensitive tables (person, person_distinct_id) with broad SELECT."""
    findings = []
    for e in events:
        if e.event_type != "otel_span":
            continue
        if e.context.get("db.system") != "clickhouse":
            continue
        statement = e.context.get("db.statement", "")
        if not statement:
            continue
        stmt_upper = statement.upper()
        # Check if any sensitive table is referenced
        for table in _OT_SENSITIVE_TABLES:
            if table.upper() not in stmt_upper:
                continue
            # Check for broad SELECT (SELECT * or no column filtering on that table)
            if "SELECT *" in stmt_upper or f"FROM {table.upper()} " in stmt_upper:
                findings.append(
                    Finding(
                        rule_id="OT-002",
                        severity=Severity.MEDIUM,
                        title="Query targeting sensitive table with broad SELECT",
                        description=(
                            f"Query on sensitive table '{table}' with broad column selection. "
                            f"Rows returned: {e.context.get('clickhouse.result_rows', '?')}. "
                            f"Query: {statement[:120]}"
                        ),
                        events=[e],
                        mitre_technique="T1530",
                    )
                )
                break  # One finding per event
    return findings


_EXPECTED_SERVICE_PATTERN = "posthog-"


@register_rule("OT-003", severity="medium", mitre="T1071.001")
def detect_unexpected_service_name(events: list[NormalizedEvent]) -> list[Finding]:
    """Span from unexpected service name (not matching posthog-* pattern)."""
    findings = []
    for e in events:
        if e.event_type != "otel_span":
            continue
        service = e.context.get("service_name", "")
        if service and not service.startswith(_EXPECTED_SERVICE_PATTERN):
            findings.append(
                Finding(
                    rule_id="OT-003",
                    severity=Severity.MEDIUM,
                    title="Span from unexpected service name",
                    description=(
                        f"Span '{e.context.get('span_name', '?')}' originated from "
                        f"service '{service}' which does not match expected pattern "
                        f"'{_EXPECTED_SERVICE_PATTERN}*'"
                    ),
                    events=[e],
                    mitre_technique="T1071.001",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Exception + Middleware Rules
# ---------------------------------------------------------------------------

_SQL_INJECTION_PATTERNS = (
    "'; DROP",
    "UNION SELECT",
    "OR 1=1",
    "xp_cmdshell",
)

_INTERNAL_ENDPOINT_PREFIXES = ("/_internal/", "/debug/", "/_health")

_LOCALHOST_IPS = ("127.0.0.1", "::1", "localhost", "10.0.0.1")


@register_rule("EM-001", severity="high", mitre="T1190")
def detect_exception_spike(events: list[NormalizedEvent]) -> list[Finding]:
    """>5 exceptions in 2 minutes from same source IP."""
    exception_events = [e for e in events if e.event_type == "exception"]
    if len(exception_events) <= 5:
        return []

    # Group by source IP
    by_ip: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in exception_events:
        ip = e.context.get("source_ip", "")
        if ip:
            by_ip[ip].append(e)

    findings = []
    window = timedelta(minutes=2)
    for ip, ip_events in by_ip.items():
        if len(ip_events) <= 5:
            continue
        ip_events.sort(key=lambda ev: ev.timestamp)
        # Sliding window check
        for i, start_event in enumerate(ip_events):
            window_end = start_event.timestamp + window
            window_events = [
                e for e in ip_events[i:] if e.timestamp <= window_end
            ]
            if len(window_events) > 5:
                findings.append(
                    Finding(
                        rule_id="EM-001",
                        severity=Severity.HIGH,
                        title="Exception spike from single source IP",
                        description=(
                            f"{len(window_events)} exceptions from IP {ip} "
                            f"within 2 minutes starting at "
                            f"{start_event.timestamp.isoformat()}"
                        ),
                        events=window_events,
                        mitre_technique="T1190",
                    )
                )
                break  # One finding per IP
    return findings


@register_rule("EM-002", severity="critical", mitre="T1059.001")
def detect_sql_injection_signature(events: list[NormalizedEvent]) -> list[Finding]:
    """SQL injection signature in exception message or request parameters."""
    findings = []
    for e in events:
        text_to_check = ""
        if e.event_type == "exception":
            text_to_check = e.context.get("exception_message", "")
            additional = e.context.get("additional_properties", {})
            if isinstance(additional, dict):
                raw_payload = additional.get("raw_payload", "")
                if raw_payload:
                    text_to_check += " " + raw_payload
        elif e.event_type == "http_request":
            # Check user_agent and path for injection patterns
            text_to_check = (
                e.context.get("user_agent", "")
                + " " + e.context.get("path", "")
            )

        if not text_to_check:
            continue

        text_upper = text_to_check.upper()
        for pattern in _SQL_INJECTION_PATTERNS:
            if pattern.upper() in text_upper:
                findings.append(
                    Finding(
                        rule_id="EM-002",
                        severity=Severity.CRITICAL,
                        title="SQL injection signature detected",
                        description=(
                            f"SQL injection pattern '{pattern}' found in "
                            f"{e.event_type} event at {e.timestamp.isoformat()}. "
                            f"Source: {e.actor}, path: {e.target}"
                        ),
                        events=[e],
                        mitre_technique="T1059.001",
                    )
                )
                break  # One finding per event
    return findings


@register_rule("EM-003", severity="medium", mitre="T1046")
def detect_internal_endpoint_access(events: list[NormalizedEvent]) -> list[Finding]:
    """Requests to internal/debug endpoints from external IPs."""
    findings = []
    for e in events:
        if e.event_type != "http_request":
            continue
        path = e.context.get("path", "")
        source_ip = e.context.get("source_ip", "")
        if not any(path.startswith(prefix) for prefix in _INTERNAL_ENDPOINT_PREFIXES):
            continue
        if source_ip in _LOCALHOST_IPS:
            continue
        findings.append(
            Finding(
                rule_id="EM-003",
                severity=Severity.MEDIUM,
                title="Internal endpoint access from external IP",
                description=(
                    f"Request to internal endpoint {path} from external IP "
                    f"{source_ip} (user-agent: "
                    f"{e.context.get('user_agent', 'unknown')[:50]})"
                ),
                events=[e],
                mitre_technique="T1046",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Plugin Server Rules
# ---------------------------------------------------------------------------

_POSTHOG_GITHUB_PREFIX = "github.com/PostHog/"


@register_rule("PS-001", severity="high", mitre="T1195.002")
def detect_untrusted_plugin_install(events: list[NormalizedEvent]) -> list[Finding]:
    """Plugin installed from non-official source."""
    findings = []
    for e in events:
        if e.event_type != "plugin_server":
            continue
        # Only fire on install/init events, not on every event from that plugin
        if e.event_name not in ("plugin_install", "plugin_init"):
            continue
        plugin_source = e.context.get("plugin_source", "")
        if not plugin_source or plugin_source == "official":
            continue
        source_url = e.context.get("plugin_source_url", "")
        if _POSTHOG_GITHUB_PREFIX in source_url:
            continue
        findings.append(
            Finding(
                rule_id="PS-001",
                severity=Severity.HIGH,
                title="Plugin installed from non-official source",
                description=(
                    f"Plugin '{e.context.get('plugin_name', '?')}' installed from "
                    f"{plugin_source} ({source_url}). "
                    f"Not from official repository or PostHog GitHub org."
                ),
                events=[e],
                mitre_technique="T1195.002",
            )
        )
    return findings


_POSTHOG_DOMAINS = (".posthog.com", ".posthog.cc")


@register_rule("PS-002", severity="critical", mitre="T1041")
def detect_plugin_outbound_exfiltration(events: list[NormalizedEvent]) -> list[Finding]:
    """Plugin making outbound HTTP calls to external domains."""
    findings = []
    for e in events:
        if e.event_type != "plugin_server":
            continue
        outbound_url = e.context.get("outbound_url", "")
        if not outbound_url:
            continue
        # Check if the URL matches any allowed PostHog domain
        if any(domain in outbound_url for domain in _POSTHOG_DOMAINS):
            continue
        findings.append(
            Finding(
                rule_id="PS-002",
                severity=Severity.CRITICAL,
                title="Plugin outbound HTTP to external domain",
                description=(
                    f"Plugin '{e.context.get('plugin_name', '?')}' made outbound "
                    f"HTTP request to {outbound_url} "
                    f"(method: {e.context.get('http_method', '?')}, "
                    f"payload: {e.context.get('payload_size_bytes', '?')} bytes)"
                ),
                events=[e],
                mitre_technique="T1041",
            )
        )
    return findings


@register_rule("PS-003", severity="high", mitre="T1552.001")
def detect_plugin_env_access(events: list[NormalizedEvent]) -> list[Finding]:
    """Plugin accessing environment variables (credential theft)."""
    findings = []
    for e in events:
        if e.event_type != "plugin_server":
            continue
        env_vars = e.context.get("env_vars_accessed")
        if not env_vars:
            continue
        findings.append(
            Finding(
                rule_id="PS-003",
                severity=Severity.HIGH,
                title="Plugin accessed environment variables",
                description=(
                    f"Plugin '{e.context.get('plugin_name', '?')}' accessed "
                    f"environment variables: {env_vars}"
                ),
                events=[e],
                mitre_technique="T1552.001",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Prometheus Metrics Rules
# ---------------------------------------------------------------------------


@register_rule("PM-001", severity="high", mitre="T1110.004")
def detect_auth_failure_metric_spike(events: list[NormalizedEvent]) -> list[Finding]:
    """Auth failure metric spike — http_requests_total with status 401/403 and anomaly_ratio > 10x."""
    findings = []
    for e in events:
        if e.event_type != "prometheus_metric":
            continue
        metric_name = e.context.get("metric_name", "")
        if metric_name != "http_requests_total":
            continue
        labels = e.context.get("labels", {})
        status = labels.get("status", "")
        if status not in ("401", "403"):
            continue
        anomaly_ratio = e.context.get("anomaly_ratio", 0)
        if anomaly_ratio > 10:
            findings.append(
                Finding(
                    rule_id="PM-001",
                    severity=Severity.HIGH,
                    title="Auth failure metric spike (credential stuffing indicator)",
                    description=(
                        f"http_requests_total{{status=\"{status}\"}} at {e.context.get('value', '?')}/min "
                        f"({anomaly_ratio}x baseline of {e.context.get('baseline_value', '?')}/min) "
                        f"on {e.context.get('pod', e.context.get('instance', '?'))}. "
                        f"Alert: {e.context.get('alert_name', 'none')}"
                    ),
                    events=[e],
                    mitre_technique="T1110.004",
                )
            )
    return findings


@register_rule("PM-002", severity="critical", mitre="T1041")
def detect_network_egress_anomaly(events: list[NormalizedEvent]) -> list[Finding]:
    """Network egress anomaly — container_network_transmit_bytes_total with anomaly_ratio > 5x."""
    findings = []
    for e in events:
        if e.event_type != "prometheus_metric":
            continue
        metric_name = e.context.get("metric_name", "")
        if metric_name != "container_network_transmit_bytes_total":
            continue
        anomaly_ratio = e.context.get("anomaly_ratio", 0)
        if anomaly_ratio > 5:
            value = e.context.get("value", 0)
            baseline = e.context.get("baseline_value", 0)
            # Format bytes for readability
            value_mb = value / (1024 * 1024) if isinstance(value, (int, float)) else 0
            baseline_mb = baseline / (1024 * 1024) if isinstance(baseline, (int, float)) else 0
            findings.append(
                Finding(
                    rule_id="PM-002",
                    severity=Severity.CRITICAL,
                    title="Network egress anomaly (data exfiltration indicator)",
                    description=(
                        f"container_network_transmit_bytes_total at {value_mb:.0f}MB/min "
                        f"({anomaly_ratio}x baseline of {baseline_mb:.0f}MB/min) "
                        f"on pod {e.context.get('pod', '?')}. "
                        f"Alert: {e.context.get('alert_name', 'none')}"
                    ),
                    events=[e],
                    mitre_technique="T1041",
                )
            )
    return findings


_RESOURCE_ABUSE_METRICS = (
    "container_cpu_usage_seconds_total",
    "container_memory_working_set_bytes",
)


@register_rule("PM-003", severity="high", mitre="T1496")
def detect_resource_abuse_metric(events: list[NormalizedEvent]) -> list[Finding]:
    """Resource abuse — CPU or memory metric with anomaly_ratio > 10x (cryptomining indicator)."""
    findings = []
    for e in events:
        if e.event_type != "prometheus_metric":
            continue
        metric_name = e.context.get("metric_name", "")
        if metric_name not in _RESOURCE_ABUSE_METRICS:
            continue
        anomaly_ratio = e.context.get("anomaly_ratio", 0)
        if anomaly_ratio > 10:
            pod = e.context.get("pod", "?")
            value = e.context.get("value", 0)
            baseline = e.context.get("baseline_value", 0)
            if metric_name == "container_memory_working_set_bytes":
                value_fmt = f"{value / (1024**3):.1f}GB"
                baseline_fmt = f"{baseline / (1024**3):.1f}GB"
            else:
                value_fmt = f"{value} cores"
                baseline_fmt = f"{baseline} cores"
            findings.append(
                Finding(
                    rule_id="PM-003",
                    severity=Severity.HIGH,
                    title="Resource abuse detected (cryptomining indicator)",
                    description=(
                        f"{metric_name} at {value_fmt} "
                        f"({anomaly_ratio}x baseline of {baseline_fmt}) "
                        f"on pod {pod}. "
                        f"Alert: {e.context.get('alert_name', 'none')}"
                    ),
                    events=[e],
                    mitre_technique="T1496",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# MCP Service Rules
# ---------------------------------------------------------------------------

_MCP_SENSITIVE_TOOLS = ("get_persons", "get_events")
_HEAVY_RESPONSE_SIZE_BYTES = 1_000_000  # 1 MB
_HEAVY_DURATION_MS = 30_000  # 30 seconds


@register_rule("MCP-001", severity="medium", mitre="T1550.001")
def detect_mcp_session_token_reuse(events: list[NormalizedEvent]) -> list[Finding]:
    """MCP session token reuse from different IP — same session_token_hash from >1 distinct source_ip."""
    mcp_events = [e for e in events if e.event_type == "mcp_request"]
    if not mcp_events:
        return []

    # Group by session_token_hash
    by_token: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in mcp_events:
        token_hash = e.context.get("session_token_hash", "")
        if token_hash:
            by_token[token_hash].append(e)

    findings = []
    for token_hash, token_events in by_token.items():
        ips = {e.context.get("source_ip", "") for e in token_events}
        ips.discard("")
        if len(ips) > 1:
            findings.append(
                Finding(
                    rule_id="MCP-001",
                    severity=Severity.MEDIUM,
                    title="MCP session token reuse from different IP",
                    description=(
                        f"Session token hash '{token_hash}' seen from {len(ips)} "
                        f"distinct IPs: {', '.join(sorted(ips))}. "
                        f"Possible session hijacking."
                    ),
                    events=token_events,
                    mitre_technique="T1550.001",
                )
            )
    return findings


@register_rule("MCP-002", severity="high", mitre="T1119")
def detect_mcp_rapid_tool_calls(events: list[NormalizedEvent]) -> list[Finding]:
    """>5 calls to same tool_name within 2 minutes from same client (automated extraction)."""
    mcp_events = [e for e in events if e.event_type == "mcp_request"]
    if not mcp_events:
        return []

    # Group by (client_id or source_ip, tool_name)
    by_client_tool: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for e in mcp_events:
        client_key = e.context.get("client_id", "") or e.context.get("source_ip", "")
        tool_name = e.context.get("tool_name", "")
        if client_key and tool_name:
            by_client_tool[(client_key, tool_name)].append(e)

    findings = []
    window = timedelta(minutes=2)
    for (client_key, tool_name), tool_events in by_client_tool.items():
        if len(tool_events) <= 5:
            continue
        tool_events.sort(key=lambda ev: ev.timestamp)
        # Sliding window check
        for i, start_event in enumerate(tool_events):
            window_end = start_event.timestamp + window
            window_events = [
                e for e in tool_events[i:] if e.timestamp <= window_end
            ]
            if len(window_events) > 5:
                findings.append(
                    Finding(
                        rule_id="MCP-002",
                        severity=Severity.HIGH,
                        title="Rapid MCP tool calls (automated extraction)",
                        description=(
                            f"{len(window_events)} calls to '{tool_name}' from "
                            f"client '{client_key}' within 2 minutes starting at "
                            f"{start_event.timestamp.isoformat()}. "
                            f"Indicates automated data extraction."
                        ),
                        events=window_events,
                        mitre_technique="T1119",
                    )
                )
                break  # One finding per (client, tool)
    return findings


@register_rule("MCP-003", severity="high", mitre="T1530")
def detect_mcp_heavy_extraction(events: list[NormalizedEvent]) -> list[Finding]:
    """MCP response with >1MB payload or >30s duration on sensitive tools."""
    findings = []
    for e in events:
        if e.event_type != "mcp_request":
            continue
        tool_name = e.context.get("tool_name", "")
        if tool_name not in _MCP_SENSITIVE_TOOLS:
            continue
        response_size = e.context.get("response_size_bytes", 0)
        duration = e.context.get("duration_ms", 0)
        if response_size > _HEAVY_RESPONSE_SIZE_BYTES or duration > _HEAVY_DURATION_MS:
            findings.append(
                Finding(
                    rule_id="MCP-003",
                    severity=Severity.HIGH,
                    title="MCP heavy data extraction on sensitive tool",
                    description=(
                        f"Tool '{tool_name}' returned {response_size} bytes in "
                        f"{duration}ms (thresholds: {_HEAVY_RESPONSE_SIZE_BYTES}B / "
                        f"{_HEAVY_DURATION_MS}ms). "
                        f"Client: {e.context.get('client_name', '?')} from "
                        f"{e.context.get('source_ip', '?')}"
                    ),
                    events=[e],
                    mitre_technique="T1530",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# HogQL injection rules
# ---------------------------------------------------------------------------

_HOGQL_INJECTION_PATTERNS = (
    "' OR '", "' AND '", "UNION ALL SELECT", "UNION SELECT",
    "'; DROP", "'; DELETE", "1'='1", "1=1",
)

_PII_PROPERTIES = (
    "$email", "$phone", "$ip", "person_id",
    "$geoip_city_name", "$geoip_country_name", "$name",
)


@register_rule("HQL-001", severity="high", mitre="T1190")
def detect_hogql_injection_probing(events: list[NormalizedEvent]) -> list[Finding]:
    """HogQL injection probing — parser errors with injection signatures."""
    findings: list[Finding]  = []
    probe_events = []
    for e in events:
        if e.event_type != "hogql_query":
            continue
        if e.context.get("status") != "error":
            continue
        query = e.context.get("hogql_query", "").upper()
        for pattern in _HOGQL_INJECTION_PATTERNS:
            if pattern.upper() in query:
                probe_events.append(e)
                break
    if probe_events:
        findings.append(
            Finding(
                rule_id="HQL-001",
                severity=Severity.HIGH,
                title="HogQL injection probing detected",
                description=(
                    f"{len(probe_events)} queries with injection signatures "
                    f"(UNION SELECT, OR '1'='1', etc.) caused parser errors. "
                    f"API key: {probe_events[0].context.get('api_key_mask', 'unknown')}. "
                    f"Indicates active exploitation attempt."
                ),
                events=probe_events,
                mitre_technique="T1190",
            )
        )
    return findings


@register_rule("HQL-002", severity="critical", mitre="T1059.009")
def detect_hogql_pii_extraction(events: list[NormalizedEvent]) -> list[Finding]:
    """HogQL queries selecting PII properties ($email, $phone, $ip, person_id)."""
    findings: list[Finding] = []
    pii_events = []
    for e in events:
        if e.event_type != "hogql_query":
            continue
        if e.context.get("status") != "ok":
            continue
        query = e.context.get("hogql_query", "")
        pii_found = [p for p in _PII_PROPERTIES if p in query]
        if len(pii_found) >= 2:
            pii_events.append(e)
    if pii_events:
        total_rows = sum(e.context.get("result_rows", 0) for e in pii_events)
        findings.append(
            Finding(
                rule_id="HQL-002",
                severity=Severity.CRITICAL,
                title="HogQL PII data extraction via API",
                description=(
                    f"{len(pii_events)} HogQL queries selected multiple PII fields "
                    f"($email, $phone, $ip, person_id) returning {total_rows:,} total rows. "
                    f"API key: {pii_events[0].context.get('api_key_mask', 'unknown')}. "
                    f"User-agent: {pii_events[0].context.get('http_user_agent', 'unknown')}."
                ),
                events=pii_events,
                mitre_technique="T1059.009",
            )
        )
    return findings


@register_rule("HQL-003", severity="high", mitre="T1005")
def detect_hogql_bulk_extraction(events: list[NormalizedEvent]) -> list[Finding]:
    """HogQL query returning >10k rows — bulk data extraction."""
    findings: list[Finding] = []
    for e in events:
        if e.event_type != "hogql_query":
            continue
        if e.context.get("status") != "ok":
            continue
        result_rows = e.context.get("result_rows", 0)
        if result_rows > 10_000:
            findings.append(
                Finding(
                    rule_id="HQL-003",
                    severity=Severity.HIGH,
                    title="HogQL bulk data extraction",
                    description=(
                        f"HogQL query returned {result_rows:,} rows "
                        f"(threshold: 10,000). Duration: {e.context.get('query_duration_ms', 0)}ms, "
                        f"read {e.context.get('read_rows', 0):,} rows. "
                        f"API key: {e.context.get('api_key_mask', 'unknown')}."
                    ),
                    events=[e],
                    mitre_technique="T1005",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


def _events_within_window(
    findings_list: list[Finding], window: timedelta
) -> bool:
    """Return True if all events across the given findings fall within *window*."""
    all_timestamps = [
        e.timestamp for f in findings_list for e in f.events
    ]
    if not all_timestamps:
        return False
    return max(all_timestamps) - min(all_timestamps) <= window


_CORRELATION_WINDOW = timedelta(minutes=30)


def _correlate(findings: list[Finding]) -> list[Finding]:
    """Check for composite attack chains."""
    chains: list[Finding] = []
    rule_ids = {f.rule_id for f in findings}

    # AWS-CHAIN: AWS-001 + AWS-003 → full SSRF to exfil chain
    if {"AWS-001", "AWS-003"} <= rule_ids:
        aws_findings = [f for f in findings if f.rule_id in ("AWS-001", "AWS-003")]
        if _events_within_window(aws_findings, _CORRELATION_WINDOW):
            all_events = []
            for f in aws_findings:
                all_events.extend(f.events)
            chains.append(
                Finding(
                    rule_id="AWS-CHAIN",
                    severity=Severity.CRITICAL,
                    title="AWS SSRF → Credential Theft → S3 Exfiltration chain",
                    description=(
                        "Complete attack chain detected: EC2 role credentials stolen via "
                        "SSRF and used to enumerate and exfiltrate S3 data."
                    ),
                    events=all_events,
                    mitre_technique="T1078.004 → T1530",
                )
            )

    # PH-CHAIN: PH-001 + PH-004 + PH-006 → full PostHog compromise
    if {"PH-001", "PH-004", "PH-006"} <= rule_ids:
        ph_findings = [
            f for f in findings if f.rule_id in ("PH-001", "PH-004", "PH-006")
        ]
        if _events_within_window(ph_findings, _CORRELATION_WINDOW):
            all_events = []
            for f in ph_findings:
                all_events.extend(f.events)
            chains.append(
                Finding(
                    rule_id="PH-CHAIN",
                    severity=Severity.CRITICAL,
                    title="PostHog API Key Compromise → Data Exfiltration chain",
                    description=(
                        "Complete attack chain detected: Compromised API key used with "
                        "script user-agent, scope escalated to wildcard, "
                        "then batch export to external S3 bucket."
                    ),
                    events=all_events,
                    mitre_technique="T1552 → T1098 → T1537",
                )
            )

    # CT-004 (chain): CT-001 + CT-003 → unknown worker + sensitive task
    if {"CT-001", "CT-003"} <= rule_ids:
        ct_findings = [f for f in findings if f.rule_id in ("CT-001", "CT-003")]
        if _events_within_window(ct_findings, _CORRELATION_WINDOW):
            all_events = []
            for f in ct_findings:
                all_events.extend(f.events)
            chains.append(
                Finding(
                    rule_id="CT-004",
                    severity=Severity.CRITICAL,
                    title="Celery Task Injection — Unknown Worker Executing Sensitive Tasks",
                    description=(
                        "Complete attack chain detected: Tasks submitted from unknown "
                        "worker hostname executing sensitive operations (delete_person, "
                        "export_all, modify_permissions). Indicates compromised task queue."
                    ),
                    events=all_events,
                    mitre_technique="T1053.005 → T1531",
                )
            )

    # OT-004 (chain): OT-001 + OT-002 → bulk extraction of sensitive data
    if {"OT-001", "OT-002"} <= rule_ids:
        ot_findings = [f for f in findings if f.rule_id in ("OT-001", "OT-002")]
        if _events_within_window(ot_findings, _CORRELATION_WINDOW):
            all_events = []
            for f in ot_findings:
                all_events.extend(f.events)
            chains.append(
                Finding(
                    rule_id="OT-004",
                    severity=Severity.CRITICAL,
                    title="Bulk extraction of sensitive ClickHouse data",
                    description=(
                        "Complete attack chain detected: Bulk ClickHouse queries "
                        "(>100k rows) combined with queries targeting sensitive tables "
                        "(person, person_distinct_id). Indicates unauthorized data extraction."
                    ),
                    events=all_events,
                    mitre_technique="T1213 → T1530",
                )
            )

    # TW-CHAIN: TW-001 + TW-003 → exfiltration + evidence cleanup
    if {"TW-001", "TW-003"} <= rule_ids:
        tw_findings = [f for f in findings if f.rule_id in ("TW-001", "TW-003")]
        if _events_within_window(tw_findings, _CORRELATION_WINDOW):
            all_events = []
            for f in tw_findings:
                all_events.extend(f.events)
            chains.append(
                Finding(
                    rule_id="TW-CHAIN",
                    severity=Severity.CRITICAL,
                    title="Temporal Workflow Hijacking — Exfiltration + Evidence Cleanup",
                    description=(
                        "Complete attack chain detected: Batch export workflow routed "
                        "data to non-allowlisted bucket, followed by workflow history "
                        "deletion to cover tracks."
                    ),
                    events=all_events,
                    mitre_technique="T1537 → T1070.004",
                )
            )

    # PS-004 (chain): PS-001 + PS-002 → untrusted plugin + data exfiltration
    if {"PS-001", "PS-002"} <= rule_ids:
        ps_findings = [f for f in findings if f.rule_id in ("PS-001", "PS-002")]
        if _events_within_window(ps_findings, _CORRELATION_WINDOW):
            all_events = []
            for f in ps_findings:
                all_events.extend(f.events)
            chains.append(
                Finding(
                    rule_id="PS-004",
                    severity=Severity.CRITICAL,
                    title="Malicious Plugin — Untrusted Source + Data Exfiltration",
                    description=(
                        "Complete attack chain detected: Plugin installed from "
                        "non-official source is making outbound HTTP calls to "
                        "external domains, indicating supply chain compromise "
                        "and active data exfiltration."
                    ),
                    events=all_events,
                    mitre_technique="T1195.002 → T1041",
                )
            )

    # EM-004 (chain): EM-001 + EM-002 → exception spike with injection signatures
    if {"EM-001", "EM-002"} <= rule_ids:
        em_findings = [f for f in findings if f.rule_id in ("EM-001", "EM-002")]
        if _events_within_window(em_findings, _CORRELATION_WINDOW):
            all_events = []
            for f in em_findings:
                all_events.extend(f.events)
            # Deduplicate events by timestamp + event_name
            seen: set[tuple] = set()
            unique_events = []
            for ev in all_events:
                key = (ev.timestamp, ev.event_name)
                if key not in seen:
                    seen.add(key)
                    unique_events.append(ev)
            chains.append(
                Finding(
                    rule_id="EM-004",
                    severity=Severity.HIGH,
                    title="Active API exploitation — Exception spike with SQL injection signatures",
                    description=(
                        "Attack chain detected: Exception spike (EM-001) co-occurs with "
                        "SQL injection signatures (EM-002). An attacker is actively "
                        "attempting to exploit injection vulnerabilities in the API."
                    ),
                    events=unique_events,
                    mitre_technique="T1190 → T1059.001",
                )
            )

    # MCP-004 (chain): MCP-002 + MCP-003 → rapid calls + heavy extraction = automated data theft
    if {"MCP-002", "MCP-003"} <= rule_ids:
        mcp_findings = [f for f in findings if f.rule_id in ("MCP-002", "MCP-003")]
        if _events_within_window(mcp_findings, _CORRELATION_WINDOW):
            all_events = []
            for f in mcp_findings:
                all_events.extend(f.events)
            # Deduplicate events by timestamp + event_name
            seen_mcp: set[tuple] = set()
            unique_mcp_events = []
            for ev in all_events:
                key = (ev.timestamp, ev.event_name)
                if key not in seen_mcp:
                    seen_mcp.add(key)
                    unique_mcp_events.append(ev)
            chains.append(
                Finding(
                    rule_id="MCP-004",
                    severity=Severity.CRITICAL,
                    title="MCP Automated Data Theft — Rapid Tool Calls + Heavy Extraction",
                    description=(
                        "Complete attack chain detected: Rapid-fire MCP tool calls (MCP-002) "
                        "combined with heavy data extraction (MCP-003). An attacker is using "
                        "the MCP service for automated bulk data theft via AI tool abuse."
                    ),
                    events=unique_mcp_events,
                    mitre_technique="T1119 → T1530",
                )
            )

    # PM-004 (chain): PM-001 + PM-002 → credential stuffing followed by data exfil
    if {"PM-001", "PM-002"} <= rule_ids:
        pm_findings = [f for f in findings if f.rule_id in ("PM-001", "PM-002")]
        if _events_within_window(pm_findings, _CORRELATION_WINDOW):
            all_events = []
            for f in pm_findings:
                all_events.extend(f.events)
            chains.append(
                Finding(
                    rule_id="PM-004",
                    severity=Severity.CRITICAL,
                    title="Credential Stuffing → Data Exfiltration (Prometheus metrics correlation)",
                    description=(
                        "Complete attack chain detected in Prometheus metrics: "
                        "Auth failure spike (PM-001) followed by network egress anomaly "
                        "(PM-002). Credential stuffing attack succeeded and data is being "
                        "exfiltrated as shown by abnormal outbound network volume."
                    ),
                    events=all_events,
                    mitre_technique="T1110.004 → T1041",
                )
            )

    # HQL-CHAIN: HQL-001 + HQL-002 → injection probing succeeded in PII extraction
    if {"HQL-001", "HQL-002"} <= rule_ids:
        hql_findings = [f for f in findings if f.rule_id in ("HQL-001", "HQL-002")]
        if _events_within_window(hql_findings, _CORRELATION_WINDOW):
            all_events = []
            for f in hql_findings:
                all_events.extend(f.events)
            chains.append(
                Finding(
                    rule_id="HQL-CHAIN",
                    severity=Severity.CRITICAL,
                    title="HogQL Injection → PII Data Exfiltration chain",
                    description=(
                        "Complete attack chain detected: HogQL injection probing "
                        "(parser errors with injection signatures) followed by "
                        "successful PII extraction queries. Attacker enumerated "
                        "the query parser behavior, then crafted queries to "
                        "extract sensitive person data."
                    ),
                    events=all_events,
                    mitre_technique="T1190 → T1059.009 → T1005",
                )
            )

    return chains
