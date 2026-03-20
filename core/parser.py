from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from dateutil.parser import parse as parse_dt

from core.models import NormalizedEvent, Severity


def load_scenario(path: str | Path) -> tuple[dict[str, Any], list[NormalizedEvent]]:
    """Load a scenario JSON file and return (metadata, normalized_events)."""
    with open(path) as f:
        data = json.load(f)

    metadata = data["metadata"]
    source_type = metadata["source_type"]

    normalizer = _NORMALIZERS.get(source_type)
    if normalizer is None:
        raise ValueError(f"Unknown source_type: {source_type}")

    events = [normalizer(raw) for raw in data["events"]]
    events.sort(key=lambda e: e.timestamp)
    return metadata, events


# ---------------------------------------------------------------------------
# CloudTrail normalizer
# ---------------------------------------------------------------------------

def _normalize_cloudtrail(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_dt(raw.get("@timestamp", raw.get("eventTime", "")))
    uid = raw.get("userIdentity", {})

    # Determine actor: userName for IAMUser, ARN for AssumedRole, type for service
    actor = uid.get("userName", "")
    if not actor and uid.get("type") == "AssumedRole":
        arn = uid.get("arn", "")
        # Extract role name from arn:aws:sts::123:assumed-role/RoleName/session
        parts = arn.split("/")
        actor = parts[1] if len(parts) > 1 else arn
    if not actor:
        actor = uid.get("type", "unknown")

    # Target: for S3 events, extract bucket name
    target = ""
    req_params = raw.get("requestParameters") or {}
    if isinstance(req_params, dict):
        target = req_params.get("bucketName", "")

    return NormalizedEvent(
        timestamp=ts,
        event_type="cloudtrail",
        event_name=raw.get("eventName", ""),
        source=raw.get("eventSource", ""),
        actor=actor,
        target=target,
        context={
            "sourceIPAddress": raw.get("sourceIPAddress", ""),
            "userAgent": raw.get("userAgent", ""),
            "awsRegion": raw.get("awsRegion", ""),
            "userIdentityType": uid.get("type", ""),
            "userIdentityArn": uid.get("arn", ""),
            "mfaAuthenticated": (
                uid.get("sessionContext", {})
                .get("attributes", {})
                .get("mfaAuthenticated", "")
            ),
            "sessionIssuerArn": (
                uid.get("sessionContext", {})
                .get("sessionIssuer", {})
                .get("arn", "")
            ),
        },
        severity=Severity.LOW,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# PostHog mixed normalizer (activity_log, structlog, rate_limit)
# ---------------------------------------------------------------------------

def _normalize_posthog(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_dt(raw.get("timestamp", ""))
    source = raw.get("source", "unknown")
    detail = raw.get("detail", {})

    # Event name: activity for activity_log, event for structlog/rate_limit
    event_name = raw.get("activity", raw.get("event", "unknown"))

    # Actor: api key mask or user email
    actor = (
        detail.get("api_key_mask", "")
        or detail.get("user_email", "")
        or raw.get("query_tag", {}).get("access_method", "")
    )

    # Target: scope for activity_log events
    target = raw.get("scope", "")

    # Build context from all available fields
    context: dict[str, Any] = {}
    if detail:
        context.update(detail)
    if "query_tag" in raw:
        context["query_tag"] = raw["query_tag"]
    if "path" in raw:
        context["path"] = raw["path"]
    if "scope" in raw and raw["source"] == "rate_limit":
        context["throttle_scope"] = raw["scope"]

    # Assign base severity by source type
    severity = Severity.LOW
    if source == "rate_limit":
        severity = Severity.MEDIUM

    return NormalizedEvent(
        timestamp=ts,
        event_type=source,
        event_name=event_name,
        source=source,
        actor=actor,
        target=target,
        context=context,
        severity=severity,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Temporal workflow normalizer
# ---------------------------------------------------------------------------

def _normalize_temporal(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_dt(raw.get("timestamp", ""))

    # Actor: activity_type when running an activity, otherwise workflow_type
    actor = raw.get("activity_type", "") or raw.get("workflow_type", "unknown")

    # Target: bucket destination when available, otherwise workflow_id
    bucket = raw.get("bucket_name", "")
    prefix = raw.get("prefix", "")
    if bucket:
        target = f"s3://{bucket}/{prefix}" if prefix else f"s3://{bucket}"
    else:
        target = raw.get("workflow_id", "")

    # Build context from Temporal-specific fields
    context: dict[str, Any] = {}
    for key in (
        "log_source", "log_source_id",
        "workflow_id", "workflow_run_id", "workflow_type", "workflow_namespace",
        "activity_id", "activity_type", "attempt",
        "task_queue", "team_id",
        "destination", "bucket_name", "prefix", "region",
        "rows_exported", "error",
    ):
        if key in raw and raw[key] != "":
            context[key] = raw[key]

    # Derive event name from the event message
    event_msg = raw.get("event", "unknown")
    if "deletion" in event_msg.lower():
        event_name = "workflow_history_deletion"
    elif "started" in event_msg.lower() and raw.get("activity_type"):
        event_name = "activity_started"
    elif "started" in event_msg.lower():
        event_name = "workflow_started"
    elif "completed" in event_msg.lower():
        event_name = "export_completed"
    elif "failed" in event_msg.lower() or "retrying" in event_msg.lower():
        event_name = "activity_retry"
    else:
        event_name = event_msg

    severity = Severity.LOW
    if raw.get("level") == "warning":
        severity = Severity.MEDIUM
    elif raw.get("level") == "error":
        severity = Severity.HIGH

    return NormalizedEvent(
        timestamp=ts,
        event_type="temporal_workflow",
        event_name=event_name,
        source=raw.get("log_source", "temporal"),
        actor=actor,
        target=target,
        context=context,
        severity=severity,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Celery task normalizer
# ---------------------------------------------------------------------------

def _normalize_celery(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_dt(raw.get("timestamp", ""))
    task_name = raw.get("task_name", "unknown")
    worker = raw.get("worker", "unknown")
    status = raw.get("status", "UNKNOWN")

    # Actor is the worker hostname
    actor = worker

    # Target is the task name plus key args
    kwargs = raw.get("kwargs", {})
    target_parts = [task_name]
    for key in ("person_id", "user_id", "cohort_id", "org_id"):
        if key in kwargs:
            target_parts.append(f"{key}={kwargs[key]}")
    target = " ".join(target_parts)

    context: dict[str, Any] = {
        "task_id": raw.get("task_id", ""),
        "status": status,
        "worker": worker,
        "queue": raw.get("queue", ""),
        "retries": raw.get("retries", 0),
        "runtime": raw.get("runtime"),
        "args": raw.get("args", []),
        "kwargs": kwargs,
        "exception": raw.get("exception"),
        "request_id": raw.get("request_id", ""),
        "task_name": task_name,
    }

    # Assign base severity by status
    severity = Severity.LOW
    if status in ("FAILURE", "RETRY"):
        severity = Severity.MEDIUM

    return NormalizedEvent(
        timestamp=ts,
        event_type="celery_task",
        event_name=status,
        source="celery_task",
        actor=actor,
        target=target,
        context=context,
        severity=severity,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# OTel trace normalizer
# ---------------------------------------------------------------------------

_SENSITIVE_TABLES = ("person", "person_distinct_id")


def _extract_table_from_statement(statement: str) -> str:
    """Extract the primary table name from a SQL statement."""
    if not statement:
        return ""
    upper = statement.upper()
    # Look for FROM <table> pattern
    for keyword in ("FROM ", "JOIN "):
        idx = upper.find(keyword)
        if idx != -1:
            rest = statement[idx + len(keyword):].strip()
            # Take the first word (table name)
            table = rest.split()[0] if rest.split() else ""
            # Strip any trailing parentheses or commas
            return table.strip("(,;")
    return ""


def _normalize_otel(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_dt(raw.get("timestamp", ""))
    attrs = raw.get("attributes", {})
    span_name = raw.get("span_name", "")
    service_name = raw.get("service_name", "")

    # Actor: db.user for ClickHouse spans, service_name for HTTP spans
    actor = attrs.get("db.user", "") or service_name

    # Target: table from db.statement for CH spans, http.url for HTTP spans
    statement = attrs.get("db.statement", "")
    if statement:
        target = _extract_table_from_statement(statement)
    else:
        target = attrs.get("http.url", "")

    # Event name: span_name is the most descriptive
    event_name = span_name

    # Build context with all OTel-relevant fields
    context: dict[str, Any] = {
        "trace_id": raw.get("trace_id", ""),
        "span_id": raw.get("span_id", ""),
        "parent_span_id": raw.get("parent_span_id", ""),
        "service_name": service_name,
        "span_name": span_name,
        "kind": raw.get("kind", ""),
        "duration_ms": raw.get("duration_ms", 0),
        "status": raw.get("status", ""),
    }
    # Merge all attributes into context
    context.update(attrs)

    # Assign base severity
    severity = Severity.LOW
    if raw.get("status") == "ERROR":
        severity = Severity.MEDIUM

    return NormalizedEvent(
        timestamp=ts,
        event_type="otel_span",
        event_name=event_name,
        source="otel_trace",
        actor=actor,
        target=target,
        context=context,
        severity=severity,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Exception + Middleware normalizer
# ---------------------------------------------------------------------------

def _normalize_exception_middleware(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_dt(raw.get("timestamp", ""))
    log_source = raw.get("log_source", "unknown")

    if log_source == "exception_capture":
        event_type = "exception"
        event_name = raw.get("exception_type", "UnknownException")
        actor = raw.get("source_ip", "unknown")
        target = raw.get("path", "")
        additional = raw.get("additional_properties", {})
        context: dict[str, Any] = {
            "exception_type": raw.get("exception_type", ""),
            "exception_message": raw.get("exception_message", ""),
            "event_id": raw.get("event_id", ""),
            "source_ip": raw.get("source_ip", ""),
            "path": raw.get("path", ""),
        }
        if additional:
            context["additional_properties"] = additional
        severity = Severity.LOW

    elif log_source == "request_middleware":
        event_type = "http_request"
        method = raw.get("method", "UNKNOWN")
        path = raw.get("path", "/")
        event_name = f"{method} {path}"
        xff = raw.get("x_forwarded_for", "")
        source_ip = xff.split(",")[0].strip() if xff else ""
        # Actor: prefer user_id if present, otherwise extract IP from x_forwarded_for
        user_id = raw.get("user_id")
        if user_id is not None:
            actor = f"user:{user_id}"
        else:
            actor = source_ip or "unknown"
        target = path
        context = {
            "request_id": raw.get("request_id", ""),
            "method": method,
            "path": path,
            "host": raw.get("host", ""),
            "x_forwarded_for": xff,
            "user_agent": raw.get("user_agent", ""),
            "user_id": raw.get("user_id"),
            "team_id": raw.get("team_id"),
            "status_code": raw.get("status_code"),
            "container_hostname": raw.get("container_hostname", ""),
            "source_ip": source_ip,
        }
        severity = Severity.LOW

    else:
        event_type = log_source
        event_name = "unknown"
        actor = "unknown"
        target = ""
        context = {}
        severity = Severity.LOW

    return NormalizedEvent(
        timestamp=ts,
        event_type=event_type,
        event_name=event_name,
        source=log_source,
        actor=actor,
        target=target,
        context=context,
        severity=severity,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Plugin server normalizer (Pino JSON)
# ---------------------------------------------------------------------------

_PINO_LEVEL_MAP = {
    10: Severity.LOW,       # trace
    20: Severity.LOW,       # debug
    30: Severity.LOW,       # info
    40: Severity.MEDIUM,    # warn
    50: Severity.HIGH,      # error
    60: Severity.CRITICAL,  # fatal
}


def _normalize_plugin_server(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_dt(raw.get("timestamp", ""))

    # Actor: plugin name + source (or component for startup events)
    plugin_name = raw.get("plugin_name", "")
    plugin_source = raw.get("plugin_source", "")
    if plugin_name:
        actor = f"{plugin_name} ({plugin_source})" if plugin_source else plugin_name
    else:
        actor = raw.get("component", "plugin-server")

    # Target: outbound URL, env vars, or empty
    target = ""
    if "outbound_url" in raw:
        target = raw["outbound_url"]
    elif "env_vars_accessed" in raw:
        target = ", ".join(raw["env_vars_accessed"])

    # Derive event name from msg
    msg = raw.get("msg", "")
    msg_lower = msg.lower()
    if "started" in msg_lower and "plugin server" in msg_lower:
        event_name = "plugin_server_start"
    elif "installation" in msg_lower or "installed" in msg_lower:
        event_name = "plugin_install"
    elif "initialized" in msg_lower or "loaded" in msg_lower:
        event_name = "plugin_init"
    elif "outbound" in msg_lower:
        event_name = "plugin_outbound_request"
    elif "env" in msg_lower:
        event_name = "plugin_env_access"
    elif "resource" in msg_lower or "threshold" in msg_lower:
        event_name = "plugin_resource_spike"
    elif "disabled" in msg_lower or "torn down" in msg_lower:
        event_name = "plugin_disabled"
    elif "sandbox" in msg_lower or "violation" in msg_lower:
        event_name = "plugin_sandbox_violation"
    elif "processing" in msg_lower:
        event_name = "plugin_processing"
    else:
        event_name = msg

    # Build context from plugin-specific fields
    context: dict[str, Any] = {}
    for key in (
        "plugin_id", "plugin_name", "plugin_source", "plugin_source_url",
        "event_count", "outbound_url", "http_method", "payload_size_bytes",
        "env_vars_accessed", "memory_mb", "cpu_percent",
        "capabilities", "violation_type", "syscall", "action",
        "requested_by", "component", "version",
    ):
        if key in raw and raw[key] != "":
            context[key] = raw[key]

    # Map Pino numeric level to severity
    pino_level = raw.get("level", 30)
    severity = _PINO_LEVEL_MAP.get(pino_level, Severity.LOW)

    return NormalizedEvent(
        timestamp=ts,
        event_type="plugin_server",
        event_name=event_name,
        source="plugin_server",
        actor=actor,
        target=target,
        context=context,
        severity=severity,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Prometheus metrics normalizer
# ---------------------------------------------------------------------------

def _normalize_prometheus(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_dt(raw.get("timestamp", ""))
    labels = raw.get("labels", {})
    metric_name = raw.get("metric_name", "unknown")
    alert_name = raw.get("alert_name", "")
    anomaly_ratio = raw.get("anomaly_ratio", 1.0)
    value = raw.get("value", 0)
    baseline_value = raw.get("baseline_value", 0)

    # Actor: pod > instance > job
    actor = labels.get("pod", "") or labels.get("instance", "") or labels.get("job", "unknown")

    # Target: metric_name + key distinguishing labels
    target_parts = [metric_name]
    for label_key in ("status", "endpoint", "queue", "container", "interface", "quantile"):
        if label_key in labels:
            target_parts.append(f"{label_key}={labels[label_key]}")
    target = " ".join(target_parts)

    # Event name: prefer alert_name, fall back to metric_name
    if alert_name:
        event_name = alert_name
    else:
        event_name = metric_name

    # Map anomaly_ratio to severity
    if anomaly_ratio > 20:
        severity = Severity.CRITICAL
    elif anomaly_ratio > 10:
        severity = Severity.HIGH
    elif anomaly_ratio > 5:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW

    # Build context with all metric fields
    context: dict[str, Any] = {
        "metric_name": metric_name,
        "labels": labels,
        "value": value,
        "baseline_value": baseline_value,
        "anomaly_ratio": anomaly_ratio,
        "window_seconds": raw.get("window_seconds", 60),
        "alert_name": alert_name,
        "severity_label": raw.get("severity_label", ""),
        "pod": labels.get("pod", ""),
        "instance": labels.get("instance", ""),
        "namespace": labels.get("namespace", ""),
        "job": labels.get("job", ""),
    }

    return NormalizedEvent(
        timestamp=ts,
        event_type="prometheus_metric",
        event_name=event_name,
        source="prometheus_metrics",
        actor=actor,
        target=target,
        context=context,
        severity=severity,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# MCP service normalizer
# ---------------------------------------------------------------------------

_MCP_SENSITIVE_TOOLS = ("get_persons", "get_events")


def _normalize_mcp(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_dt(raw.get("timestamp", ""))
    tool_name = raw.get("tool_name", "")
    method = raw.get("method", "")
    client_name = raw.get("client_name", "unknown")
    client_id = raw.get("client_id", "")
    source_ip = raw.get("source_ip", "")
    status_code = raw.get("status_code", 0)

    # Actor: prefer client_name + client_id, fall back to source_ip
    if client_name and client_name != "unknown":
        actor = f"{client_name} ({client_id})" if client_id else client_name
    else:
        actor = source_ip or "unknown"

    # Target: tool_name + key params (date range, fields)
    params = raw.get("params", {})
    target_parts = [tool_name] if tool_name else [method]
    if "fields" in params:
        target_parts.append(f"fields={params['fields']}")
    if "date_from" in params and "date_to" in params:
        target_parts.append(f"{params['date_from']}..{params['date_to']}")
    target = " ".join(target_parts)

    # Event name from tool_name or method
    event_name = tool_name if tool_name else method

    # Build context from all MCP-specific fields
    context: dict[str, Any] = {
        "request_id": raw.get("request_id", ""),
        "method": method,
        "tool_name": tool_name,
        "params": params,
        "status_code": status_code,
        "duration_ms": raw.get("duration_ms", 0),
        "response_size_bytes": raw.get("response_size_bytes", 0),
        "client_id": client_id,
        "client_name": client_name,
        "source_ip": source_ip,
        "session_token_hash": raw.get("session_token_hash", ""),
        "headers_redacted": raw.get("headers_redacted", {}),
        "team_id": raw.get("team_id"),
    }

    # Map status_code to base severity
    severity = Severity.LOW
    if status_code in (401, 403):
        severity = Severity.MEDIUM

    return NormalizedEvent(
        timestamp=ts,
        event_type="mcp_request",
        event_name=event_name,
        source="mcp_service",
        actor=actor,
        target=target,
        context=context,
        severity=severity,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# HogQL query normalizer
# ---------------------------------------------------------------------------

_HOGQL_INJECTION_PATTERNS = (
    "' OR '", "' AND '", "UNION ALL SELECT", "UNION SELECT",
    "'; DROP", "'; DELETE", "1'='1", "1=1",
)

_PII_PROPERTIES = (
    "$email", "$phone", "$ip", "person_id",
    "$geoip_city_name", "$geoip_country_name", "$name",
)


def _normalize_hogql(raw: dict[str, Any]) -> NormalizedEvent:
    ts = parse_dt(raw.get("timestamp", ""))
    query_tag = raw.get("query_tag", {})
    hogql_query = raw.get("hogql_query", "")
    status = raw.get("status", "unknown")

    actor = query_tag.get("api_key_mask", "") or f"user:{query_tag.get('user_id', 'unknown')}"
    target = hogql_query[:120] if hogql_query else ""

    event_name = "hogql_query"
    if status == "error":
        event_name = "hogql_query_error"

    context: dict[str, Any] = {
        "hogql_query": hogql_query,
        "status": status,
        "query_duration_ms": raw.get("query_duration_ms", 0),
        "read_rows": raw.get("read_rows", 0),
        "result_rows": raw.get("result_rows", 0),
        "query_type": query_tag.get("query_type", ""),
        "access_method": query_tag.get("access_method", ""),
        "api_key_mask": query_tag.get("api_key_mask", ""),
        "team_id": query_tag.get("team_id"),
        "user_id": query_tag.get("user_id"),
        "product": query_tag.get("product", ""),
        "client_query_id": query_tag.get("client_query_id", ""),
        "http_user_agent": raw.get("http_user_agent", ""),
    }
    if "exception_type" in raw:
        context["exception_type"] = raw["exception_type"]
        context["exception_message"] = raw.get("exception_message", "")
    if "timings" in query_tag:
        context["timings"] = query_tag["timings"]

    severity = Severity.LOW
    if status == "error":
        severity = Severity.MEDIUM

    return NormalizedEvent(
        timestamp=ts,
        event_type="hogql_query",
        event_name=event_name,
        source="structlog",
        actor=actor,
        target=target,
        context=context,
        severity=severity,
        raw=raw,
    )


_NORMALIZERS = {
    "cloudtrail": _normalize_cloudtrail,
    "posthog_mixed": _normalize_posthog,
    "temporal_workflow": _normalize_temporal,
    "celery_task": _normalize_celery,
    "otel_trace": _normalize_otel,
    "exception_middleware": _normalize_exception_middleware,
    "plugin_server": _normalize_plugin_server,
    "prometheus_metrics": _normalize_prometheus,
    "mcp_service": _normalize_mcp,
    "hogql_query": _normalize_hogql,
}
