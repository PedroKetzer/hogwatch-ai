from __future__ import annotations

from datetime import datetime

from core.models import Finding, NormalizedEvent, TimelineEntry


def build_timeline(
    events: list[NormalizedEvent], findings: list[Finding]
) -> list[TimelineEntry]:
    """Build a chronological timeline with findings linked to events."""
    if not events:
        return []

    sorted_events = sorted(events, key=lambda e: e.timestamp)
    first_ts = sorted_events[0].timestamp

    # Index findings by event timestamp+name for fast lookup
    finding_index: dict[tuple[datetime, str], list[Finding]] = {}
    for f in findings:
        for evt in f.events:
            key = (evt.timestamp, evt.event_name)
            finding_index.setdefault(key, []).append(f)

    entries: list[TimelineEntry] = []
    for event in sorted_events:
        delta = event.timestamp - first_ts
        total_seconds = int(delta.total_seconds())
        minutes, seconds = divmod(total_seconds, 60)
        hours, minutes = divmod(minutes, 60)

        if hours > 0:
            relative = f"T+{hours}h{minutes:02d}m"
        elif minutes > 0:
            relative = f"T+{minutes}m{seconds:02d}s"
        else:
            relative = f"T+{seconds}s"

        key = (event.timestamp, event.event_name)
        matched_findings = finding_index.get(key, [])
        # Deduplicate findings by rule_id
        seen_rules: set[str] = set()
        unique_findings: list[Finding] = []
        for f in matched_findings:
            if f.rule_id not in seen_rules:
                seen_rules.add(f.rule_id)
                unique_findings.append(f)

        description = _describe_event(event)

        entries.append(
            TimelineEntry(
                timestamp=event.timestamp,
                relative_time=relative,
                description=description,
                event=event,
                findings=unique_findings,
                is_suspicious=len(unique_findings) > 0,
            )
        )

    return entries


def _describe_event(event: NormalizedEvent) -> str:
    """Generate a human-readable description for an event."""
    ctx = event.context

    # CloudTrail events
    if event.event_type == "cloudtrail":
        ip = ctx.get("sourceIPAddress", "")
        uid_type = ctx.get("userIdentityType", "")

        if event.event_name == "AssumeRole":
            if ip == "ec2.amazonaws.com":
                return "EC2 metadata service assumed IAM role (credential provisioning)"
            return f"AssumeRole by {event.actor} from {ip}"

        if event.event_name in ("ListBuckets", "ListObjects"):
            target = event.target or "all buckets"
            return f"S3 {event.event_name} on {target} by {event.actor} from {ip}"

        if event.event_name == "GetObject":
            return f"S3 GetObject (data download) on {event.target} by {event.actor} from {ip}"

        if event.event_name.startswith("Describe"):
            return f"{event.event_name} by {event.actor} from {ip} via {ctx.get('userAgent', 'unknown')[:30]}"

        return f"{event.event_name} by {event.actor} from {ip}"

    # PostHog activity_log
    if event.event_type == "activity_log":
        if event.event_name == "login":
            ua = ctx.get("user_agent", "unknown")
            ip = ctx.get("ip", "unknown")
            return f"Login from {ip} with user-agent {ua}"

        if event.event_name == "updated" and event.target == "PersonalAPIKey":
            changes = ctx.get("changes", [{}])
            if changes:
                c = changes[0]
                return f"API key scope changed: {c.get('before')} → {c.get('after')}"
            return f"PersonalAPIKey updated"

        if event.event_name == "created" and event.target == "BatchExport":
            bucket = ctx.get("bucket_name", "unknown")
            return f"Batch export created → s3://{bucket}/{ctx.get('prefix', '')}"

        if event.event_name == "started" and event.target == "BatchExportRun":
            rows = ctx.get("rows_exported", "?")
            dest = ctx.get("destination", "unknown")
            return f"Batch export run started: {rows} rows → {dest}"

        return f"{event.event_name} on {event.target}"

    # PostHog structlog
    if event.event_type == "structlog":
        path = ctx.get("path", "")
        qt = ctx.get("query_tag", {})
        kind = qt.get("kind", "")
        return f"Query executed: {kind} on {path}" if path else f"Query executed: {kind}"

    # PostHog rate_limit
    if event.event_type == "rate_limit":
        count = ctx.get("count", 0)
        baseline = ctx.get("baseline", 0)
        path = ctx.get("path", "")
        ratio = count / baseline if baseline else 0
        return f"Rate limit exceeded on {path}: {count} reqs ({ratio:.0f}x baseline)"

    # Temporal workflow events
    if event.event_type == "temporal_workflow":
        wf_type = ctx.get("workflow_type", "unknown")
        wf_id = ctx.get("workflow_id", "unknown")
        task_q = ctx.get("task_queue", "unknown")
        activity = ctx.get("activity_type", "")
        attempt = ctx.get("attempt", 1)
        bucket = ctx.get("bucket_name", "")
        prefix = ctx.get("prefix", "")
        rows = ctx.get("rows_exported", "")

        if event.event_name == "workflow_started":
            return f"Temporal workflow started: {wf_type} (queue: {task_q})"

        if event.event_name == "activity_started":
            return f"Activity {activity} attempt #{attempt} on workflow {wf_id}"

        if event.event_name == "activity_retry":
            error = ctx.get("error", "unknown error")
            return f"Activity {activity} attempt #{attempt} on workflow {wf_id} — {error}"

        if event.event_name == "export_completed":
            if rows and bucket:
                return f"Batch export completed: {rows} rows → s3://{bucket}/{prefix}"
            return f"Batch export completed on workflow {wf_id}"

        if event.event_name == "workflow_history_deletion":
            return f"Workflow history deletion requested for {wf_id}"

        return f"{event.event_name} on workflow {wf_id}"

    # Celery task events
    if event.event_type == "celery_task":
        task_name = ctx.get("task_name", "unknown")
        worker = ctx.get("worker", "unknown")
        queue = ctx.get("queue", "")
        status = ctx.get("status", "")
        runtime = ctx.get("runtime")
        retries = ctx.get("retries", 0)
        exception = ctx.get("exception")

        if status == "STARTED":
            return f"Celery task started: {task_name} on worker {worker} (queue: {queue})"
        if status == "SUCCESS":
            runtime_str = f"{runtime}s" if runtime is not None else "?s"
            return f"Task completed: {task_name} in {runtime_str}"
        if status == "FAILURE":
            exc_str = exception or "unknown error"
            return f"Task FAILED: {task_name} — {exc_str}"
        if status == "RETRY":
            return f"Task retry #{retries}: {task_name} on {worker}"

        return f"Celery task {status}: {task_name} on {worker}"

    # OTel span events
    if event.event_type == "otel_span":
        span_name = ctx.get("span_name", "")
        service = ctx.get("service_name", "")
        duration = ctx.get("duration_ms", 0)
        status = ctx.get("status", "")

        # Error span
        if status == "ERROR":
            error_msg = ctx.get("clickhouse.error_message", "") or ctx.get("error_message", "")
            return f"Span ERROR: {span_name} — {error_msg}" if error_msg else f"Span ERROR: {span_name}"

        # ClickHouse span
        if ctx.get("db.system") == "clickhouse":
            query_type = ctx.get("clickhouse.query_type", "Other")
            db_name = ctx.get("db.name", "unknown")
            result_rows = ctx.get("clickhouse.result_rows", "?")
            exec_time = ctx.get("clickhouse.execution_time_ms", "?")
            return (
                f"ClickHouse query: {query_type} on {db_name} "
                f"— {result_rows} rows in {exec_time}ms"
            )

        # HTTP span
        method = ctx.get("http.method", "")
        url = ctx.get("http.url", "")
        if method and url:
            status_code = ctx.get("http.status_code", "?")
            return f"HTTP {method} {url} [{status_code}] ({duration}ms) via {service}"

        return f"{span_name} ({duration}ms) via {service}"

    # Exception capture events
    if event.event_type == "exception":
        exc_type = ctx.get("exception_type", "Unknown")
        exc_msg = ctx.get("exception_message", "")
        exc_msg_truncated = exc_msg[:80] + "..." if len(exc_msg) > 80 else exc_msg
        path = ctx.get("path", "unknown")
        source_ip = ctx.get("source_ip", "unknown")
        return f"Exception {exc_type}: {exc_msg_truncated} on {path} from {source_ip}"

    # HTTP request middleware events
    if event.event_type == "http_request":
        method = ctx.get("method", "?")
        path = ctx.get("path", "/")
        status_code = ctx.get("status_code", "?")
        source_ip = ctx.get("source_ip", "") or ctx.get("x_forwarded_for", "unknown")
        user_agent = ctx.get("user_agent", "unknown")
        ua_truncated = user_agent[:40] + "..." if len(user_agent) > 40 else user_agent

        # Highlight internal endpoint access
        internal_prefixes = ("/_internal/", "/debug/", "/_health")
        if any(path.startswith(p) for p in internal_prefixes):
            return f"Internal endpoint access: {method} {path} from {source_ip}"

        return f"HTTP {method} {path} [{status_code}] from {source_ip} (UA: {ua_truncated})"

    # Plugin server events
    if event.event_type == "plugin_server":
        plugin_name = ctx.get("plugin_name", "")
        plugin_source = ctx.get("plugin_source", "")
        plugin_source_url = ctx.get("plugin_source_url", "")

        if event.event_name == "plugin_server_start":
            pid = event.raw.get("pid", "?")
            hostname = event.raw.get("hostname", "?")
            return f"Plugin server started (PID: {pid}, host: {hostname})"

        if event.event_name == "plugin_install":
            return (
                f"Plugin installed: {plugin_name} from {plugin_source} "
                f"({plugin_source_url})"
            )

        if event.event_name == "plugin_init":
            return f"Plugin initialized: {plugin_name} ({plugin_source})"

        if event.event_name == "plugin_processing":
            event_count = ctx.get("event_count", "?")
            return f"Plugin {plugin_name}: processed {event_count} events"

        if event.event_name == "plugin_outbound_request":
            outbound_url = ctx.get("outbound_url", "?")
            return f"Plugin {plugin_name}: outbound HTTP to {outbound_url}"

        if event.event_name == "plugin_env_access":
            env_vars = ctx.get("env_vars_accessed", [])
            return f"Plugin {plugin_name}: accessed env vars {env_vars}"

        if event.event_name == "plugin_resource_spike":
            memory_mb = ctx.get("memory_mb", "?")
            cpu_percent = ctx.get("cpu_percent", "?")
            return (
                f"Plugin {plugin_name}: resource spike "
                f"— {memory_mb}MB / {cpu_percent}% CPU"
            )

        if event.event_name == "plugin_sandbox_violation":
            msg = event.raw.get("msg", "unknown violation")
            return f"Plugin {plugin_name}: SANDBOX VIOLATION — {msg}"

        if event.event_name == "plugin_disabled":
            return f"Plugin {plugin_name}: disabled and torn down"

        return f"Plugin {plugin_name}: {event.raw.get('msg', event.event_name)}"

    # Prometheus metric events
    if event.event_type == "prometheus_metric":
        metric_name = ctx.get("metric_name", "unknown")
        alert_name = ctx.get("alert_name", "")
        value = ctx.get("value", "?")
        baseline_value = ctx.get("baseline_value", "?")
        anomaly_ratio = ctx.get("anomaly_ratio", 1.0)
        pod = ctx.get("pod", "") or ctx.get("instance", "unknown")

        if alert_name and anomaly_ratio > 5:
            return (
                f"Prometheus alert: {alert_name} — {metric_name} at {value} "
                f"({anomaly_ratio}x baseline) on {pod}"
            )

        return (
            f"Prometheus metric: {metric_name} at {value} "
            f"(baseline: {baseline_value}) on {pod}"
        )

    # MCP request events
    if event.event_type == "mcp_request":
        tool_name = ctx.get("tool_name", "unknown")
        client_name = ctx.get("client_name", "unknown")
        status_code = ctx.get("status_code", "?")
        duration_ms = ctx.get("duration_ms", 0)
        response_size_bytes = ctx.get("response_size_bytes", 0)
        source_ip = ctx.get("source_ip", "unknown")

        # Auth failure
        if status_code in (401, 403):
            return f"MCP auth failure: {tool_name} from {source_ip} [{status_code}]"

        # Heavy extraction: >1MB or >30s
        if response_size_bytes > 1_000_000 or duration_ms > 30_000:
            return (
                f"MCP heavy request: {tool_name} by {client_name} "
                f"— {response_size_bytes}B in {duration_ms}ms"
            )

        # Normal call
        return (
            f"MCP tool call: {tool_name} by {client_name} "
            f"[{status_code}] ({duration_ms}ms, {response_size_bytes}B)"
        )

    # HogQL query events
    if event.event_type == "hogql_query":
        query = ctx.get("hogql_query", "")
        status = ctx.get("status", "unknown")
        result_rows = ctx.get("result_rows", 0)
        duration_ms = ctx.get("query_duration_ms", 0)
        api_key = ctx.get("api_key_mask", "unknown")

        query_preview = query[:80] + "..." if len(query) > 80 else query

        if status == "error":
            exc_type = ctx.get("exception_type", "Error")
            exc_msg = ctx.get("exception_message", "")[:60]
            return f"HogQL ERROR ({exc_type}): {query_preview} — {exc_msg}"

        if result_rows > 10_000:
            return (
                f"HogQL bulk query: {result_rows:,} rows in {duration_ms}ms "
                f"— {query_preview}"
            )

        return (
            f"HogQL query [{status}]: {result_rows:,} rows in {duration_ms}ms "
            f"— {query_preview}"
        )

    return f"{event.event_name} ({event.event_type})"
