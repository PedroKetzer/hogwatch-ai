from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from core.models import Finding, InvestigationResult, Severity, TimelineEntry

_RULE_RECOMMENDATIONS: dict[str, list[str]] = {
    # AWS
    "AWS-001": [
        "Rotate the compromised IAM role credentials immediately",
        "Enforce IMDSv2 on all EC2 instances to prevent SSRF-based credential theft",
        "Review VPC security groups for overly permissive inbound rules",
    ],
    "AWS-002": [
        "Audit AssumeRole trust policies for overly broad principals",
        "Enable CloudTrail event alerting for burst AssumeRole patterns",
    ],
    "AWS-003": [
        "Enable S3 server access logging on all buckets",
        "Apply least-privilege bucket policies — restrict ListBuckets and GetObject",
        "Consider S3 Object Lock for critical data",
    ],
    "AWS-004": [
        "Review IAM permissions — restrict Describe* to least-privilege",
        "Set up CloudWatch alarms for reconnaissance-pattern API calls",
    ],
    "AWS-CHAIN": [
        "Treat as confirmed compromise — activate incident response playbook",
        "Isolate affected EC2 instance and revoke all associated credentials",
        "Forensic snapshot of the instance before termination",
    ],
    # PostHog
    "PH-001": [
        "Investigate the source of scripted login — verify if authorized automation",
        "Enforce MFA or restrict API access by IP allowlist",
    ],
    "PH-002": [
        "Block or challenge API requests from unrecognized IPs",
        "Implement IP-based rate limiting for API key authentication",
    ],
    "PH-003": [
        "Review rate limit thresholds — current spike suggests automated scraping",
        "Implement progressive rate limiting with exponential backoff",
    ],
    "PH-004": [
        "Immediately revoke the escalated API key",
        "Audit all API key scope changes in the last 30 days",
        "Implement approval workflow for scope escalations",
    ],
    "PH-005": [
        "Review what person data was accessed and assess PII exposure",
        "Restrict persons endpoint access to session-authenticated users only",
    ],
    "PH-006": [
        "Pause or cancel the batch export immediately",
        "Verify the S3 destination bucket ownership",
        "Implement an allowlist for batch export destinations",
    ],
    "PH-CHAIN": [
        "Treat as confirmed data breach — activate incident response",
        "Revoke all API keys associated with the compromised account",
        "Notify affected users per data breach notification requirements",
    ],
    # MCP
    "MCP-001": [
        "Invalidate the reused session token",
        "Investigate whether the session was hijacked or shared",
    ],
    "MCP-002": [
        "Rate-limit MCP tool calls per client session",
        "Review whether the rapid calls indicate automated extraction",
    ],
    "MCP-003": [
        "Implement response size limits on sensitive MCP tools",
        "Add data loss prevention controls for bulk data responses",
    ],
    "MCP-004": [
        "Block the offending client and revoke session tokens",
        "Implement anomaly detection on MCP tool usage patterns",
    ],
    # Temporal
    "TW-001": [
        "Verify the batch export destination is authorized",
        "Implement destination allowlisting for Temporal workflows",
    ],
    "TW-002": [
        "Investigate excessive retry attempts — may indicate injection",
        "Set maximum retry limits on sensitive workflows",
    ],
    "TW-003": [
        "Recover deleted workflow history from backups",
        "Restrict workflow history deletion to admin roles only",
    ],
    "TW-CHAIN": [
        "Treat as confirmed workflow hijacking — pause affected workflows",
        "Audit all Temporal workflow configurations",
    ],
    # Celery
    "CT-001": [
        "Investigate the unknown worker — verify it belongs to the cluster",
        "Restrict Celery broker access to known worker hostnames",
    ],
    "CT-002": [
        "Review the failing task for misuse or injection",
        "Set hard retry limits and alert on retry storms",
    ],
    "CT-003": [
        "Audit who triggered the sensitive task and verify authorization",
        "Restrict sensitive tasks to specific queues with tighter access controls",
    ],
    "CT-004": [
        "Treat as confirmed task queue compromise — rotate broker credentials",
        "Isolate affected workers and review task execution logs",
    ],
    # OTel
    "OT-001": [
        "Review the bulk extraction query and requester identity",
        "Implement row-count limits on ClickHouse queries via OTel",
    ],
    "OT-002": [
        "Audit access to sensitive tables — restrict to authorized services",
        "Add query-level access controls for PII-containing tables",
    ],
    "OT-003": [
        "Investigate the unexpected service — may be unauthorized",
        "Maintain a service registry and alert on unknown service names",
    ],
    "OT-004": [
        "Treat as confirmed data extraction — assess data exposure",
        "Implement query auditing and DLP for ClickHouse",
    ],
    # Exception/Middleware
    "EM-001": [
        "Investigate the exception spike for underlying cause",
        "Set up alerting for exception rate anomalies",
    ],
    "EM-002": [
        "Block the source IP — SQL injection attempt detected",
        "Review WAF rules and enable parameterized query enforcement",
    ],
    "EM-003": [
        "Block external access to internal endpoints immediately",
        "Review reverse proxy configuration for path traversal",
    ],
    "EM-004": [
        "Treat as confirmed middleware exploitation — review access logs",
        "Harden middleware configuration and restrict internal routes",
    ],
    # Plugin Server
    "PS-001": [
        "Remove the untrusted plugin immediately",
        "Implement plugin signing and source verification",
    ],
    "PS-002": [
        "Block outbound connections from the plugin server to unknown domains",
        "Implement egress filtering for plugin server workloads",
    ],
    "PS-003": [
        "Revoke any credentials the plugin may have accessed",
        "Sandbox plugin execution to prevent environment variable access",
    ],
    "PS-004": [
        "Treat as confirmed plugin compromise — disable all untrusted plugins",
        "Implement plugin sandboxing with network and filesystem isolation",
    ],
    # Prometheus
    "PM-001": [
        "Investigate the source of authentication failures",
        "Implement account lockout after repeated failures",
    ],
    "PM-002": [
        "Review network egress for data exfiltration indicators",
        "Implement egress monitoring and bandwidth alerting",
    ],
    "PM-003": [
        "Investigate the resource consumption anomaly — possible cryptomining",
        "Set resource quotas and alert on CPU/memory spikes",
    ],
    # HogQL
    "HQL-001": [
        "Block the API key used for injection probing immediately",
        "Review HogQL endpoints for f-string injection vulnerabilities (see .semgrep/rules/hogql-no-fstring.yaml)",
        "Ensure all user input flows through ast.Constant/ast.Field placeholders, never f-strings",
    ],
    "HQL-002": [
        "Revoke the API key and audit all queries executed by this user",
        "Restrict PII property access in HogQL to authorized roles only",
        "Implement query-level DLP to detect bulk PII selection patterns",
    ],
    "HQL-003": [
        "Implement result row limits on HogQL API queries",
        "Add query cost estimation and reject queries exceeding thresholds",
        "Alert on HogQL queries returning >10k rows via API key access",
    ],
    "HQL-CHAIN": [
        "Treat as confirmed data breach — activate incident response",
        "Revoke all API keys for the compromised user account",
        "Audit all HogQL parse_expr/parse_select call sites for f-string injection",
        "Assess PII exposure and notify affected users per breach requirements",
    ],
}


def generate_report(
    metadata: dict[str, Any],
    timeline: list[TimelineEntry],
    findings: list[Finding],
    investigation: InvestigationResult | None = None,
) -> str:
    """Generate a markdown incident report."""
    parts: list[str] = []

    title = metadata.get("title", "Unknown Incident")
    parts.append(f"# Incident Report — {title}")
    parts.append(f"\n*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    parts.append(f"*Dataset: {metadata.get('dataset_ref', metadata.get('inspired_by', 'N/A'))}*")
    parts.append(f"*MITRE Techniques: {', '.join(metadata.get('mitre_techniques', []))}*")

    # Executive Summary
    parts.append("\n## Executive Summary\n")
    if investigation and investigation.summary:
        parts.append(investigation.summary)
    else:
        severity_counts = _count_severities(findings)
        parts.append(
            f"Automated analysis of {len(timeline)} events detected "
            f"**{len(findings)} findings**: "
            + ", ".join(f"{count} {sev}" for sev, count in severity_counts.items() if count > 0)
            + "."
        )

    # Timeline
    parts.append("\n## Timeline\n")
    parts.append("| Time | Relative | Event | Findings |")
    parts.append("|------|----------|-------|----------|")
    for entry in timeline:
        ts = entry.timestamp.strftime("%H:%M:%S")
        finding_tags = ""
        if entry.findings:
            tags = [f"`{f.rule_id}`" for f in entry.findings]
            finding_tags = " ".join(tags)
        marker = " **!!**" if entry.is_suspicious else ""
        parts.append(
            f"| {ts} | {entry.relative_time} | {entry.description[:70]} | {finding_tags}{marker} |"
        )

    # Findings
    parts.append("\n## Detection Findings\n")
    # Sort by severity (critical first)
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 4))

    for f in sorted_findings:
        icon = _severity_icon(f.severity)
        parts.append(f"### {icon} [{f.severity.value.upper()}] {f.rule_id} — {f.title}\n")
        parts.append(f"{f.description}\n")
        parts.append(f"**MITRE ATT&CK**: {f.mitre_technique}\n")

    # AI Analysis
    if investigation:
        parts.append("\n## AI Investigation Analysis\n")

        if investigation.attack_path:
            parts.append("### Attack Path\n")
            parts.append(investigation.attack_path)
            parts.append("")

        if investigation.is_malicious:
            parts.append(
                f"### Assessment: **MALICIOUS** (confidence: {investigation.confidence})\n"
            )
        else:
            parts.append(
                f"### Assessment: **Likely benign** (confidence: {investigation.confidence})\n"
            )

        if investigation.impact_assessment:
            parts.append("### Impact Assessment\n")
            parts.append(investigation.impact_assessment)
            parts.append("")

        if investigation.mitre_techniques:
            parts.append("### MITRE ATT&CK Mapping\n")
            for t in investigation.mitre_techniques:
                parts.append(f"- {t}")
            parts.append("")

    # Recommended Actions
    parts.append("\n## Recommended Actions\n")
    if investigation and investigation.immediate_actions:
        parts.append("### Immediate\n")
        for action in investigation.immediate_actions:
            parts.append(f"- {action}")
        parts.append("")

    if investigation and investigation.long_term_recommendations:
        parts.append("### Long-term\n")
        for rec in investigation.long_term_recommendations:
            parts.append(f"- {rec}")
    elif not investigation:
        immediate: list[str] = []
        long_term: list[str] = []
        seen_rules: set[str] = set()
        for f in sorted_findings:
            if f.rule_id in seen_rules:
                continue
            seen_rules.add(f.rule_id)
            recs = _RULE_RECOMMENDATIONS.get(f.rule_id)
            if not recs:
                continue
            immediate.append(recs[0])
            long_term.extend(recs[1:])

        if immediate:
            parts.append("### Immediate\n")
            for action in immediate:
                parts.append(f"- {action}")
            parts.append("")

        if long_term:
            parts.append("### Long-term\n")
            for rec in long_term:
                parts.append(f"- {rec}")
            parts.append("")

        if not immediate and not long_term:
            parts.append("*No static recommendations available for the detected rules.*")

    parts.append("\n---\n*Generated by hogwatch-ai*")
    return "\n".join(parts)


def save_report(content: str, output_dir: str = "output") -> Path:
    """Save report to output directory, return path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = out / f"report_{ts}.md"
    path.write_text(content)
    return path


def _count_severities(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        label = f.severity.value
        counts[label] = counts.get(label, 0) + 1
    return counts


def _severity_icon(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "[!!!]",
        Severity.HIGH: "[!!]",
        Severity.MEDIUM: "[!]",
        Severity.LOW: "[.]",
    }.get(severity, "")
