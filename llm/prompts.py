from __future__ import annotations

from typing import Any

from core.models import Finding, TimelineEntry

SYSTEM_PROMPT = """\
You are an expert security analyst specializing in cloud security, incident response, \
and the MITRE ATT&CK framework. You work at a fast-growing SaaS company that runs on AWS.

When presented with a security timeline and detection findings, you provide:
1. A concise executive summary
2. A clear attack path narrative
3. A malicious/benign assessment with confidence level
4. MITRE ATT&CK technique mapping
5. Impact assessment
6. Immediate and long-term remediation recommendations

Be specific and actionable. Reference actual event details from the timeline. \
Format your response using the exact section headers specified in the prompt.
"""


def build_investigation_prompt(
    timeline: list[TimelineEntry],
    findings: list[Finding],
    metadata: dict[str, Any],
) -> str:
    """Build the user prompt for LLM investigation."""
    parts: list[str] = []

    # Scenario context
    parts.append(f"# Incident Investigation: {metadata.get('title', 'Unknown')}")
    parts.append(f"\n**Scenario**: {metadata.get('description', '')}")
    parts.append(
        f"**MITRE Techniques Referenced**: {', '.join(metadata.get('mitre_techniques', []))}"
    )

    # Timeline
    parts.append("\n## Event Timeline\n")
    parts.append("| Time | Relative | Event | Suspicious |")
    parts.append("|------|----------|-------|------------|")
    for entry in timeline:
        flag = "!!" if entry.is_suspicious else ""
        ts = entry.timestamp.strftime("%H:%M:%S")
        desc = entry.description[:80]
        parts.append(f"| {ts} | {entry.relative_time} | {desc} | {flag} |")

    # Findings
    parts.append("\n## Detection Findings\n")
    for f in findings:
        parts.append(
            f"- **[{f.severity.value.upper()}] {f.rule_id}** — {f.title}\n"
            f"  {f.description}\n"
            f"  MITRE: {f.mitre_technique}"
        )

    # Questions
    parts.append("\n## Investigation Questions\n")
    parts.append(
        "Please analyze the above timeline and findings, then respond with "
        "the following sections (use these exact headers):\n"
    )
    parts.append("### SUMMARY\nProvide a 2-3 sentence executive summary of the incident.\n")
    parts.append("### ATTACK_PATH\nDescribe the attack path step by step.\n")
    parts.append(
        "### IS_MALICIOUS\nState YES or NO, followed by your confidence "
        "(HIGH/MEDIUM/LOW) and reasoning.\n"
    )
    parts.append(
        "### IMPACT_ASSESSMENT\nDescribe the potential impact of this incident.\n"
    )
    parts.append(
        "### MITRE_TECHNIQUES\nList each MITRE ATT&CK technique observed, "
        "one per line, format: T####.### - Name - Description of how it was used.\n"
    )
    parts.append(
        "### IMMEDIATE_ACTIONS\nList immediate response actions, one per line.\n"
    )
    parts.append(
        "### LONG_TERM_RECOMMENDATIONS\nList long-term security improvements, "
        "one per line.\n"
    )

    return "\n".join(parts)
