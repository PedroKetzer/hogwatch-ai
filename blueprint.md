# hogwatch-ai — Project Blueprint

## 1. Overview

hogwatch-ai is a lightweight CLI tool that simulates and investigates cloud and product-level security incidents using LLMs.

Built to demonstrate how small security teams can scale incident response without a traditional SOC by combining:

* Detection heuristics
* Timeline reconstruction
* AI-assisted investigation
* Real-time simulation of attack progression

This is a **demonstration tool**, not a production SIEM.

---

## 2. Scope

### INCLUDED
* Static scenarios (JSON) grounded in **real security datasets**
* Hand-written detection rules mapped to MITRE ATT&CK
* Timeline reconstruction
* LLM-based investigation (Claude)
* CLI interface with simulate mode (fake real-time replay)

### EXCLUDED
* Real PostHog/AWS integration
* PostgreSQL queries, Docker log parsing
* Live ingestion pipeline

---

## 3. Architecture

```
hogwatch-ai/
├── pyproject.toml
├── cmd/main.py              # Click CLI entrypoint
├── core/
│   ├── __init__.py
│   ├── models.py            # Pydantic models
│   ├── parser.py            # Load + normalize JSON logs
│   ├── detector.py          # Detection rules
│   ├── timeline.py          # Event ordering + formatting
│   └── report.py            # Markdown report generator
├── llm/
│   ├── __init__.py
│   ├── client.py            # Anthropic SDK wrapper
│   └── prompts.py           # Prompt templates
├── data/
│   ├── scenario_1.json      # AWS SSRF → S3 exfiltration (real CloudTrail)
│   └── scenario_2.json      # PostHog API key abuse (synthetic, GoldenSAML-inspired)
└── output/
    └── .gitkeep
```

### Dependencies
`click`, `anthropic`, `rich`, `python-dateutil`, `pydantic`

---

## 4. Scenarios

Both scenarios are grounded in real datasets from the [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) project.

---

### Scenario 1 — AWS SSRF → Credential Theft → S3 Exfiltration

**Dataset source**: `SDAWS-200914011940` — AWS Cloud Bank Breach S3
**MITRE**: T1078.004 (Valid Accounts: Cloud), T1530 (Data from Cloud Storage)

#### Story

An attacker exploits a misconfigured EC2 reverse proxy (nginx) to reach the instance metadata service (169.254.169.254), steals the IAM role's temporary credentials, then uses them to enumerate and exfiltrate data from S3 buckets.

#### Real Data Profile (103 CloudTrail events)

| Phase | Events | Key Fields |
|-------|--------|------------|
| **Recon** (lines 1-39) | EC2 Describe* calls by IAM user `pedro` from `1.2.3.4` via console | `userIdentity.type: IAMUser`, `mfaAuthenticated: true` |
| **Credential Theft** (lines 40-44) | 5x `AssumeRole` from `ec2.amazonaws.com` (metadata service) | `userIdentity.type: AWSService`, `sourceIPAddress: ec2.amazonaws.com` |
| **S3 Enumeration** (lines 45-102) | `ListBuckets`, `ListObjects` using stolen role credentials from `1.2.3.4` | `userIdentity.type: AssumedRole`, `arn: ...MordorNginxStack-BankingWAFRole-...` |
| **Exfiltration** (lines 80, 103) | `GetObject` on S3 bucket data | Same assumed role, `eventSource: s3.amazonaws.com` |

#### Detection Rules

| Rule ID | Severity | Trigger | MITRE |
|---------|----------|---------|-------|
| `AWS-001` | HIGH | EC2 role credentials used from external IP (not `ec2.amazonaws.com`) | T1078.004 |
| `AWS-002` | MEDIUM | `AssumeRole` burst (>3 in 5min) from service | T1550.001 |
| `AWS-003` | HIGH | `ListBuckets` + `ListObjects` + `GetObject` chain by assumed role | T1530 |
| `AWS-004` | MEDIUM | Recon burst: >10 Describe* calls in 60s | T1580 |
| `AWS-CHAIN` | CRITICAL | Composite: AWS-001 + AWS-003 in same session → full attack chain | T1078 → T1530 |

#### data/scenario_1.json Format

Use the **real CloudTrail events** from the dataset, wrapped in a scenario envelope:

```json
{
  "metadata": {
    "id": "scenario_1",
    "title": "AWS SSRF to S3 Exfiltration",
    "source_type": "cloudtrail",
    "dataset_ref": "SDAWS-200914011940",
    "mitre_techniques": ["T1078.004", "T1530", "T1580"]
  },
  "events": [
    // Real CloudTrail JSON objects from ec2_proxy_s3_exfiltration.zip
    // Each line is a complete CloudTrail event with:
    //   eventName, eventSource, sourceIPAddress, userIdentity, @timestamp,
    //   requestParameters, responseElements, etc.
  ]
}
```

---

### Scenario 2 — PostHog API Key Compromise → Data Exfiltration

**Inspired by**: `GoldenSAMLADFSMailAccess` compound dataset
**Pattern**: credential theft → permission escalation → impersonation → data exfiltration via API
**MITRE**: T1552 (Unsecured Credentials), T1098 (Account Manipulation), T1530 (Data from Cloud Storage)

The GoldenSAML attack pattern (steal ADFS cert → forge SAML token → grant Mail.ReadWrite → read mailbox) is translated to PostHog's domain:

| GoldenSAML Step | PostHog Equivalent |
|-----------------|-------------------|
| Steal AD FS token signing cert | Compromised `PersonalAPIKey` via leaked `.env` |
| Forge SAML token for user | Use API key from unusual IP with script user-agent |
| Grant `Mail.ReadWrite` permission | Escalate API key scope from `query:read` to `*` |
| Access mailbox via Graph API | Batch export person data to external S3 |

#### Story

An attacker finds a PostHog PersonalAPIKey in a public GitHub commit. They use it from a foreign IP to probe the API, escalate the key's scope, query sensitive person data, and create a batch export to an external S3 bucket they control.

#### Attack Flow (synthetic events using real PostHog log formats)

| # | Time | Event | Log Source | PostHog Model |
|---|------|-------|-----------|---------------|
| 1 | T+0m | Login from unusual IP (`203.0.113.10`) with `python-requests/2.28` user-agent | `activity_log` | `UserLoginContext` |
| 2 | T+2m | API queries via personal key — unusual `access_method: personal_api_key` | `structlog` | `QueryTags` |
| 3 | T+5m | Rate limit exceeded spike (10x baseline) | `rate_limit` | `RATE_LIMIT_EXCEEDED_COUNTER` |
| 4 | T+8m | API key scope changed from `["query:read"]` to `["*"]` | `activity_log` | `PersonalAPIKey` scope |
| 5 | T+12m | Query on `/api/projects/{id}/persons/` with `$distinct_id` filter | `structlog` | persons endpoint |
| 6 | T+15m | Batch export created → destination: `s3://attacker-bucket-ext` | `activity_log` | `BatchExportDestination` |
| 7 | T+18m | Batch export run started — 50k rows | `activity_log` | `BatchExportRun` |

#### Detection Rules

| Rule ID | Severity | Trigger | MITRE |
|---------|----------|---------|-------|
| `PH-001` | MEDIUM | Login with script user-agent (`python-requests`, `curl`, `httpie`) | T1078 |
| `PH-002` | MEDIUM | API key usage from IP not in known list | T1552 |
| `PH-003` | LOW | Rate limit spike (>5x baseline in 5min window) | T1499 |
| `PH-004` | CRITICAL | API key scope escalation (any → `*` or adding `write` scopes) | T1098 |
| `PH-005` | HIGH | Query on persons/sensitive endpoint via API key | T1530 |
| `PH-006` | HIGH | Batch export to non-allowlisted S3 destination | T1537 |
| `PH-CHAIN` | CRITICAL | Composite: PH-001 + PH-004 + PH-006 → full attack chain | T1552 → T1098 → T1537 |

#### data/scenario_2.json Format

Synthetic events using real PostHog field names:

```json
{
  "metadata": {
    "id": "scenario_2",
    "title": "PostHog API Key Compromise",
    "source_type": "posthog_mixed",
    "inspired_by": "GoldenSAMLADFSMailAccess",
    "mitre_techniques": ["T1552", "T1098", "T1530", "T1537"]
  },
  "events": [
    {
      "timestamp": "2026-03-11T14:00:00Z",
      "source": "activity_log",
      "activity": "login",
      "scope": "User",
      "detail": {
        "ip": "203.0.113.10",
        "user_agent": "python-requests/2.28.1",
        "access_method": "personal_api_key",
        "api_key_mask": "phx_...k9Zm"
      }
    },
    {
      "timestamp": "2026-03-11T14:02:00Z",
      "source": "structlog",
      "event": "query_executed",
      "query_tag": {
        "kind": "EventsQuery",
        "access_method": "personal_api_key",
        "product": "api",
        "team_id": 1
      }
    },
    {
      "timestamp": "2026-03-11T14:05:00Z",
      "source": "rate_limit",
      "event": "rate_limit_exceeded",
      "scope": "burst",
      "path": "/api/projects/1/events/",
      "count": 847,
      "baseline": 80
    },
    {
      "timestamp": "2026-03-11T14:08:00Z",
      "source": "activity_log",
      "activity": "updated",
      "scope": "PersonalAPIKey",
      "detail": {
        "changes": [
          {
            "field": "scopes",
            "before": ["query:read"],
            "after": ["*"]
          }
        ],
        "api_key_mask": "phx_...k9Zm"
      }
    },
    {
      "timestamp": "2026-03-11T14:12:00Z",
      "source": "structlog",
      "event": "query_executed",
      "path": "/api/projects/1/persons/",
      "query_tag": {
        "kind": "PersonsQuery",
        "access_method": "personal_api_key",
        "filter": "$distinct_id"
      }
    },
    {
      "timestamp": "2026-03-11T14:15:00Z",
      "source": "activity_log",
      "activity": "created",
      "scope": "BatchExport",
      "detail": {
        "destination_type": "S3",
        "bucket_name": "attacker-bucket-ext",
        "region": "eu-west-1",
        "prefix": "exfil/"
      }
    },
    {
      "timestamp": "2026-03-11T14:18:00Z",
      "source": "activity_log",
      "activity": "started",
      "scope": "BatchExportRun",
      "detail": {
        "rows_exported": 50000,
        "destination": "s3://attacker-bucket-ext/exfil/"
      }
    }
  ]
}
```

---

## 5. Detection Engine (`core/detector.py`)

Decorator-based rule registry. Each rule is a function that receives a list of `NormalizedEvent` and returns `Finding[]`.

```python
@register_rule("AWS-001", severity="high", mitre="T1078.004")
def detect_stolen_ec2_credentials(events):
    """EC2 role credentials used from external IP"""
    ...
```

### Correlation Engine

After individual rules fire, a correlation pass checks for composite attack chains:
- `AWS-CHAIN`: AWS-001 + AWS-003 in same session
- `PH-CHAIN`: PH-001 + PH-004 + PH-006 by same actor

---

## 6. Timeline Builder (`core/timeline.py`)

* Sort events by timestamp
* Compute relative time from first event (`T+0m`, `T+2m`, ...)
* Generate human-readable descriptions
* Mark suspicious events (linked to findings)

---

## 7. LLM Investigation (`llm/`)

System prompt: security analyst persona with MITRE ATT&CK knowledge.

User prompt includes: timeline, findings, raw context, then structured questions:
* What happened? (summary)
* Is this malicious? (confidence level)
* Attack path diagram
* MITRE technique mapping
* Impact assessment
* Immediate + long-term remediation

Supports `--no-llm` flag to skip (outputs findings + timeline only).

---

## 8. Report Generation (`core/report.py`)

Markdown output to `output/`:

```
# Incident Report — {scenario_title}

## Executive Summary
## Timeline
## Detection Findings
## AI Investigation Analysis
## Recommended Actions
```

---

## 9. CLI Usage

```bash
python cmd/main.py investigate data/scenario_1.json            # Full pipeline
python cmd/main.py investigate data/scenario_1.json --no-llm   # Skip LLM
python cmd/main.py simulate data/scenario_2.json               # Fake real-time replay
python cmd/main.py simulate data/scenario_2.json --delay 1     # Faster replay
python cmd/main.py list-scenarios                               # List available scenarios
```

**Simulate mode**: replays events one-by-one with `rich` formatting and configurable delay (`--delay`, default 2s). Runs detection incrementally after each event so findings appear as they would in a live stream. At the end, runs the full investigation pipeline.

---

## 10. Key Design Decisions

* **Real data where possible**: Scenario 1 uses actual CloudTrail from OTRF Security-Datasets
* **Realistic synthetic data**: Scenario 2 uses real PostHog field names (ActivityLog, structlog, rate_limit) inspired by the GoldenSAML compound attack pattern
* Heuristic detection mapped to MITRE ATT&CK (not ML)
* LLM for reasoning, not detection
* Simulate mode for demo impact

---

## 11. Positioning

This project demonstrates:

* **Incident response**: end-to-end investigation from raw logs to actionable report
* **Detection engineering**: hand-crafted rules with MITRE mapping and correlation
* **Cloud security**: real AWS attack patterns (SSRF, credential theft, S3 exfil)
* **Product security**: realistic SaaS-level attacks against PostHog's data model
* **AI-assisted security**: practical LLM use for investigation, not hype

Inspired by real-world needs of small, high-velocity teams like PostHog.
