# hogwatch-ai

CLI tool that simulates and investigates cloud and product-level security incidents using LLMs.

Built to demonstrate how small security teams can scale incident response without a traditional SOC by combining detection heuristics, timeline reconstruction, AI-assisted investigation, and real-time attack simulation.

This is a **demonstration tool**, not a production SIEM.

## How It Works

```
  Scenario JSON       Detection Engine       Timeline Builder       LLM Investigation       Report
  ┌──────────┐       ┌──────────────┐       ┌───────────────┐       ┌──────────────┐       ┌──────────┐
  │ CloudTrail│──────▶│ 31 rules     │──────▶│ Sort + enrich │──────▶│ Claude       │──────▶│ Markdown │
  │ PostHog   │ parse │ MITRE mapped │detect │ relative time │build  │ analysis     │report │ to       │
  │ OTel/MCP  │       │ correlation  │       │ finding links │       │ (optional)   │       │ output/  │
  └──────────┘       └──────────────┘       └───────────────┘       └──────────────┘       └──────────┘
```

**Pipeline stages:**

1. **Parse** — Load scenario JSON, normalize events from 10 different log formats (CloudTrail, PostHog activity_log, structlog, Temporal, Celery, OTel spans, Pino, Prometheus, MCP, HogQL query logs) into a common `NormalizedEvent` model
2. **Detect** — Run 34 detection rules against normalized events. Rules use a decorator-based registry, each mapped to a MITRE ATT&CK technique. A correlation pass detects composite attack chains across phases
3. **Timeline** — Sort events chronologically, compute relative timestamps (`T+0s`, `T+2m30s`), generate human-readable descriptions, and link findings to suspicious events
4. **Investigate** (optional) — Send timeline + findings to Claude for structured analysis: executive summary, attack path, malicious assessment, MITRE mapping, impact, and remediation
5. **Report** — Generate a Markdown incident report to `output/`

**LLM backend:** If `ANTHROPIC_API_KEY` is set, uses the Anthropic SDK directly. Otherwise, falls back to the `claude` CLI using your existing authentication (OAuth/SSO) — no separate API key needed. Use `--no-llm` to skip AI analysis entirely.

## Quick Start

```bash
git clone https://github.com/your-org/hogwatch-ai.git
cd hogwatch-ai
python3 -m venv .venv && source .venv/bin/activate
pip install --index-url https://pypi.org/simple/ -e ".[dev]"

# List available scenarios
hogwatch list-scenarios

# Run investigation (detection + timeline + report, no LLM)
hogwatch investigate data/scenario_1.json --no-llm

# Run with Claude analysis (uses claude CLI auth if no API key)
hogwatch investigate data/scenario_1.json

# Real-time attack simulation with incremental detection
hogwatch simulate data/scenario_2.json --delay 0.5
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `hogwatch investigate <scenario>` | Full pipeline: parse → detect → timeline → LLM → report |
| `hogwatch simulate <scenario>` | Real-time replay with incremental detection |
| `hogwatch list-scenarios` | List available scenarios with metadata |

| Flag | Description |
|------|-------------|
| `--no-llm` | Skip LLM investigation |
| `--model <name>` | Override Claude model |
| `--delay <seconds>` | Event replay delay in simulate mode (default: 2.0) |
| `--output <dir>` | Output directory for reports (default: `output/`) |
| `--verbose` | Show detailed timeline table |

## Scenarios

### Scenario 1 — AWS SSRF → Credential Theft → S3 Exfiltration

**Source data:** Real CloudTrail events (103 events) from [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) — dataset `SDAWS-200914011940` (AWS Cloud Bank Breach S3)

An attacker exploits a misconfigured EC2 reverse proxy (nginx) to reach the instance metadata service (`169.254.169.254`), steals the IAM role's temporary credentials, then uses them to enumerate and exfiltrate data from S3 buckets.

| Phase | What happens |
|-------|-------------|
| Reconnaissance | EC2 `Describe*` burst by IAM user via console |
| Credential Theft | 5x `AssumeRole` from `ec2.amazonaws.com` (metadata service) |
| S3 Enumeration | `ListBuckets` + `ListObjects` using stolen role credentials from external IP |
| Exfiltration | `GetObject` on S3 bucket data |

**Detection rules:** `AWS-001` (stolen creds), `AWS-002` (AssumeRole burst), `AWS-003` (S3 enum+exfil chain), `AWS-004` (recon burst), `AWS-CHAIN` (composite)
**MITRE:** T1078.004, T1530, T1550.001, T1580

---

### Scenario 2 — PostHog API Key Compromise → Data Exfiltration

**Inspired by:** [GoldenSAML attack pattern](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/GoldenSAMLADFSMailAccess) from OTRF/Security-Datasets — credential theft → permission escalation → impersonation → data exfiltration, translated to PostHog's domain

**Log sources:** PostHog `activity_log`, `structlog`, `rate_limit` — field names modeled on real PostHog logging ([ActivityLog model](https://github.com/PostHog/posthog/blob/master/posthog/models/activity_logging/activity_log.py), [QueryTags](https://github.com/PostHog/posthog/blob/master/posthog/clickhouse/query_tagging.py))

An attacker finds a PostHog `PersonalAPIKey` in a public GitHub commit. They use it from a foreign IP to probe the API, escalate the key's scope from `query:read` to `*`, query sensitive person data, and create a batch export to an external S3 bucket.

| GoldenSAML Step | PostHog Equivalent |
|-----------------|-------------------|
| Steal AD FS signing cert | Compromised `PersonalAPIKey` via leaked `.env` |
| Forge SAML token | API key usage from unusual IP with script user-agent |
| Grant `Mail.ReadWrite` | Escalate API key scope to `*` |
| Access mailbox via Graph API | Batch export person data to attacker S3 bucket |

**Detection rules:** `PH-001` through `PH-006`, `PH-CHAIN` (composite)
**MITRE:** T1552, T1098, T1530, T1537

---

### Scenario 3 — Temporal Workflow Hijacking → Batch Export Exfiltration

**Log sources:** PostHog Temporal workflow logs — field names modeled on [PostHog Temporal logger](https://github.com/PostHog/posthog/blob/master/posthog/temporal/common/logger.py) and [batch export workflows](https://github.com/PostHog/posthog/blob/master/products/batch_exports/backend/temporal/batch_exports.py)

An attacker with access to the Temporal task queue creates a batch export workflow targeting an external S3 bucket, retries excessively to extract data, then deletes workflow history to cover tracks.

**Detection rules:** `TW-001` (external bucket target), `TW-002` (excessive retries), `TW-003` (workflow history deletion), `TW-CHAIN` (composite)
**MITRE:** T1537, T1078, T1070.004

---

### Scenario 4 — Celery Task Queue Injection → Unauthorized Task Execution

**Log sources:** PostHog Celery task logs — field names modeled on [PostHog celery.py](https://github.com/PostHog/posthog/blob/master/posthog/celery.py) and [django-structlog](https://github.com/jrobichaud/django-structlog) instrumentation (`task_name`, `task_id`, `status`, `retries`, `runtime`, `queue`)

An attacker injects tasks into the Celery queue from an unknown worker, triggers retry storms, and executes sensitive operations like `delete_person` and `export_all_events`.

**Detection rules:** `CT-001` (unknown worker), `CT-002` (retry storm), `CT-003` (sensitive task execution)
**MITRE:** T1053.005, T1059, T1531

---

### Scenario 5 — OTel Trace Anomalies → ClickHouse Data Extraction

**Log sources:** OpenTelemetry spans — field names modeled on [PostHog tracing product](https://github.com/PostHog/posthog/blob/master/products/tracing/backend/logic.py) (`trace_id`, `span_id`, `parent_span_id`, `service_name`, `kind`, `duration_ms`, OTel semantic attributes)

An unexpected service name appears in traces, runs bulk `SELECT *` queries against ClickHouse, extracts >100k rows from sensitive tables (`person`, `events`), and exfiltrates data via oversized HTTP responses.

**Detection rules:** `OT-001` (bulk extraction), `OT-002` (sensitive table query), `OT-003` (unexpected service), `OT-CHAIN` (composite)
**MITRE:** T1213, T1530, T1071.001

---

### Scenario 6 — Exception Spike & Middleware Anomalies → API Exploitation

**Log sources:** PostHog exception capture and request middleware — field names modeled on [PostHog middleware.py](https://github.com/PostHog/posthog/blob/master/posthog/middleware.py) (`x_forwarded_for`, `container_hostname`, `team_id`, `user_id`) and [exceptions_capture.py](https://github.com/PostHog/posthog/blob/master/posthog/exceptions_capture.py)

A spike in exceptions signals active exploitation — SQL injection attempts against the API, probing of internal endpoints (`_debug/`, `_system/`), and forced errors to map the application's error handling.

**Detection rules:** `EM-001` (exception spike), `EM-002` (SQL injection signatures), `EM-003` (internal endpoint access), `EM-CHAIN` (composite)
**MITRE:** T1190, T1059.001, T1046

---

### Scenario 7 — Plugin Server Compromise → Malicious Plugin Execution

**Log sources:** PostHog Node.js plugin server Pino logs — structure modeled on [PostHog Node.js logger](https://github.com/PostHog/posthog/blob/master/nodejs/src/utils/logger.ts) (`level`, `time`, `pid`, `hostname`, `msg`)

An untrusted plugin is installed, makes outbound HTTP calls to exfiltrate data, accesses environment variables to steal credentials, and consumes excessive resources.

**Detection rules:** `PS-001` (untrusted plugin install), `PS-002` (outbound exfiltration), `PS-003` (env var access)
**MITRE:** T1195.002, T1041, T1552.001, T1496

---

### Scenario 8 — Prometheus Metrics Anomalies → Credential Stuffing & Cryptomining

**Log sources:** Prometheus metric alerts — metric names modeled on [PostHog django-prometheus metrics](https://github.com/PostHog/posthog/blob/master/posthog/celery.py) and Celery task queue metrics

A credential stuffing attack causes a spike in 401/403 responses (>10x baseline). Simultaneously, network egress anomalies and CPU/memory abuse suggest cryptomining on compromised workers.

**Detection rules:** `PM-001` (auth failure spike), `PM-002` (network egress anomaly), `PM-003` (resource abuse)
**MITRE:** T1110.004, T1496, T1041, T1053.005

---

### Scenario 9 — MCP Service Exploitation → AI Tool Abuse for Data Extraction

**Log sources:** PostHog MCP service request logs — field names modeled on [PostHog MCP tools API](https://github.com/PostHog/posthog/blob/master/products/posthog_ai/backend/api/mcp_tools.py) (`tool_name`, `params`, `team_id`)

An attacker reuses a stolen MCP session token from a different IP, makes rapid-fire tool calls to `get_persons` for automated data extraction, and triggers heavy requests returning >1MB of data.

**Detection rules:** `MCP-001` (session token reuse across IPs), `MCP-002` (rapid tool calls), `MCP-003` (heavy data extraction), `MCP-004` (composite: automated data theft chain)
**MITRE:** T1530, T1550.001, T1119, T1071.001

---

### Scenario 10 — HogQL Injection → Query Manipulation for Data Exfiltration

**Log sources:** PostHog structlog query execution and ClickHouse query_log_archive — field names modeled on [PostHog HogQL parser](https://github.com/PostHog/posthog/blob/master/posthog/hogql/parser.py), [QueryTags](https://github.com/PostHog/posthog/blob/master/posthog/clickhouse/query_tagging.py), and [query_log_archive schema](https://github.com/PostHog/posthog/blob/master/posthog/clickhouse/query_log_archive.py). Vulnerability patterns based on PostHog's own [semgrep rules for HogQL injection](https://github.com/PostHog/posthog/blob/master/.semgrep/rules/hogql-no-fstring.yaml).

An attacker with API key access discovers a HogQL injection vulnerability. They probe with malformed queries (`' OR '1'='1'`, `UNION ALL SELECT`) to map parser behavior via error messages, then craft queries that escalate from benign analytics to bulk PII extraction — selecting `$email`, `$phone`, `$ip`, and `person_id` across 100k+ rows.

| Phase | What happens |
|-------|-------------|
| Reconnaissance | Benign query establishes baseline, then injection probes trigger `HogQLException` parser errors |
| Enumeration | `UNION ALL SELECT ... FROM person` reveals table access restrictions via error messages |
| PII Extraction | Queries select `$email`, `$phone`, `$ip` from `$identify` events, escalating from 12k → 50k → 100k rows |

**Detection rules:** `HQL-001` (injection probing — parser errors with injection signatures), `HQL-002` (PII extraction — multiple PII fields selected), `HQL-003` (bulk extraction — >10k result rows), `HQL-CHAIN` (composite: probing + PII extraction)
**MITRE:** T1190, T1059.009, T1005, T1530

## Architecture

```
hogwatch-ai/
├── pyproject.toml
├── hogwatch_cli/
│   └── main.py              # Click CLI entrypoint
├── core/
│   ├── models.py            # Pydantic models (NormalizedEvent, Finding, TimelineEntry, InvestigationResult)
│   ├── parser.py            # 10 log format normalizers
│   ├── detector.py          # 34 detection rules + correlation engine
│   ├── timeline.py          # Event ordering + relative time + descriptions
│   └── report.py            # Markdown report generator
├── llm/
│   ├── client.py            # Anthropic SDK + claude CLI dual backend
│   └── prompts.py           # System/user prompt templates
├── data/
│   └── scenario_*.json      # 10 scenario files
├── tests/
│   ├── test_detector.py     # Detection rule unit tests
│   └── test_integration.py  # End-to-end pipeline tests
└── output/                  # Generated Markdown reports
```

## Detection Rules

34 rules across 10 domains, all mapped to MITRE ATT&CK. Rules use a decorator-based registry:

```python
@register_rule("AWS-001", severity="high", mitre="T1078.004")
def detect_stolen_ec2_credentials(events):
    """EC2 role credentials used from external IP"""
    ...
```

A correlation engine runs after individual rules to detect composite attack chains — multi-phase attacks where findings from separate rules combine to confirm a full attack path (e.g., `AWS-CHAIN`: credential theft + S3 exfiltration in the same session).

## Data Sources & References

| Source | Usage | Link |
|--------|-------|------|
| OTRF/Security-Datasets | Real CloudTrail events (scenario 1), GoldenSAML attack pattern inspiration (scenario 2) | [github.com/OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) |
| PostHog source code | Log formats, field names, and data models for scenarios 2-10 | [github.com/PostHog/posthog](https://github.com/PostHog/posthog) |
| PostHog semgrep rules | HogQL injection vulnerability patterns (scenario 10) | [hogql-no-fstring.yaml](https://github.com/PostHog/posthog/blob/master/.semgrep/rules/hogql-no-fstring.yaml) |
| MITRE ATT&CK | Technique mapping for all 34 detection rules | [attack.mitre.org](https://attack.mitre.org/) |

## Requirements

- Python >= 3.11
- For LLM investigation (optional): either `ANTHROPIC_API_KEY` env var or the [claude CLI](https://docs.anthropic.com/en/docs/claude-code) authenticated
- Use `--no-llm` to run without any LLM dependency
