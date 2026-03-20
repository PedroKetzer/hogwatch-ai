from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NormalizedEvent(BaseModel):
    timestamp: datetime
    event_type: str  # e.g. "cloudtrail", "activity_log", "structlog", "rate_limit"
    event_name: str  # e.g. "AssumeRole", "login", "query_executed"
    source: str  # e.g. "sts.amazonaws.com", "activity_log"
    actor: str = ""  # e.g. "pedro", "phx_...k9Zm"
    target: str = ""  # e.g. "s3://bucket", "PersonalAPIKey"
    context: dict[str, Any] = Field(default_factory=dict)
    severity: Severity = Severity.LOW
    raw: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    title: str
    description: str
    events: list[NormalizedEvent] = Field(default_factory=list)
    mitre_technique: str = ""


class TimelineEntry(BaseModel):
    timestamp: datetime
    relative_time: str  # e.g. "T+0m", "T+5m"
    description: str
    event: NormalizedEvent
    findings: list[Finding] = Field(default_factory=list)
    is_suspicious: bool = False


class InvestigationResult(BaseModel):
    summary: str = ""
    attack_path: str = ""
    is_malicious: bool = False
    confidence: str = ""  # e.g. "high", "medium", "low"
    impact_assessment: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    immediate_actions: list[str] = Field(default_factory=list)
    long_term_recommendations: list[str] = Field(default_factory=list)
    raw_response: str = ""
