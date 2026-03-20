from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any

from core.models import Finding, InvestigationResult, TimelineEntry
from llm.prompts import SYSTEM_PROMPT, build_investigation_prompt

DEFAULT_MODEL = "claude-sonnet-4-20250514"

# Minimum seconds between API calls. Prevents throttling when running
# multiple scenarios in sequence (e.g. batch investigation of all 9).
MIN_REQUEST_INTERVAL = float(os.environ.get("HOGWATCH_LLM_INTERVAL", "1.0"))

_last_request_time: float = 0.0


def _rate_limit_wait() -> None:
    """Block until MIN_REQUEST_INTERVAL seconds have elapsed since the last call."""
    global _last_request_time
    if _last_request_time > 0:
        elapsed = time.monotonic() - _last_request_time
        remaining = MIN_REQUEST_INTERVAL - elapsed
        if remaining > 0:
            time.sleep(remaining)
    _last_request_time = time.monotonic()


def _has_api_key() -> bool:
    """Check if ANTHROPIC_API_KEY is available."""
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _has_claude_cli() -> bool:
    """Check if the claude CLI is available on PATH."""
    return shutil.which("claude") is not None


def _investigate_sdk(
    prompt: str,
    model: str | None = None,
) -> str:
    """Call Claude via the Anthropic SDK. Requires ANTHROPIC_API_KEY."""
    import anthropic

    client = anthropic.Anthropic()

    _rate_limit_wait()

    response = client.messages.create(
        model=model or DEFAULT_MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    return response.content[0].text


def _investigate_cli(
    prompt: str,
    model: str | None = None,
) -> str:
    """Call Claude via the claude CLI. Uses existing CLI authentication (OAuth/SSO)."""
    cmd = [
        "claude",
        "-p", prompt,
        "--output-format", "json",
        "--system-prompt", SYSTEM_PROMPT,
    ]

    if model:
        cmd.extend(["--model", model])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=180,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(f"claude CLI failed (exit {result.returncode}): {stderr}")

    response = json.loads(result.stdout)

    if response.get("is_error"):
        raise RuntimeError(f"claude CLI returned error: {response.get('result', 'unknown')}")

    return response["result"]


def investigate(
    timeline: list[TimelineEntry],
    findings: list[Finding],
    metadata: dict[str, Any],
    model: str | None = None,
) -> InvestigationResult:
    """Send timeline + findings to Claude and parse the response.

    Backend selection:
    - If ANTHROPIC_API_KEY is set → uses the Anthropic SDK directly (faster).
    - Otherwise, if the ``claude`` CLI is on PATH → uses CLI with existing
      authentication (OAuth/SSO, no separate API key needed).
    - If neither is available → raises RuntimeError with setup instructions.
    """
    prompt = build_investigation_prompt(timeline, findings, metadata)

    if _has_api_key():
        raw_text = _investigate_sdk(prompt, model)
    elif _has_claude_cli():
        print(
            "[hogwatch] Using claude CLI for investigation (no ANTHROPIC_API_KEY found)",
            file=sys.stderr,
        )
        raw_text = _investigate_cli(prompt, model)
    else:
        raise RuntimeError(
            "No LLM backend available. Either set ANTHROPIC_API_KEY or "
            "install the claude CLI (https://docs.anthropic.com/en/docs/claude-code)."
        )

    return _parse_response(raw_text)


def _parse_response(text: str) -> InvestigationResult:
    """Parse structured LLM response into InvestigationResult."""
    sections = _extract_sections(text)
    _validate_sections(sections)

    # Parse IS_MALICIOUS section
    is_malicious_text = sections.get("IS_MALICIOUS", "")
    is_malicious = "yes" in is_malicious_text.lower().split("\n")[0]
    confidence = "medium"
    for level in ("high", "medium", "low"):
        if level in is_malicious_text.lower():
            confidence = level
            break

    return InvestigationResult(
        summary=sections.get("SUMMARY", "").strip(),
        attack_path=sections.get("ATTACK_PATH", "").strip(),
        is_malicious=is_malicious,
        confidence=confidence,
        impact_assessment=sections.get("IMPACT_ASSESSMENT", "").strip(),
        mitre_techniques=_parse_list(sections.get("MITRE_TECHNIQUES", "")),
        immediate_actions=_parse_list(sections.get("IMMEDIATE_ACTIONS", "")),
        long_term_recommendations=_parse_list(
            sections.get("LONG_TERM_RECOMMENDATIONS", "")
        ),
        raw_response=text,
    )


_EXPECTED_SECTIONS = [
    "SUMMARY",
    "ATTACK_PATH",
    "IS_MALICIOUS",
    "IMPACT_ASSESSMENT",
    "MITRE_TECHNIQUES",
    "IMMEDIATE_ACTIONS",
    "LONG_TERM_RECOMMENDATIONS",
]


def _strip_markdown_formatting(text: str) -> str:
    """Remove inline markdown formatting characters (**, *, _, `) from *text*.

    Only removes leading/trailing runs of ``*``, ``_``, and `` ` `` that act as
    markdown emphasis or code markers.  Underscores *inside* the text (e.g.
    ``ATTACK_PATH``) are preserved.
    """
    # Strip backticks everywhere (inline code markers)
    text = text.replace("`", "")
    # Repeatedly strip leading/trailing bold/italic markers and any
    # trailing colons / whitespace that may sit between formatting
    # layers (e.g.  ``**SUMMARY:**``  or  ``__ATTACK_PATH__:``).
    prev = None
    while text != prev:
        prev = text
        text = re.sub(r"^[*_]+", "", text)
        text = re.sub(r"[*_]+$", "", text)
        text = text.strip().rstrip(":").strip()
    return text


def _extract_sections(text: str) -> dict[str, str]:
    """Extract named sections from markdown-formatted response.

    Handles:
    - Any heading level from ``##`` to ``######``.
    - Bold / italic / code formatting inside the header text
      (e.g. ``### **SUMMARY**``).
    - Trailing colons and extra whitespace (e.g. ``### SUMMARY:``).
    - Mixed case (normalised to upper-case, spaces replaced with underscores).
    """
    sections: dict[str, str] = {}
    current_key: str | None = None
    current_lines: list[str] = []

    for line in text.split("\n"):
        # Match any ATX heading level (##, ###, ####, etc.)
        header_match = re.match(r"^#{2,6}\s+(.+)", line)
        if header_match:
            if current_key:
                sections[current_key] = "\n".join(current_lines)
            raw_header = header_match.group(1)
            cleaned = _strip_markdown_formatting(raw_header)
            current_key = cleaned.upper().replace(" ", "_")
            current_lines = []
        elif current_key:
            current_lines.append(line)

    if current_key:
        sections[current_key] = "\n".join(current_lines)

    return sections


def _validate_sections(sections: dict[str, str]) -> None:
    """Log a warning to stderr for each expected section missing from *sections*."""
    missing = [s for s in _EXPECTED_SECTIONS if s not in sections]
    if missing:
        print(
            f"[hogwatch] WARNING: LLM response missing sections: {', '.join(missing)}",
            file=sys.stderr,
        )


def _parse_list(text: str) -> list[str]:
    """Parse a section with list items into a list of strings."""
    items = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if line and line not in ("", "-"):
            # Remove leading bullet/number
            line = re.sub(r"^[-*\d.]+\s*", "", line)
            if line:
                items.append(line)
    return items
