"""
Classifies a TheHive case as true_positive, false_positive, or needs_investigation.
Uses a structured JSON prompt — no tool calling, deterministic output.
"""
from __future__ import annotations
import json
import logging
from dataclasses import dataclass, field

from connectors.base import Case, LogEntry, IOC
from llm_client import LLMClient

logger = logging.getLogger(__name__)

_SYSTEM = """You are a SOC analyst performing case triage. You will be given a security case and recent SIEM log entries. Your job is to classify the case and extract key information.

Always respond with valid JSON only. No explanation outside the JSON object."""

_USER_TEMPLATE = """Classify this security case.

CASE TITLE: {title}
CASE DESCRIPTION: {description}
CASE SEVERITY: {severity}/4
CASE TAGS: {tags}
SOURCE: {source}

RECENT SIEM ALERTS ({log_count} entries):
{logs_summary}

Respond with this exact JSON structure:
{{
  "classification": "true_positive" | "false_positive" | "needs_investigation",
  "confidence": 0.0-1.0,
  "severity": 1-4,
  "reasoning": "concise explanation of your decision",
  "iocs": [
    {{"type": "ip|domain|hash|url|filename|username", "value": "..."}}
  ],
  "mitre_ttps": ["T1059.001", "..."],
  "recommended_action": "what should happen next"
}}

Classification guidance:
- true_positive: Clear evidence of malicious activity matching the detection logic
- false_positive: Evidence of legitimate activity triggering the rule (tool noise, admin activity, known-good processes)
- needs_investigation: Ambiguous — escalate to analyst for manual review"""


@dataclass
class TriageResult:
    classification: str        # true_positive | false_positive | needs_investigation
    confidence: float
    severity: int              # 1-4
    reasoning: str
    iocs: list[IOC]
    mitre_ttps: list[str]
    recommended_action: str
    raw_response: dict = field(default_factory=dict)


def _summarise_logs(logs: list[LogEntry], max_entries: int = 20) -> str:
    if not logs:
        return "No SIEM logs available for this case."
    lines = []
    for log in logs[:max_entries]:
        parts = [f"[{log.timestamp.strftime('%Y-%m-%dT%H:%M:%S')}]"]
        if log.rule_id:
            parts.append(f"Rule {log.rule_id}")
        if log.rule_name:
            parts.append(f"({log.rule_name})")
        if log.agent_name:
            parts.append(f"Agent: {log.agent_name}")
        if log.process:
            parts.append(f"Process: {log.process}")
        if log.command_line:
            cmd = log.command_line[:120] + "..." if len(log.command_line) > 120 else log.command_line
            parts.append(f"CMD: {cmd}")
        if log.source_ip:
            parts.append(f"SrcIP: {log.source_ip}")
        if log.mitre_ids:
            parts.append(f"MITRE: {','.join(log.mitre_ids)}")
        lines.append(" | ".join(parts))
    if len(logs) > max_entries:
        lines.append(f"... and {len(logs) - max_entries} more entries")
    return "\n".join(lines)


async def classify_case(
    case: Case,
    logs: list[LogEntry],
    llm: LLMClient,
) -> TriageResult:
    user_prompt = _USER_TEMPLATE.format(
        title=case.title,
        description=case.description[:500] if case.description else "No description",
        severity=case.severity,
        tags=", ".join(case.tags) if case.tags else "none",
        source=case.source or "Unknown",
        log_count=len(logs),
        logs_summary=_summarise_logs(logs),
    )

    try:
        raw = await llm.complete_json(_SYSTEM, user_prompt)
    except Exception as exc:
        logger.error("Triage LLM call failed for case %s: %s", case.id, exc)
        return TriageResult(
            classification="needs_investigation",
            confidence=0.0,
            severity=case.severity,
            reasoning=f"Triage failed due to LLM error: {exc}",
            iocs=[],
            mitre_ttps=[],
            recommended_action="Manual investigation required",
        )

    iocs = [
        IOC(type=i.get("type", "unknown"), value=i.get("value", ""))
        for i in raw.get("iocs", [])
        if i.get("value")
    ]

    return TriageResult(
        classification=raw.get("classification", "needs_investigation"),
        confidence=float(raw.get("confidence", 0.5)),
        severity=int(raw.get("severity", case.severity)),
        reasoning=raw.get("reasoning", ""),
        iocs=iocs,
        mitre_ttps=raw.get("mitre_ttps", []),
        recommended_action=raw.get("recommended_action", ""),
        raw_response=raw,
    )
