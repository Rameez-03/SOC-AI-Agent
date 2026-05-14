"""
Deep log analysis for true positive cases.
Takes SIEM logs + triage result and produces a structured analyst summary.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field

from connectors.base import Case, LogEntry
from triage import TriageResult
from llm_client import LLMClient

logger = logging.getLogger(__name__)

_SYSTEM = """You are a senior SOC analyst writing a technical investigation summary. You will be given a security case and detailed SIEM log data. Produce a concise but complete analysis suitable for a Tier 2 analyst to act on.

Always respond with valid JSON only."""

_USER_TEMPLATE = """Analyse this confirmed security incident.

CASE: {title}
TRIAGE CLASSIFICATION: {classification} (confidence: {confidence:.0%})
INITIAL REASONING: {reasoning}
MITRE TTPs (from triage): {mitre_ttps}

FULL SIEM LOG DATA ({log_count} entries):
{logs_detail}

Respond with this JSON structure:
{{
  "summary": "2-3 sentence executive summary of what happened",
  "attack_timeline": [
    {{"time": "HH:MM:SS", "event": "description of what occurred"}}
  ],
  "kill_chain_stage": "Reconnaissance|Weaponisation|Delivery|Exploitation|Installation|Command and Control|Actions on Objectives",
  "mitre_ttps": [
    {{"id": "T1059.001", "name": "PowerShell", "evidence": "specific log line or field"}}
  ],
  "iocs": [
    {{"type": "ip|domain|hash|url|username|filename|process", "value": "...", "context": "what role this plays"}}
  ],
  "affected_assets": ["hostname or IP of affected systems"],
  "lateral_movement_detected": true|false,
  "persistence_detected": true|false,
  "data_exfiltration_indicators": true|false,
  "recommended_containment": ["list of recommended containment actions"],
  "analyst_notes": "anything else the analyst needs to know"
}}"""


@dataclass
class LogAnalysis:
    summary: str
    attack_timeline: list[dict]
    kill_chain_stage: str
    mitre_ttps: list[dict]
    iocs: list[dict]
    affected_assets: list[str]
    lateral_movement_detected: bool
    persistence_detected: bool
    data_exfiltration_indicators: bool
    recommended_containment: list[str]
    analyst_notes: str
    raw: dict = field(default_factory=dict)


def _format_logs_detail(logs: list[LogEntry], max_entries: int = 50) -> str:
    if not logs:
        return "No logs available."
    lines = []
    for log in logs[:max_entries]:
        line = f"[{log.timestamp.strftime('%Y-%m-%dT%H:%M:%S')}]"
        if log.rule_id:
            line += f" Rule={log.rule_id}"
        if log.rule_name:
            line += f" ({log.rule_name})"
        if log.rule_level:
            line += f" Level={log.rule_level}"
        if log.agent_name:
            line += f"\n  Agent: {log.agent_name}"
        if log.source_ip:
            line += f" | SrcIP: {log.source_ip}"
        if log.dest_ip:
            line += f" | DstIP: {log.dest_ip}"
        if log.process:
            line += f"\n  Process: {log.process}"
        if log.command_line:
            cmd = log.command_line[:200] + "..." if len(log.command_line) > 200 else log.command_line
            line += f"\n  CommandLine: {cmd}"
        if log.mitre_ids:
            line += f"\n  MITRE: {', '.join(log.mitre_ids)}"
        lines.append(line)
    if len(logs) > max_entries:
        lines.append(f"\n[{len(logs) - max_entries} additional log entries truncated]")
    return "\n\n".join(lines)


async def analyse(
    case: Case,
    logs: list[LogEntry],
    triage_result: TriageResult,
    llm: LLMClient,
) -> LogAnalysis:
    user_prompt = _USER_TEMPLATE.format(
        title=case.title,
        classification=triage_result.classification,
        confidence=triage_result.confidence,
        reasoning=triage_result.reasoning,
        mitre_ttps=", ".join(triage_result.mitre_ttps) or "none identified at triage",
        log_count=len(logs),
        logs_detail=_format_logs_detail(logs),
    )

    try:
        raw = await llm.complete_json(_SYSTEM, user_prompt)
    except Exception as exc:
        logger.error("Log analysis failed for case %s: %s", case.id, exc)
        return LogAnalysis(
            summary=f"Automated analysis failed: {exc}. Manual investigation required.",
            attack_timeline=[],
            kill_chain_stage="Unknown",
            mitre_ttps=[],
            iocs=[],
            affected_assets=[],
            lateral_movement_detected=False,
            persistence_detected=False,
            data_exfiltration_indicators=False,
            recommended_containment=["Manual investigation required"],
            analyst_notes="LLM analysis failed — review logs directly in SIEM",
        )

    return LogAnalysis(
        summary=raw.get("summary", ""),
        attack_timeline=raw.get("attack_timeline", []),
        kill_chain_stage=raw.get("kill_chain_stage", "Unknown"),
        mitre_ttps=raw.get("mitre_ttps", []),
        iocs=raw.get("iocs", []),
        affected_assets=raw.get("affected_assets", []),
        lateral_movement_detected=bool(raw.get("lateral_movement_detected", False)),
        persistence_detected=bool(raw.get("persistence_detected", False)),
        data_exfiltration_indicators=bool(raw.get("data_exfiltration_indicators", False)),
        recommended_containment=raw.get("recommended_containment", []),
        analyst_notes=raw.get("analyst_notes", ""),
        raw=raw,
    )
