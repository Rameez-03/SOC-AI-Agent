"""
Generates incident reports and false-positive documentation using the
template at /app/config/templates/incident_report.md.
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from connectors.base import Case
from triage import TriageResult
from log_analysis import LogAnalysis
from enrichment import format_enrichment_summary
from connectors.base import EnrichmentResult
from playbook_runner import PlaybookResult, format_playbook_result
from llm_client import LLMClient

logger = logging.getLogger(__name__)

_TEMPLATE_PATH = Path("/app/config/templates/incident_report.md")

_FP_SYSTEM = """You are a SOC analyst writing a false positive documentation note. Be concise and factual."""

_FP_TEMPLATE = """Write a brief false positive documentation note for this case.

CASE: {title}
TRIAGE REASONING: {reasoning}
MITRE TTPs CONSIDERED: {mitre_ttps}

The note should:
1. State clearly this is a false positive
2. Explain why (what legitimate activity triggered the rule)
3. Suggest whether suppression/tuning is needed
4. Be 3-5 sentences maximum

Respond with plain text, no JSON."""

_REPORT_SYSTEM = """You are a SOC analyst writing a formal incident report. Fill in the provided template with the given incident data. Be precise, technical, and complete. Use the exact template structure."""


async def generate_false_positive_note(
    case: Case,
    triage_result: TriageResult,
    llm: LLMClient,
) -> str:
    user_prompt = _FP_TEMPLATE.format(
        title=case.title,
        reasoning=triage_result.reasoning,
        mitre_ttps=", ".join(triage_result.mitre_ttps) or "none",
    )
    try:
        note = await llm.complete(_FP_SYSTEM, user_prompt)
    except Exception as exc:
        logger.error("FP note generation failed for case %s: %s", case.id, exc)
        note = f"False positive — automated analysis: {triage_result.reasoning}"

    header = f"## 🟢 False Positive — Auto-closed by SOC Agent\n\n**Case:** {case.title}\n**Closed:** {_now()}\n\n"
    return header + note


async def generate_incident_report(
    case: Case,
    triage_result: TriageResult,
    analysis: LogAnalysis,
    enrichment_results: list[EnrichmentResult],
    playbook_result: Optional[PlaybookResult],
    llm: LLMClient,
) -> str:
    template = _load_template()

    # Build a context block for the LLM to fill the template
    context = _build_context(case, triage_result, analysis, enrichment_results, playbook_result)

    user_prompt = f"""Fill in the following incident report template using the provided incident data.

TEMPLATE:
{template}

INCIDENT DATA:
{context}

Return the completed report with all placeholders replaced. Keep the template structure exactly as-is."""

    try:
        report = await llm.complete(_REPORT_SYSTEM, user_prompt, temperature=0.2)
    except Exception as exc:
        logger.error("Report generation failed for case %s: %s", case.id, exc)
        report = _fallback_report(case, triage_result, analysis, enrichment_results, playbook_result)

    return report


def _load_template() -> str:
    if _TEMPLATE_PATH.exists():
        return _TEMPLATE_PATH.read_text()
    return _DEFAULT_TEMPLATE


def _build_context(
    case: Case,
    triage: TriageResult,
    analysis: LogAnalysis,
    enrichment: list[EnrichmentResult],
    playbook: Optional[PlaybookResult],
) -> str:
    ioc_lines = "\n".join(
        f"- {i['type']}: {i['value']} ({i.get('context', '')})"
        for i in analysis.iocs
    ) or "None identified"

    timeline_lines = "\n".join(
        f"- {t.get('time', '?')}: {t.get('event', '')}"
        for t in analysis.attack_timeline
    ) or "See SIEM logs"

    mitre_lines = "\n".join(
        f"- {m.get('id', '?')}: {m.get('name', '?')} — {m.get('evidence', '')}"
        for m in analysis.mitre_ttps
    ) or "None mapped"

    enrichment_table = format_enrichment_summary(enrichment)
    playbook_section = format_playbook_result(playbook) if playbook else "No playbook executed"

    return f"""Case ID: {case.id}
Case Title: {case.title}
Detection Time: {case.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
Report Generated: {_now()}
Analyst: SOC AI Agent (autonomous)
Severity: {case.severity}/4
Classification: {triage.classification} (confidence: {triage.confidence:.0%})
Kill Chain Stage: {analysis.kill_chain_stage}

EXECUTIVE SUMMARY:
{analysis.summary}

TRIAGE REASONING:
{triage.reasoning}

ATTACK TIMELINE:
{timeline_lines}

MITRE ATT&CK MAPPING:
{mitre_lines}

INDICATORS OF COMPROMISE:
{ioc_lines}

AFFECTED ASSETS:
{chr(10).join('- ' + a for a in analysis.affected_assets) or 'Under investigation'}

LATERAL MOVEMENT DETECTED: {analysis.lateral_movement_detected}
PERSISTENCE DETECTED: {analysis.persistence_detected}
DATA EXFILTRATION INDICATORS: {analysis.data_exfiltration_indicators}

IOC ENRICHMENT:
{enrichment_table}

PLAYBOOK EXECUTION:
{playbook_section}

RECOMMENDED CONTAINMENT:
{chr(10).join('- ' + r for r in analysis.recommended_containment) or 'See analyst notes'}

ANALYST NOTES:
{analysis.analyst_notes}"""


def _fallback_report(
    case: Case,
    triage: TriageResult,
    analysis: LogAnalysis,
    enrichment: list[EnrichmentResult],
    playbook: Optional[PlaybookResult],
) -> str:
    """Plain fallback if LLM report generation fails."""
    return f"""# Incident Report — {case.title}

**Case ID:** {case.id}
**Generated:** {_now()}
**Severity:** {case.severity}/4
**Classification:** {triage.classification}

## Summary
{analysis.summary}

## Triage
{triage.reasoning}

## MITRE ATT&CK
{chr(10).join(f"- {m.get('id')}: {m.get('name')}" for m in analysis.mitre_ttps) or 'None mapped'}

## IOC Enrichment
{format_enrichment_summary(enrichment)}

## Playbook
{format_playbook_result(playbook) if playbook else 'None executed'}

## Recommended Actions
{chr(10).join('- ' + r for r in analysis.recommended_containment) or 'Manual investigation required'}
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


_DEFAULT_TEMPLATE = """# Incident Report

**Case ID:** {{CASE_ID}}
**Title:** {{CASE_TITLE}}
**Severity:** {{SEVERITY}}/4
**Classification:** {{CLASSIFICATION}}
**Detection Time:** {{DETECTION_TIME}}
**Report Generated:** {{REPORT_TIME}}
**Analyst:** {{ANALYST}}

---

## Executive Summary
{{SUMMARY}}

## Attack Timeline
{{TIMELINE}}

## MITRE ATT&CK
{{MITRE}}

## Indicators of Compromise
{{IOCS}}

## Affected Assets
{{ASSETS}}

## IOC Enrichment
{{ENRICHMENT}}

## Playbook Execution
{{PLAYBOOK}}

## Containment Recommendations
{{CONTAINMENT}}

## Analyst Notes
{{NOTES}}
"""
