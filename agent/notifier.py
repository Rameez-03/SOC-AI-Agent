"""
Posts proactive alerts to the Open WebUI SOC Monitor chat and logs them locally.
If WEBUI_API_KEY or WEBUI_MONITOR_CHAT_ID are not set, alerts are logged only.
"""
from __future__ import annotations
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx

from connectors.base import Case, LogEntry, EnrichmentResult
from triage import TriageResult
from log_analysis import LogAnalysis

logger = logging.getLogger(__name__)

_WEBUI_URL = os.getenv("WEBUI_URL", "http://open-webui:8080")
_API_KEY = os.getenv("WEBUI_API_KEY", "")
_CHAT_ID = os.getenv("WEBUI_MONITOR_CHAT_ID", "")

_SEVERITY_LABEL = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
_SEVERITY_ICON  = {1: "🟡", 2: "🟠", 3: "🔴", 4: "🚨"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M UTC")


def _build_tp_message(
    case: Case,
    triage: TriageResult,
    analysis: LogAnalysis,
    enrichment_results: list[EnrichmentResult],
    logs: list[LogEntry],
) -> str:
    icon  = _SEVERITY_ICON.get(case.severity, "🔴")
    label = _SEVERITY_LABEL.get(case.severity, "High")

    lines = [
        f"{icon} **SOC ALERT — {label.upper()} SEVERITY**",
        f"**Time:** {_now()}  |  **Case ID:** `{case.id}`",
        f"**Case:** {case.title}",
        f"**Classification:** {triage.classification.replace('_', ' ').title()} ({triage.confidence:.0%} confidence)",
        "",
        "---",
        "### Summary",
        analysis.summary,
        "",
    ]

    # Affected assets
    if analysis.affected_assets:
        lines.append("### Affected Assets")
        for asset in analysis.affected_assets:
            lines.append(f"- {asset}")
        lines.append("")
    elif logs:
        agents = list({l.agent_name for l in logs if l.agent_name})
        if agents:
            lines.append(f"### Affected Machine(s)")
            for a in agents:
                lines.append(f"- {a}")
            lines.append("")

    # MITRE ATT&CK
    if analysis.mitre_ttps:
        lines.append("### MITRE ATT&CK")
        for m in analysis.mitre_ttps:
            lines.append(f"- **{m.get('id')}** — {m.get('name')}: {m.get('evidence', '')}")
        lines.append("")

    # Attack timeline (top 5 events)
    if analysis.attack_timeline:
        lines.append("### Attack Timeline")
        for event in analysis.attack_timeline[:5]:
            lines.append(f"- `{event.get('time', '?')}` — {event.get('event', '')}")
        lines.append("")

    # IOC enrichment
    enriched_iocs = [e for e in enrichment_results if e.verdict != "unknown"]
    if enriched_iocs:
        lines.append("### IOC Enrichment Results")
        for e in enriched_iocs:
            verdict_icon = "🔴" if e.verdict == "malicious" else "🟠" if e.verdict == "suspicious" else "🟢"
            score_str = f" ({e.score}% detections)" if e.score else ""
            lines.append(f"- {verdict_icon} `{e.ioc.value}` ({e.ioc.type}) — **{e.verdict.upper()}**{score_str}")
        lines.append("")
    elif triage.iocs:
        lines.append("### IOCs Identified")
        for ioc in triage.iocs[:5]:
            lines.append(f"- `{ioc.value}` ({ioc.type})")
        lines.append("")

    # Flags
    flags = []
    if analysis.lateral_movement_detected:
        flags.append("⚠️ **Lateral movement detected**")
    if analysis.persistence_detected:
        flags.append("⚠️ **Persistence mechanism detected**")
    if analysis.data_exfiltration_indicators:
        flags.append("⚠️ **Data exfiltration indicators present**")
    if flags:
        lines += flags + [""]

    # Recommended actions
    if analysis.recommended_containment:
        lines.append("### Recommended Actions")
        for i, action in enumerate(analysis.recommended_containment, 1):
            lines.append(f"{i}. {action}")
        lines.append("")

    lines += [
        "---",
        f"> **Next step:** Review the full analysis in TheHive case `{case.id}`, then reply here to instruct me on containment actions.",
    ]

    return "\n".join(lines)


def _build_fp_message(case: Case, triage: TriageResult, logs: list[LogEntry]) -> str:
    log_count = len(logs)
    first_ts = logs[0].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if logs else "N/A"
    last_ts  = logs[-1].timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if logs else "N/A"

    lines = [
        f"🟢 **FALSE POSITIVE — ANALYST APPROVAL REQUIRED**",
        f"**Time:** {_now()}  |  **Case ID:** `{case.id}`",
        f"**Case:** {case.title}",
        f"**Confidence:** {triage.confidence:.0%}",
        "",
        "### AI Analysis",
        triage.reasoning,
        "",
        "### Log Evidence",
        f"- **{log_count}** SIEM log entries reviewed",
    ]

    if logs:
        lines.append(f"- Timeframe: `{first_ts}` → `{last_ts}`")
        agents = list({l.agent_name for l in logs if l.agent_name})
        if agents:
            lines.append(f"- Agent(s): {', '.join(agents)}")
        rule_names = list({l.rule_name for l in logs if l.rule_name})
        if rule_names:
            lines.append(f"- Rules triggered: {', '.join(rule_names[:3])}")

    lines += [
        "",
        "### Action Required",
        f"1. Review the FP documentation in **TheHive case `{case.id}`**",
        "2. Verify the evidence matches known-good activity",
        "3. **Manually close the case** in TheHive when satisfied",
        "4. Consider tuning the Wazuh rule if this fires frequently",
        "",
        f"> Reply here with `close {case.id}` to confirm closure, or `escalate {case.id}` if you disagree.",
    ]

    return "\n".join(lines)


async def send_tp_alert(
    case: Case,
    triage: TriageResult,
    analysis: LogAnalysis,
    enrichment_results: list[EnrichmentResult],
    logs: list[LogEntry],
) -> None:
    message = _build_tp_message(case, triage, analysis, enrichment_results, logs)
    logger.info("SOC ALERT | Case: %s | %s | %s", case.id, case.title, triage.classification)
    if not _API_KEY or not _CHAT_ID:
        logger.warning("WEBUI_API_KEY or WEBUI_MONITOR_CHAT_ID not set — alert logged only.")
        return
    await _post_to_webui(message)


async def send_fp_review_alert(case: Case, triage: TriageResult, logs: list[LogEntry]) -> None:
    message = _build_fp_message(case, triage, logs)
    logger.info("FP REVIEW | Case: %s | %s | awaiting analyst approval", case.id, case.title)
    if not _API_KEY or not _CHAT_ID:
        return
    await _post_to_webui(message)


async def send_system_message(text: str) -> None:
    if not _API_KEY or not _CHAT_ID:
        return
    await _post_to_webui(f"ℹ️ **System:** {text}")


async def create_monitor_chat() -> Optional[str]:
    if not _API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{_WEBUI_URL}/api/v1/chats/new",
                headers={"Authorization": f"Bearer {_API_KEY}", "Content-Type": "application/json"},
                json={
                    "chat": {
                        "title": "🛡️ SOC Monitor",
                        "models": ["soc-agent"],
                        "messages": [
                            {
                                "id": "init",
                                "role": "assistant",
                                "content": (
                                    "**SOC Monitor active.** I am monitoring your security environment "
                                    "and will post alerts here when cases are detected.\n\n"
                                    "You can also ask me questions directly in this chat."
                                ),
                            }
                        ],
                    }
                },
            )
            resp.raise_for_status()
            chat_id = resp.json().get("id")
            logger.info("SOC Monitor chat created — ID: %s", chat_id)
            logger.info("Add WEBUI_MONITOR_CHAT_ID=%s to your .env and restart the agent.", chat_id)
            return chat_id
    except Exception as exc:
        logger.warning("Could not create SOC Monitor chat: %s", exc)
        return None


async def _post_to_webui(message: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            get_resp = await client.get(
                f"{_WEBUI_URL}/api/v1/chats/{_CHAT_ID}",
                headers={"Authorization": f"Bearer {_API_KEY}"},
            )
            if get_resp.status_code != 200:
                logger.warning("Could not fetch SOC Monitor chat (status %d)", get_resp.status_code)
                return

            chat_data = get_resp.json()
            messages = chat_data.get("chat", {}).get("messages", [])
            messages.append({
                "id": str(uuid.uuid4()),
                "role": "assistant",
                "content": message,
                "timestamp": int(time.time()),
            })

            update_resp = await client.post(
                f"{_WEBUI_URL}/api/v1/chats/{_CHAT_ID}",
                headers={"Authorization": f"Bearer {_API_KEY}", "Content-Type": "application/json"},
                json={"chat": {**chat_data.get("chat", {}), "messages": messages}},
            )
            if update_resp.status_code not in (200, 201):
                logger.warning("WebUI chat update returned status %d", update_resp.status_code)
    except Exception as exc:
        logger.error("Failed to post alert to WebUI: %s", exc)
