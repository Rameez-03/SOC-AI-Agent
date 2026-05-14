"""
Posts proactive alerts to the Open WebUI SOC Monitor chat and logs them locally.
If WEBUI_API_KEY or WEBUI_MONITOR_CHAT_ID are not set, alerts are logged only.
"""
from __future__ import annotations
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx

from connectors.base import Case
from triage import TriageResult

logger = logging.getLogger(__name__)

_WEBUI_URL = os.getenv("WEBUI_URL", "http://open-webui:8080")
_API_KEY = os.getenv("WEBUI_API_KEY", "")
_CHAT_ID = os.getenv("WEBUI_MONITOR_CHAT_ID", "")

# Severity labels matching TheHive
_SEVERITY_LABEL = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
_SEVERITY_ICON = {1: "🟡", 2: "🟠", 3: "🔴", 4: "🚨"}


def _build_alert_message(case: Case, triage: TriageResult, analysis_summary: str) -> str:
    icon = _SEVERITY_ICON.get(case.severity, "🔴")
    label = _SEVERITY_LABEL.get(case.severity, "High")
    now = datetime.now(timezone.utc).strftime("%H:%M UTC")

    lines = [
        f"{icon} **SOC ALERT — {label.upper()} SEVERITY**",
        f"**Time:** {now}",
        f"**Case:** {case.title}",
        f"**Case ID:** `{case.id}`",
        f"**Classification:** {triage.classification.replace('_', ' ').title()} ({triage.confidence:.0%} confidence)",
        "",
        f"**Summary:** {analysis_summary[:300]}{'...' if len(analysis_summary) > 300 else ''}",
        "",
    ]

    if triage.mitre_ttps:
        lines.append(f"**MITRE ATT&CK:** {', '.join(triage.mitre_ttps)}")

    if triage.iocs:
        ioc_strs = [f"`{ioc.value}` ({ioc.type})" for ioc in triage.iocs[:5]]
        lines.append(f"**IOCs:** {', '.join(ioc_strs)}")

    lines += [
        "",
        f"**Recommended:** {triage.recommended_action}",
        "",
        f"> View in TheHive and use the chat to instruct me on next steps.",
    ]

    return "\n".join(lines)


async def send_tp_alert(
    case: Case,
    triage: TriageResult,
    analysis_summary: str,
) -> None:
    message = _build_alert_message(case, triage, analysis_summary)

    # Always log locally so the alert is never lost
    logger.info("SOC ALERT | Case: %s | %s | %s", case.id, case.title, triage.classification)

    if not _API_KEY or not _CHAT_ID:
        logger.warning(
            "WEBUI_API_KEY or WEBUI_MONITOR_CHAT_ID not set — alert logged only. "
            "Set these in .env to enable WebUI push notifications."
        )
        return

    await _post_to_webui(message)


async def send_system_message(text: str) -> None:
    """Posts a system status message to the SOC Monitor (e.g., startup, loop errors)."""
    if not _API_KEY or not _CHAT_ID:
        return
    await _post_to_webui(f"ℹ️ **System:** {text}")


async def create_monitor_chat() -> Optional[str]:
    """
    Creates the SOC Monitor chat if WEBUI_API_KEY is set but WEBUI_MONITOR_CHAT_ID is not.
    Returns the new chat ID on success.
    """
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
                                    "and will post alerts here when true positive cases are detected.\n\n"
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
    """Appends a message to the SOC Monitor chat via the Open WebUI API."""
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # Get current chat to retrieve existing messages
            get_resp = await client.get(
                f"{_WEBUI_URL}/api/v1/chats/{_CHAT_ID}",
                headers={"Authorization": f"Bearer {_API_KEY}"},
            )
            if get_resp.status_code != 200:
                logger.warning("Could not fetch SOC Monitor chat (status %d)", get_resp.status_code)
                return

            chat_data = get_resp.json()
            messages = chat_data.get("chat", {}).get("messages", [])

            # Append new alert message
            import time, uuid
            new_msg = {
                "id": str(uuid.uuid4()),
                "role": "assistant",
                "content": message,
                "timestamp": int(time.time()),
            }
            messages.append(new_msg)

            # Update the chat
            update_resp = await client.post(
                f"{_WEBUI_URL}/api/v1/chats/{_CHAT_ID}",
                headers={"Authorization": f"Bearer {_API_KEY}", "Content-Type": "application/json"},
                json={"chat": {**chat_data.get("chat", {}), "messages": messages}},
            )
            if update_resp.status_code not in (200, 201):
                logger.warning("WebUI chat update returned status %d", update_resp.status_code)
    except Exception as exc:
        logger.error("Failed to post alert to WebUI: %s", exc)
