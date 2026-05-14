"""
Loads playbooks from /app/config/playbooks/ and executes them step by step.
Low-risk steps (query, enrich, document) run autonomously.
High-risk steps (block, isolate, disable) are flagged for analyst approval
unless AUTO_EXECUTE_PLAYBOOKS=true in .env.
"""
from __future__ import annotations
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from connectors.base import Case, SOARConnector

logger = logging.getLogger(__name__)

_PLAYBOOK_DIR = Path("/app/config/playbooks")
_AUTO_EXECUTE = os.getenv("AUTO_EXECUTE_PLAYBOOKS", "false").lower() == "true"

# Keywords that mark a step as high-risk (requires approval)
_HIGH_RISK_KEYWORDS = {
    "block", "isolate", "disable", "delete", "terminate", "quarantine",
    "revoke", "kill", "shut down", "contain", "restrict", "ban",
}


@dataclass
class PlaybookStep:
    number: int
    description: str
    is_high_risk: bool
    executed: bool = False
    result: Optional[str] = None
    requires_approval: bool = False


@dataclass
class PlaybookResult:
    playbook_name: str
    steps: list[PlaybookStep]
    pending_approvals: list[PlaybookStep]
    completed_steps: list[PlaybookStep]
    summary: str


def _detect_high_risk(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in _HIGH_RISK_KEYWORDS)


def _parse_playbook(content: str) -> list[PlaybookStep]:
    """Extracts numbered steps from Markdown playbook content."""
    steps = []
    # Match lines like: 1. Step text, or **1.** Step text
    pattern = re.compile(r"^[\*\s]*(\d+)[.\)]\s+\*{0,2}(.+?)\*{0,2}\s*$", re.MULTILINE)
    for match in pattern.finditer(content):
        number = int(match.group(1))
        description = match.group(2).strip()
        is_high_risk = _detect_high_risk(description)
        steps.append(PlaybookStep(
            number=number,
            description=description,
            is_high_risk=is_high_risk,
            requires_approval=is_high_risk and not _AUTO_EXECUTE,
        ))
    return steps


def _find_playbook(case: Case) -> Optional[tuple[str, str]]:
    """Returns (name, content) of the best matching playbook for this case."""
    if not _PLAYBOOK_DIR.exists():
        return None

    # Check tags and title for playbook keywords
    search_text = (case.title + " " + " ".join(case.tags)).lower()

    candidates = {
        "brute_force": ["brute", "authentication", "failed logon", "smb_login", "100500"],
        "malware_execution": ["malware", "powershell", "encoded", "lolbin", "wmi", "100001", "100002", "100003"],
        "lateral_movement": ["lateral", "remote thread", "injection", "createremotethread", "100400", "100600"],
    }

    for playbook_name, keywords in candidates.items():
        if any(kw in search_text for kw in keywords):
            path = _PLAYBOOK_DIR / f"{playbook_name}.md"
            if path.exists():
                return playbook_name, path.read_text()

    # Fallback: use the first available playbook
    for path in sorted(_PLAYBOOK_DIR.glob("*.md")):
        return path.stem, path.read_text()

    return None


async def run(
    case: Case,
    soar_connector: Optional[SOARConnector] = None,
) -> PlaybookResult:
    match = _find_playbook(case)
    if not match:
        return PlaybookResult(
            playbook_name="none",
            steps=[],
            pending_approvals=[],
            completed_steps=[],
            summary="No applicable playbook found in /app/config/playbooks/",
        )

    playbook_name, content = match
    steps = _parse_playbook(content)

    if not steps:
        return PlaybookResult(
            playbook_name=playbook_name,
            steps=[],
            pending_approvals=[],
            completed_steps=[],
            summary=f"Playbook '{playbook_name}' loaded but no numbered steps found.",
        )

    completed: list[PlaybookStep] = []
    pending: list[PlaybookStep] = []

    for step in steps:
        if step.requires_approval:
            step.result = "AWAITING ANALYST APPROVAL"
            pending.append(step)
        else:
            # Low-risk steps: mark executed (actual execution happens via SOAR)
            step.executed = True
            step.result = "Recorded — execute manually or via SOAR"

            # If SOAR is available and step mentions a specific action, trigger it
            if soar_connector and _AUTO_EXECUTE:
                try:
                    wr = await soar_connector.trigger(
                        action=f"playbook_step",
                        payload={
                            "case_id": case.id,
                            "playbook": playbook_name,
                            "step": step.number,
                            "description": step.description,
                        },
                    )
                    step.result = "SOAR triggered" if wr.success else f"SOAR failed: {wr.error}"
                except Exception as exc:
                    step.result = f"SOAR error: {exc}"

            completed.append(step)

    auto_count = len(completed)
    approval_count = len(pending)
    summary = (
        f"Playbook '{playbook_name}': {len(steps)} steps total. "
        f"{auto_count} recorded autonomously. "
        f"{approval_count} step(s) require analyst approval before execution."
    )

    return PlaybookResult(
        playbook_name=playbook_name,
        steps=steps,
        pending_approvals=pending,
        completed_steps=completed,
        summary=summary,
    )


def format_playbook_result(result: PlaybookResult) -> str:
    """Renders the playbook result as Markdown for a case note."""
    lines = [f"### Playbook: {result.playbook_name}", "", result.summary, ""]

    if result.completed_steps:
        lines.append("**Steps recorded:**")
        for step in result.completed_steps:
            lines.append(f"- [x] Step {step.number}: {step.description}")
        lines.append("")

    if result.pending_approvals:
        lines.append("**Steps requiring analyst approval before execution:**")
        for step in result.pending_approvals:
            lines.append(f"- [ ] Step {step.number}: {step.description} ⚠️ *HIGH RISK — awaiting approval*")
        lines.append("")
        lines.append("> To authorise a step, respond in the SOC Monitor chat: `approve step <N> for case <case_id>`")

    return "\n".join(lines)
