"""
SOC AI Agent — main entry point.

Runs two things simultaneously inside one process:
  1. FastAPI server exposing an OpenAI-compatible /v1/chat/completions API
     so Open WebUI can talk to the agent interactively.
  2. Background asyncio loop that autonomously polls the case management
     platform every POLL_INTERVAL_MINUTES and processes new cases.
"""
from __future__ import annotations
import asyncio
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import enrichment as enrichment_module
import log_analysis
import notifier
import playbook_runner
import report_writer
import triage as triage_module
from connectors import (
    get_case_connector, get_enrichment_connector,
    get_siem_connector, get_soar_connector,
    Case, CaseUpdate, IOC,
)
from llm_client import LLMClient

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("soc-agent")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
OLLAMA_KEEP_ALIVE = int(os.getenv("OLLAMA_KEEP_ALIVE", "3600"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_MINUTES", "15")) * 60
LOG_LOOKBACK = int(os.getenv("LOG_LOOKBACK_HOURS", "24"))
SIEM_MIN_LEVEL = int(os.getenv("SIEM_MIN_LEVEL", "3"))
ESCALATION_THRESHOLD = int(os.getenv("ESCALATION_SEVERITY_THRESHOLD", "3"))
STATE_FILE = Path("/app/data/processed_cases.json")

_SYSTEM_PROMPT_PATH = Path("/app/config/system_prompt.txt")

# ---------------------------------------------------------------------------
# Global singletons — initialised at startup
# ---------------------------------------------------------------------------
llm: Optional[LLMClient] = None
siem = None
cases = None
enrichment_conn = None
soar = None

# case_id -> ISO timestamp of last processed updated_at
processed: dict[str, str] = {}


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def _load_state() -> None:
    global processed
    if STATE_FILE.exists():
        try:
            processed = json.loads(STATE_FILE.read_text())
        except Exception:
            processed = {}


def _save_state() -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(processed, indent=2))


def _system_prompt() -> str:
    if _SYSTEM_PROMPT_PATH.exists():
        return _SYSTEM_PROMPT_PATH.read_text()
    return "You are an autonomous SOC analyst AI assistant."


def _already_processed(case: Case) -> bool:
    key = processed.get(case.id)
    if not key:
        return False
    return key >= case.updated_at.isoformat()


def _mark_processed(case: Case) -> None:
    processed[case.id] = case.updated_at.isoformat()
    _save_state()


# ---------------------------------------------------------------------------
# Background case processing
# ---------------------------------------------------------------------------

async def _process_case(case: Case) -> None:
    logger.info("Processing case %s: %s", case.id, case.title)

    # 1. Fetch SIEM logs
    logs = []
    if siem:
        try:
            logs = await siem.get_logs_for_case(case, hours_back=LOG_LOOKBACK)
            logger.info("Fetched %d log entries for case %s", len(logs), case.id)
        except Exception as exc:
            logger.warning("SIEM log fetch failed for %s: %s", case.id, exc)

    # 2. Triage
    result = await triage_module.classify_case(case, logs, llm)
    logger.info("Case %s classified as: %s (%.0f%%)", case.id, result.classification, result.confidence * 100)

    # 3. False positive — document with evidence and flag for analyst approval (no auto-close)
    if result.classification == "false_positive" and result.confidence >= 0.8:
        note = await report_writer.generate_false_positive_note(case, result, logs, llm)
        if cases:
            await cases.add_note(case.id, note)
            await cases.update_case(case.id, CaseUpdate(status="InProgress"))
        await notifier.send_fp_review_alert(case, result, logs)
        logger.info("Case %s flagged as false positive — awaiting analyst approval to close", case.id)
        _mark_processed(case)
        return

    # 4. True positive or needs investigation — full analysis
    enrichment_results = []
    if enrichment_conn and result.iocs:
        try:
            enrichment_results = await enrichment_module.enrich_all(result.iocs, enrichment_conn)
        except Exception as exc:
            logger.warning("Enrichment failed for case %s: %s", case.id, exc)

    analysis = await log_analysis.analyse(case, logs, result, llm)

    # 5. Run playbook
    pb_result = await playbook_runner.run(case, soar_connector=soar)

    # 6. Post findings note to case
    findings_note = _build_findings_note(case, result, analysis, enrichment_results, pb_result)
    if cases:
        await cases.add_note(case.id, findings_note)
        if result.severity >= ESCALATION_THRESHOLD:
            await cases.update_case(case.id, CaseUpdate(status="InProgress"))

    # 7. Alert analyst via WebUI
    await notifier.send_tp_alert(case, result, analysis, enrichment_results, logs)

    _mark_processed(case)
    logger.info("Case %s processing complete", case.id)


def _build_findings_note(case, triage_r, analysis, enrichment_results, pb_result) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"## 🤖 SOC Agent Analysis — {now}",
        f"**Classification:** {triage_r.classification.replace('_', ' ').title()} "
        f"(confidence: {triage_r.confidence:.0%})",
        f"**Kill Chain Stage:** {analysis.kill_chain_stage}",
        "",
        f"### Summary",
        analysis.summary,
        "",
    ]

    if analysis.mitre_ttps:
        lines.append("### MITRE ATT&CK")
        for m in analysis.mitre_ttps:
            lines.append(f"- **{m.get('id')}** — {m.get('name')}: {m.get('evidence', '')}")
        lines.append("")

    if enrichment_results:
        lines.append("### IOC Enrichment")
        lines.append(enrichment_module.format_enrichment_summary(enrichment_results))
        lines.append("")

    if pb_result:
        lines.append(playbook_runner.format_playbook_result(pb_result))

    if analysis.recommended_containment:
        lines.append("### Recommended Actions")
        for r in analysis.recommended_containment:
            lines.append(f"- {r}")
        lines.append("")

    if analysis.analyst_notes:
        lines.append(f"### Notes\n{analysis.analyst_notes}")

    return "\n".join(lines)


async def _background_loop() -> None:
    logger.info("Background loop starting — poll interval: %ds", POLL_INTERVAL)
    await notifier.send_system_message(
        f"SOC Agent started. Monitoring every {POLL_INTERVAL // 60} minutes. "
        f"SIEM: {siem.name if siem else 'disabled'} | "
        f"Cases: {cases.name if cases else 'disabled'} | "
        f"Enrichment: {enrichment_conn.name if enrichment_conn else 'disabled'}"
    )

    while True:
        try:
            if cases:
                open_cases = await cases.get_open_cases()
                logger.info("Poll: %d open cases found", len(open_cases))
                for case in open_cases:
                    if _already_processed(case):
                        continue
                    try:
                        await _process_case(case)
                    except Exception as exc:
                        logger.error("Error processing case %s: %s", case.id, exc)
            else:
                logger.debug("No case connector configured — skipping poll")
        except Exception as exc:
            logger.error("Background loop error: %s", exc)

        await asyncio.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Tool definitions for interactive mode
# ---------------------------------------------------------------------------

_TOOLS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "get_open_cases",
            "description": "List all open security cases from the case management platform",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_case_details",
            "description": "Get full details of a specific case including observables",
            "parameters": {
                "type": "object",
                "properties": {"case_id": {"type": "string", "description": "The case ID"}},
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_siem_logs",
            "description": "Query the SIEM for recent alerts and log entries",
            "parameters": {
                "type": "object",
                "properties": {
                    "hours_back": {"type": "integer", "description": "How many hours back to query", "default": 24},
                    "min_level": {"type": "integer", "description": "Minimum Wazuh rule level (0-15)", "default": 3},
                    "limit": {"type": "integer", "description": "Max results", "default": 50},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_logs_for_case",
            "description": "Get SIEM logs relevant to a specific case",
            "parameters": {
                "type": "object",
                "properties": {"case_id": {"type": "string"}, "hours_back": {"type": "integer", "default": 24}},
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enrich_ioc",
            "description": "Enrich a single IOC (IP, domain, hash) via threat intelligence",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc_type": {"type": "string", "description": "ip | domain | hash | url"},
                    "ioc_value": {"type": "string", "description": "The IOC value"},
                },
                "required": ["ioc_type", "ioc_value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_case_note",
            "description": "Add a note or comment to a case",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "note": {"type": "string", "description": "The note content (Markdown supported)"},
                },
                "required": ["case_id", "note"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "close_case",
            "description": "Close a case with a resolution summary",
            "parameters": {
                "type": "object",
                "properties": {
                    "case_id": {"type": "string"},
                    "resolution": {"type": "string", "description": "Why this case is being closed"},
                },
                "required": ["case_id", "resolution"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_playbook",
            "description": "Load and execute the appropriate investigation playbook for a case",
            "parameters": {
                "type": "object",
                "properties": {"case_id": {"type": "string"}},
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "generate_report",
            "description": "Generate a full incident report for a case and post it to the case",
            "parameters": {
                "type": "object",
                "properties": {"case_id": {"type": "string"}},
                "required": ["case_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "trigger_soar_action",
            "description": "Trigger a SOAR workflow action. ALWAYS confirm with the analyst before calling this for destructive actions (block, isolate, disable).",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "description": "Action name e.g. block_ip, isolate_host, disable_user"},
                    "case_id": {"type": "string"},
                    "target": {"type": "string", "description": "The target IP, hostname, or username"},
                },
                "required": ["action", "case_id", "target"],
            },
        },
    },
]


async def _execute_tool(name: str, args: dict) -> str:
    """Dispatches tool calls from the interactive agentic loop."""

    if name == "get_open_cases":
        if not cases:
            return "Case management is not configured."
        case_list = await cases.get_open_cases()
        return json.dumps(
            [{"id": c.id, "title": c.title, "severity": c.severity, "status": c.status, "tags": c.tags}
             for c in case_list],
            default=str,
        )

    if name == "get_case_details":
        if not cases:
            return "Case management is not configured."
        case = await cases.get_case(args["case_id"])
        return json.dumps({
            "id": case.id, "title": case.title, "severity": case.severity,
            "status": case.status, "description": case.description,
            "tags": case.tags,
            "observables": [{"type": o.type, "value": o.value} for o in case.observables],
        }, default=str)

    if name == "get_siem_logs":
        if not siem:
            return "SIEM is not configured."
        alerts = await siem.get_alerts(
            limit=args.get("limit", 50),
            min_level=args.get("min_level", SIEM_MIN_LEVEL),
            hours_back=args.get("hours_back", 24),
        )
        return json.dumps(
            [{"id": a.id, "title": a.title, "severity": a.severity,
              "timestamp": str(a.timestamp), "rule_id": a.rule_id,
              "agent": a.agent_name, "mitre": a.mitre_ids}
             for a in alerts],
            default=str,
        )

    if name == "get_logs_for_case":
        if not siem or not cases:
            return "SIEM or case management not configured."
        case = await cases.get_case(args["case_id"])
        logs = await siem.get_logs_for_case(case, hours_back=args.get("hours_back", LOG_LOOKBACK))
        return json.dumps(
            [{"timestamp": str(l.timestamp), "rule": l.rule_name,
              "level": l.rule_level, "agent": l.agent_name,
              "process": l.process, "cmd": l.command_line,
              "src_ip": l.source_ip, "mitre": l.mitre_ids}
             for l in logs[:100]],
            default=str,
        )

    if name == "enrich_ioc":
        if not enrichment_conn:
            return "Enrichment is not configured."
        ioc = IOC(type=args["ioc_type"], value=args["ioc_value"])
        result = await enrichment_conn.enrich(ioc)
        return json.dumps({
            "ioc": args["ioc_value"],
            "verdict": result.verdict,
            "score": result.score,
            "source": result.source,
            "details": result.details,
        }, default=str)

    if name == "add_case_note":
        if not cases:
            return "Case management is not configured."
        await cases.add_note(args["case_id"], args["note"])
        return f"Note added to case {args['case_id']}"

    if name == "close_case":
        if not cases:
            return "Case management is not configured."
        await cases.close_case(args["case_id"], args["resolution"])
        return f"Case {args['case_id']} closed."

    if name == "run_playbook":
        if not cases:
            return "Case management is not configured."
        case = await cases.get_case(args["case_id"])
        pb_result = await playbook_runner.run(case, soar_connector=soar)
        return playbook_runner.format_playbook_result(pb_result)

    if name == "generate_report":
        if not cases:
            return "Case management is not configured."
        case = await cases.get_case(args["case_id"])
        logs = await siem.get_logs_for_case(case) if siem else []
        t_result = await triage_module.classify_case(case, logs, llm)
        analysis = await log_analysis.analyse(case, logs, t_result, llm)
        enrich_results = []
        if enrichment_conn and t_result.iocs:
            enrich_results = await enrichment_module.enrich_all(t_result.iocs, enrichment_conn)
        pb_result = await playbook_runner.run(case, soar_connector=soar)
        report = await report_writer.generate_incident_report(
            case, t_result, analysis, enrich_results, pb_result, llm
        )
        if cases:
            await cases.add_note(case.id, report)
        return report

    if name == "trigger_soar_action":
        if not soar:
            return "SOAR is not configured."
        result = await soar.trigger(
            action=args["action"],
            payload={"case_id": args["case_id"], "target": args.get("target", "")},
        )
        return f"SOAR action '{args['action']}': {'success' if result.success else 'failed — ' + str(result.error)}"

    return f"Unknown tool: {name}"


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global llm, siem, cases, enrichment_conn, soar

    _load_state()

    llm = LLMClient(OLLAMA_URL, OLLAMA_MODEL, OLLAMA_KEEP_ALIVE)
    siem = get_siem_connector()
    cases = get_case_connector()
    enrichment_conn = get_enrichment_connector()
    soar = get_soar_connector()

    logger.info("Connectors: SIEM=%s | Cases=%s | Enrichment=%s | SOAR=%s",
                siem.name if siem else "disabled",
                cases.name if cases else "disabled",
                enrichment_conn.name if enrichment_conn else "disabled",
                soar.name if soar else "disabled")

    # Create SOC Monitor chat if API key is set but no chat ID yet
    if os.getenv("WEBUI_API_KEY") and not os.getenv("WEBUI_MONITOR_CHAT_ID"):
        await notifier.create_monitor_chat()

    # Start background polling loop
    loop_task = asyncio.create_task(_background_loop())

    yield

    loop_task.cancel()
    try:
        await loop_task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="SOC AI Agent", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# OpenAI-compatible endpoints
# ---------------------------------------------------------------------------

class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "soc-agent"
    messages: list[Message]
    stream: bool = False
    temperature: float = 0.1
    max_tokens: Optional[int] = None


def _make_chunk(content: str, finish_reason: Optional[str] = None) -> str:
    chunk = {
        "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": "soc-agent",
        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": finish_reason}],
    }
    return f"data: {json.dumps(chunk)}\n\n"


async def _stream_response(messages: list[dict]) -> AsyncIterator[str]:
    # Run agentic tool-call loop first (non-streaming), then stream final answer
    sys_prompt = _system_prompt()
    full_messages = [{"role": "system", "content": sys_prompt}] + messages

    final_response = await llm.agentic_complete(
        messages=full_messages,
        tools=_TOOLS,
        tool_executor=_execute_tool,
    )

    # Stream the final response word-by-word for UX
    words = final_response.split(" ")
    for i, word in enumerate(words):
        chunk_text = word + (" " if i < len(words) - 1 else "")
        yield _make_chunk(chunk_text)
        await asyncio.sleep(0.01)

    yield _make_chunk("", finish_reason="stop")
    yield "data: [DONE]\n\n"


@app.get("/v1/models")
async def list_models():
    return {
        "object": "list",
        "data": [
            {
                "id": "soc-agent",
                "object": "model",
                "created": 1700000000,
                "owned_by": "soc-lab",
                "description": "SOC AI Agent — autonomous security analyst",
            }
        ],
    }


@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    if not llm:
        raise HTTPException(status_code=503, detail="LLM client not initialised")

    messages = [{"role": m.role, "content": m.content} for m in request.messages]

    if request.stream:
        return StreamingResponse(
            _stream_response(messages),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # Non-streaming
    sys_prompt = _system_prompt()
    full_messages = [{"role": "system", "content": sys_prompt}] + messages
    content = await llm.agentic_complete(
        messages=full_messages,
        tools=_TOOLS,
        tool_executor=_execute_tool,
    )

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "soc-agent",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


@app.get("/health")
async def health():
    llm_ok = await llm.is_available() if llm else False
    return {
        "status": "ok" if llm_ok else "degraded",
        "llm": llm_ok,
        "siem": siem.name if siem else None,
        "cases": cases.name if cases else None,
        "enrichment": enrichment_conn.name if enrichment_conn else None,
        "soar": soar.name if soar else None,
        "processed_cases": len(processed),
    }


@app.post("/run")
async def run_now(force: bool = False):
    """Trigger an immediate poll and process all open cases.
    force=true clears processed state so all open cases are re-analysed.
    """
    if not cases:
        raise HTTPException(status_code=503, detail="No case connector configured")
    if force:
        processed.clear()
        _save_state()
        logger.info("Forced run: processed state cleared")
    open_cases = await cases.get_open_cases()
    queued = []
    skipped = []
    for case in open_cases:
        if _already_processed(case):
            skipped.append(case.id)
        else:
            queued.append(case.id)
            asyncio.create_task(_process_case(case))
    return {
        "open_cases": len(open_cases),
        "queued": queued,
        "skipped_already_processed": skipped,
    }
