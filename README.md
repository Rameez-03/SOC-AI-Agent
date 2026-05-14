# SOC-AI-Agent

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?style=flat-square)
![Ollama](https://img.shields.io/badge/Ollama-Qwen2.5:14B-purple?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Compose-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

A containerised, fully local AI SOC analyst that runs on your own hardware. No cloud. No data egress. One command to start.

Built as a companion to [SOC-Lab](https://github.com/Rameez-03/SOC-Lab) but designed to work with any security stack via a pluggable connector architecture.

---

## What It Does

The agent runs two modes simultaneously inside one container:

**Autonomous** — polls your case management platform every N minutes, triages every open case, auto-closes false positives with documentation, and sends you a direct alert in the browser UI for every true positive it finds.

**Interactive** — you talk to it like a colleague via the browser. Ask it to investigate a case, enrich an IOC, run a playbook, or generate a report. It executes against your live tools and responds with findings.

### Autonomous workflow

```
Poll TheHive (every 15 min)
       │
  For each new/updated case:
       │
   Fetch Wazuh logs
       │
   Classify with LLM ──── False Positive ──► Auto-document + close case
       │
   True Positive
       │
   Enrich IOCs (Cortex/VirusTotal/AbuseIPDB)
       │
   Deep log analysis + MITRE mapping
       │
   Run playbook (auto-step low-risk, flag high-risk for approval)
       │
   Post findings to TheHive case
       │
   Alert analyst in SOC Monitor chat (Open WebUI)
```

### Interactive commands (examples)

```
"Show me all open critical cases"
"Investigate case ~12345"
"Enrich IP 185.220.101.5"
"Run the brute force playbook on case ~12345"
"Generate the incident report for case ~12345"
"Block IP 185.220.101.5 on case ~12345"  → asks for approval first
```

---

## Architecture

```
Browser (Open WebUI :8080)
        │
        ▼
SOC Agent (FastAPI :8000)          ← background polling loop runs here
        │  OpenAI-compatible API
        ▼
   Ollama :11434
   Qwen 2.5 14B (local)
        │
        ▼ (tool calls)
Wazuh :55000 | TheHive :9000 | Cortex :9001 | Shuffle :3001
```

---

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU VRAM | 8 GB | 12 GB (RTX 4070) |
| System RAM | 16 GB | 32 GB |
| Storage | 20 GB | 50 GB+ |
| OS | Windows 10/11, Ubuntu, macOS | Any |

Swap `qwen2.5:14b` for `qwen2.5:7b` in `.env` if you have 6 GB VRAM. CPU-only works but is slow (~5 tokens/sec).

---

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- NVIDIA drivers 470.76+ (for GPU acceleration on Windows/Linux)
- Docker Desktop using WSL2 backend (Windows)
- Your SOC tools running and reachable from the host machine

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/Rameez-03/SOC-AI-Agent
cd SOC-AI-Agent
copy .env.example .env      # Windows
# cp .env.example .env      # Linux/macOS
```

Open `.env` and fill in your credentials. Every variable has a comment explaining where to find the value.

**Minimum required fields:**

```env
WAZUH_PASSWORD=          # Your wazuh-wui password
THEHIVE_API_KEY=         # analyst@soclab.local API key from TheHive
CORTEX_API_KEY=          # New agent user API key from Cortex
WEBUI_SECRET_KEY=        # Any random string (for WebUI session signing)
```

### 2. Start the stack

```bash
docker compose up -d
```

This starts:
- **Ollama** — local LLM runner (GPU-accelerated)
- **model-init** — pulls `qwen2.5:14b` on first run (downloads ~9 GB, one-time)
- **soc-agent** — the FastAPI agent
- **open-webui** — browser interface at `http://localhost:8080`

Monitor startup:
```bash
docker compose logs -f
```

### 3. First login to Open WebUI

1. Open `http://localhost:8080` in your browser
2. Create an admin account (first user becomes admin)
3. Go to **Settings → Account → API Keys → New Key**
4. Copy the key and add it to `.env`:
   ```env
   WEBUI_API_KEY=sk-...
   ```

### 4. Get your SOC Monitor chat ID

The agent creates the SOC Monitor chat automatically on startup if `WEBUI_API_KEY` is set. Check the logs:

```bash
docker compose logs soc-agent | findstr "SOC Monitor"
# Linux: docker compose logs soc-agent | grep "SOC Monitor"
```

You'll see:
```
SOC Monitor chat created — ID: abc123def456
Add WEBUI_MONITOR_CHAT_ID=abc123def456 to your .env and restart the agent.
```

Add it to `.env`:
```env
WEBUI_MONITOR_CHAT_ID=abc123def456
```

### 5. Restart the agent to pick up the new values

```bash
docker compose restart soc-agent
```

### 6. Verify everything is working

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "llm": true,
  "siem": "wazuh",
  "cases": "thehive",
  "enrichment": "cortex",
  "soar": null
}
```

---

## Using the Agent

### SOC Monitor (proactive alerts)

Open `http://localhost:8080`, find the **SOC Monitor** chat in the sidebar, and keep it open. When the agent finds a true positive, a message appears here automatically:

```
🚨 SOC ALERT — CRITICAL SEVERITY
Time: 14:32 UTC
Case: Brute Force Detected — windows10
Classification: True Positive (92% confidence)

Summary: Metasploit smb_login executed 147 auth attempts against
192.168.56.30 in 60s. Rule 100500 fired. No successful logon found.

MITRE ATT&CK: T1110.001
IOCs: 192.168.56.20 (ip)

Recommended: Block source IP, review logs for successful auth
```

### Interactive chat

Click **+** in Open WebUI to start a new chat. Select **soc-agent** as the model.

```
> Investigate case ~12345
> What IOCs are in all open critical cases?
> Enrich IP 185.220.101.5
> Run the brute force playbook on case ~12345
> Generate the incident report for case ~12345 and post it to TheHive
> Block IP 185.220.101.5 on case ~12345   ← agent asks for confirmation first
```

---

## Configuration Reference

All configuration is in `.env`. See `.env.example` for the full list with comments.

### Switching tools (portability)

```env
# Different SIEM:
SIEM_BACKEND=elastic       # or: wazuh | none

# Different case management:
CASE_BACKEND=jira          # or: thehive | none

# Enrich directly (no Cortex needed):
ENRICHMENT_BACKEND=direct
VIRUSTOTAL_API_KEY=your-key
ABUSEIPDB_API_KEY=your-key

# Different SOAR:
SOAR_BACKEND=generic_webhook
SOAR_WEBHOOK_URL=https://your-n8n-instance/webhook/...
```

---

## Connector Backends

| Type | Available |
|------|-----------|
| SIEM | `wazuh` ✅ · `elastic` (stub) |
| Case management | `thehive` ✅ · `jira` (stub) |
| Enrichment | `cortex` ✅ · `direct` ✅ (VT + AbuseIPDB) |
| SOAR | `shuffle` ✅ · `generic_webhook` ✅ |

### Adding a new connector

1. Create `agent/connectors/<type>/yourplatform.py`
2. Inherit from the abstract base class in `agent/connectors/base.py`
3. Implement all `@abstractmethod` methods
4. Register it in `agent/connectors/registry.py`
5. Add env vars to `.env.example`

---

## Playbooks

Live in `config/playbooks/`. Each is a Markdown file with numbered steps. Steps containing high-risk keywords (`block`, `isolate`, `disable`, `quarantine`) require analyst approval unless `AUTO_EXECUTE_PLAYBOOKS=true`.

Included:
- `brute_force.md` — Rule 100500, T1110.001
- `malware_execution.md` — Rules 100001-100004, PowerShell/LOLBin/WMI
- `lateral_movement.md` — Rules 100400, 100600, injection and recon chains

Add your own by dropping a numbered Markdown file into `config/playbooks/`.

---

## Project Structure

```
SOC-AI-Agent/
├── docker-compose.yml
├── .env.example
├── agent/
│   ├── main.py               # FastAPI + background loop + OpenAI API
│   ├── llm_client.py         # Ollama wrapper
│   ├── triage.py             # TP/FP classification
│   ├── log_analysis.py       # SIEM log deep analysis
│   ├── enrichment.py         # IOC enrichment orchestrator
│   ├── playbook_runner.py    # Playbook execution
│   ├── report_writer.py      # Incident report generation
│   ├── notifier.py           # Open WebUI push alerts
│   └── connectors/
│       ├── base.py           # Data models + abstract interfaces
│       ├── registry.py       # Connector factory
│       ├── siem/             # wazuh.py, elastic.py
│       ├── case_management/  # thehive.py, jira.py
│       ├── enrichment/       # cortex.py, direct.py
│       └── soar/             # shuffle.py, webhook.py
├── config/
│   ├── system_prompt.txt
│   ├── playbooks/
│   └── templates/
└── ollama/
    └── Modelfile
```

---

## Troubleshooting

**Model download slow** — First run downloads ~9 GB. Check: `docker compose logs model-init -f`

**Agent can't reach Wazuh/TheHive** — Confirm your VMs are running. On Windows with Docker Desktop + WSL2, the `192.168.56.x` host-only network is reachable from containers.

**No model in WebUI** — Select `soc-agent` from the model dropdown. Check agent is running: `curl http://localhost:8000/v1/models`

**LLM not using GPU** — Check: `docker exec soc-ollama ollama ps`. Should show GPU layers. Verify NVIDIA drivers and Docker Desktop GPU support.

**Cortex enrichment times out** — Analyzer jobs can take 30-60s. Timeout is set to 90s in `connectors/enrichment/cortex.py` (`_JOB_TIMEOUT`).

---

## Related

- [SOC-Lab](https://github.com/Rameez-03/SOC-Lab) — the home lab this was built on top of
