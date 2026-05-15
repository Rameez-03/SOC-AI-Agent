#!/usr/bin/env python3
"""
Wazuh Alert File API — reads current alerts.json + daily archives.
Serves GET /alerts with Wazuh-compatible response format.
"""
import gzip, json, os
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

ALERTS_DIR = "/var/ossec/logs/alerts"
ALERTS_FILE = f"{ALERTS_DIR}/alerts.json"
PORT = 55001
MONTH = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]


def _parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00").replace("+0000", "+00:00"))
    except Exception:
        return None


def _archive_paths(since, until):
    paths = []
    start = since.date() if since else None
    end   = until.date() if until else None
    if start and end:
        day = start
        while day <= end:
            base = f"{ALERTS_DIR}/{day.year}/{MONTH[day.month-1]}/ossec-alerts-{day.day:02d}"
            for ext in (".json", ".json.gz"):
                if os.path.exists(base + ext):
                    paths.append(base + ext)
                    break
            day += timedelta(days=1)
    if os.path.exists(ALERTS_FILE) and ALERTS_FILE not in paths:
        paths.append(ALERTS_FILE)
    return paths


def _read(path):
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rb") as f:
                return f.read().decode("utf-8", errors="ignore")
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > 52428800:
                f.seek(size - 52428800)
                f.readline()
            return f.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not urlparse(self.path).path.startswith("/alerts"):
            self.send_response(404); self.end_headers(); return

        p = parse_qs(urlparse(self.path).query)
        limit = int(p.get("limit", ["200"])[0])
        q = p.get("q", [""])[0]

        since = until = rule_id = agent_name = None
        min_level = 0
        for part in q.split(";"):
            if part.startswith("timestamp>"):    since = _parse_ts(part[10:])
            elif part.startswith("timestamp<"):  until = _parse_ts(part[10:])
            elif part.startswith("rule.id="):    rule_id = part[8:]
            elif part.startswith("agent.name="): agent_name = part[11:]
            elif part.startswith("rule.level>="):
                try: min_level = int(part[12:])
                except Exception: pass

        items = []
        for path in _archive_paths(since, until):
            for line in _read(path).splitlines():
                if len(items) >= limit: break
                line = line.strip()
                if not line: continue
                try: alert = json.loads(line)
                except Exception: continue
                ts = _parse_ts(alert.get("timestamp", ""))
                if ts:
                    if since and ts < since: continue
                    if until and ts > until: continue
                rule = alert.get("rule", {})
                if rule_id and str(rule.get("id", "")) != str(rule_id): continue
                if agent_name and alert.get("agent", {}).get("name", "") != agent_name: continue
                if min_level and int(rule.get("level", 0)) < min_level: continue
                items.append(alert)
            if len(items) >= limit:
                break

        body = json.dumps({"data": {"affected_items": items,
            "total_affected_items": len(items),
            "total_failed_items": 0, "failed_items": []},
            "error": 0}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers(); self.wfile.write(body)

    def log_message(self, *_): pass


HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
