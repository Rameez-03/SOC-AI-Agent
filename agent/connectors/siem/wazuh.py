from __future__ import annotations
import asyncio
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx

from ..base import SIEMConnector, Alert, LogEntry, Case, IOC

logger = logging.getLogger(__name__)

# Wazuh JWTs expire after 900 seconds by default — refresh at 800s
_TOKEN_TTL = 800


class WazuhConnector(SIEMConnector):
    def __init__(self, url: str, user: str, password: str, verify_ssl: bool = False):
        self._url = url.rstrip("/")
        self._user = user
        self._password = password
        self._verify_ssl = verify_ssl
        self._token: Optional[str] = None
        self._token_fetched_at: float = 0.0

    @property
    def name(self) -> str:
        return "wazuh"

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def _get_token(self) -> str:
        if self._token and (time.monotonic() - self._token_fetched_at) < _TOKEN_TTL:
            return self._token

        async with httpx.AsyncClient(verify=self._verify_ssl, timeout=15) as client:
            resp = await client.post(
                f"{self._url}/security/user/authenticate",
                auth=(self._user, self._password),
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
            self._token_fetched_at = time.monotonic()
            return self._token

    async def _headers(self) -> dict:
        token = await self._get_token()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def is_available(self) -> bool:
        try:
            await self._get_token()
            return True
        except Exception as exc:
            logger.warning("Wazuh not available: %s", exc)
            return False

    async def get_alerts(
        self,
        limit: int = 100,
        min_level: int = 3,
        hours_back: int = 24,
    ) -> list[Alert]:
        headers = await self._headers()
        since = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        params = {
            "limit": limit,
            "sort": "-timestamp",
            "q": f"rule.level>={min_level};timestamp>{since}",
        }

        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=30) as client:
                resp = await client.get(
                    f"{self._url}/alerts",
                    headers=headers,
                    params=params,
                )
                resp.raise_for_status()
                items = resp.json().get("data", {}).get("affected_items", [])
                return [self._parse_alert(item) for item in items]
        except Exception as exc:
            logger.error("Wazuh get_alerts failed: %s", exc)
            return []

    async def get_logs_for_case(
        self,
        case: Case,
        hours_back: int = 24,
    ) -> list[LogEntry]:
        """
        Builds a Wazuh query from case context (tags, observables, timeframe)
        and returns matching log entries.
        """
        headers = await self._headers()

        # Extract agent name from tags or observables
        agent_name = self._extract_agent(case)
        rule_ids = self._extract_rule_ids(case)
        since = (case.created_at - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        until = (case.created_at + timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")

        filters = [f"timestamp>{since}", f"timestamp<{until}"]
        if agent_name:
            filters.append(f"agent.name={agent_name}")
        if rule_ids:
            # Query for first rule ID; Wazuh doesn't support OR in q param
            filters.append(f"rule.id={rule_ids[0]}")

        params = {
            "limit": 500,
            "sort": "-timestamp",
            "q": ";".join(filters),
        }

        try:
            async with httpx.AsyncClient(verify=self._verify_ssl, timeout=30) as client:
                resp = await client.get(
                    f"{self._url}/alerts",
                    headers=headers,
                    params=params,
                )
                resp.raise_for_status()
                items = resp.json().get("data", {}).get("affected_items", [])

                # If multiple rule IDs, fetch each and merge
                all_items = list(items)
                for rule_id in rule_ids[1:]:
                    p2 = dict(params)
                    p2["q"] = ";".join(
                        [f for f in filters if not f.startswith("rule.id")]
                        + [f"rule.id={rule_id}"]
                    )
                    r2 = await client.get(f"{self._url}/alerts", headers=headers, params=p2)
                    if r2.status_code == 200:
                        all_items.extend(r2.json().get("data", {}).get("affected_items", []))

                return [self._parse_log(item) for item in all_items]
        except Exception as exc:
            logger.error("Wazuh get_logs_for_case failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    def _parse_alert(self, item: dict) -> Alert:
        rule = item.get("rule", {})
        agent = item.get("agent", {})
        mitre = rule.get("mitre", {})
        ts = self._parse_ts(item.get("timestamp", ""))
        return Alert(
            id=item.get("id", ""),
            title=rule.get("description", "Unknown alert"),
            severity=self._level_to_severity(rule.get("level", 0)),
            timestamp=ts,
            source="Wazuh",
            rule_id=str(rule.get("id", "")),
            rule_level=rule.get("level"),
            agent_name=agent.get("name"),
            agent_ip=agent.get("ip"),
            description=rule.get("description", ""),
            mitre_ids=mitre.get("id", []) if isinstance(mitre, dict) else [],
            raw=item,
        )

    def _parse_log(self, item: dict) -> LogEntry:
        rule = item.get("rule", {})
        agent = item.get("agent", {})
        data = item.get("data", {})
        win = data.get("win", {})
        edata = win.get("eventdata", {})
        mitre = rule.get("mitre", {})
        ts = self._parse_ts(item.get("timestamp", ""))
        return LogEntry(
            id=item.get("id", ""),
            timestamp=ts,
            rule_id=str(rule.get("id", "")),
            rule_name=rule.get("description"),
            rule_level=rule.get("level"),
            agent_name=agent.get("name"),
            source_ip=edata.get("ipAddress") or edata.get("sourceIp"),
            dest_ip=edata.get("destinationIp"),
            process=edata.get("image") or edata.get("parentImage"),
            command_line=edata.get("commandLine"),
            mitre_ids=mitre.get("id", []) if isinstance(mitre, dict) else [],
            raw=item,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ts(ts_str: str) -> datetime:
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _level_to_severity(level: int) -> int:
        if level >= 12:
            return 4
        if level >= 8:
            return 3
        if level >= 4:
            return 2
        return 1

    @staticmethod
    def _extract_agent(case: Case) -> Optional[str]:
        for tag in case.tags:
            if tag.lower().startswith("agent:"):
                return tag.split(":", 1)[1].strip()
        # Try description heuristic
        for word in case.description.split():
            if word.lower().startswith("agent="):
                return word.split("=", 1)[1]
        return None

    @staticmethod
    def _extract_rule_ids(case: Case) -> list[str]:
        ids = []
        for tag in case.tags:
            if tag.lower().startswith("rule-"):
                ids.append(tag.split("-", 1)[1])
        return ids
