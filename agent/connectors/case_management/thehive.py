from __future__ import annotations
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from ..base import CaseConnector, Case, CaseUpdate, Observable

logger = logging.getLogger(__name__)


class TheHiveConnector(CaseConnector):
    def __init__(self, url: str, api_key: str, org: str = "SOCLab"):
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._org = org

    @property
    def name(self) -> str:
        return "thehive"

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "X-Organisation": self._org,
        }

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self._url}/api/v1/user/current",
                    headers=self._headers(),
                )
                return resp.status_code == 200
        except Exception as exc:
            logger.warning("TheHive not available: %s", exc)
            return False

    async def get_open_cases(self) -> list[Case]:
        body = {
            "query": [
                {"_name": "listCase"},
                {"_name": "filter", "_and": [{"_in": {"_field": "status", "_values": ["New", "InProgress"]}}]},
                {"_name": "sort", "_fields": [{"_updatedAt": "desc"}]},
                {"_name": "page", "from": 0, "to": 100},
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{self._url}/api/v1/query?name=list-cases",
                    headers=self._headers(),
                    json=body,
                )
                resp.raise_for_status()
                return [self._parse_case(c) for c in resp.json()]
        except Exception as exc:
            logger.error("TheHive get_open_cases failed: %s", exc)
            return []

    async def get_case(self, case_id: str) -> Case:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self._url}/api/v1/case/{case_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            case = self._parse_case(resp.json())

        # Fetch observables separately
        case.observables = await self._get_observables(case_id)
        return case

    async def _get_observables(self, case_id: str) -> list[Observable]:
        body = {
            "query": [
                {"_name": "getCase", "idOrName": case_id},
                {"_name": "observables"},
                {"_name": "page", "from": 0, "to": 100},
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{self._url}/api/v1/query?name=case-observables",
                    headers=self._headers(),
                    json=body,
                )
                if resp.status_code != 200:
                    return []
                return [
                    Observable(
                        id=o.get("_id", ""),
                        type=o.get("dataType", ""),
                        value=o.get("data", ""),
                        tags=o.get("tags", []),
                    )
                    for o in resp.json()
                ]
        except Exception:
            return []

    async def add_note(self, case_id: str, note: str) -> None:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{self._url}/api/v1/case/{case_id}/comment",
                    headers=self._headers(),
                    json={"message": note},
                )
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.error("TheHive add_note failed for case %s: HTTP %s — %s",
                         case_id, exc.response.status_code, exc.response.text[:300])
        except Exception as exc:
            logger.error("TheHive add_note failed for case %s: %r", case_id, exc)

    async def update_case(self, case_id: str, update: CaseUpdate) -> None:
        body: dict = {}
        if update.status:
            body["status"] = update.status
        if update.severity:
            body["severity"] = update.severity
        if not body:
            return
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.patch(
                    f"{self._url}/api/v1/case/{case_id}",
                    headers=self._headers(),
                    json=body,
                )
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.error("TheHive update_case failed for %s: HTTP %s — %s",
                         case_id, exc.response.status_code, exc.response.text[:300])
        except Exception as exc:
            logger.error("TheHive update_case failed for %s: %r", case_id, exc)

    async def close_case(self, case_id: str, resolution: str) -> None:
        body = {
            "status": "Resolved",
            "summary": resolution,
            "resolutionStatus": "FalsePositive",
            "impactStatus": "NoImpact",
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.patch(
                    f"{self._url}/api/v1/case/{case_id}",
                    headers=self._headers(),
                    json=body,
                )
                resp.raise_for_status()
        except Exception as exc:
            logger.error("TheHive close_case failed for %s: %s", case_id, exc)

    # ------------------------------------------------------------------
    # Parser
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_case(data: dict) -> Case:
        return Case(
            id=data.get("_id", data.get("id", "")),
            title=data.get("title", ""),
            severity=data.get("severity", 1),
            status=data.get("status", "Open"),
            created_at=TheHiveConnector._epoch_to_dt(data.get("_createdAt", 0)),
            updated_at=TheHiveConnector._epoch_to_dt(data.get("_updatedAt", 0)),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            source=data.get("source", ""),
            source_ref=data.get("sourceRef", ""),
        )

    @staticmethod
    def _epoch_to_dt(epoch_ms: int) -> datetime:
        try:
            return datetime.fromtimestamp(epoch_ms / 1000, tz=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
