from __future__ import annotations
import asyncio
import logging
from typing import Optional

import httpx

from ..base import EnrichmentConnector, EnrichmentResult, IOC

logger = logging.getLogger(__name__)

# Maps IOC type to the Cortex analyzers to run, in priority order
_ANALYZER_MAP: dict[str, list[str]] = {
    "ip": ["VirusTotal_GetReport_3_1", "Abuse_Finder_3_0"],
    "domain": ["VirusTotal_GetReport_3_1", "Abuse_Finder_3_0"],
    "fqdn": ["VirusTotal_GetReport_3_1", "Abuse_Finder_3_0"],
    "url": ["VirusTotal_GetReport_3_1"],
    "hash": ["VirusTotal_GetReport_3_1"],
    "mail": ["Abuse_Finder_3_0"],
}

_JOB_POLL_INTERVAL = 3      # seconds between status checks
_JOB_TIMEOUT = 90           # seconds before giving up on a job


class CortexConnector(EnrichmentConnector):
    def __init__(self, url: str, api_key: str):
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._available_analyzers: Optional[set[str]] = None

    @property
    def name(self) -> str:
        return "cortex"

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._api_key}"}

    def _json_headers(self) -> dict:
        return {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{self._url}/api/analyzer?range=all",
                    headers=self._headers(),
                )
                return resp.status_code == 200
        except Exception as exc:
            logger.warning("Cortex not available: %s", exc)
            return False

    async def _get_available_analyzers(self) -> set[str]:
        if self._available_analyzers is not None:
            return self._available_analyzers
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{self._url}/api/analyzer?range=all",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                self._available_analyzers = {a["name"] for a in resp.json()}
                return self._available_analyzers
        except Exception as exc:
            logger.error("Could not fetch Cortex analyzers: %s", exc)
            return set()

    async def enrich(self, ioc: IOC) -> EnrichmentResult:
        if ioc.type not in _ANALYZER_MAP:
            logger.debug("Skipping enrichment for unsupported IOC type=%s", ioc.type)
            return EnrichmentResult(ioc=ioc, source="cortex", verdict="unknown", details={"error": "unsupported type"})
        available = await self._get_available_analyzers()
        wanted = _ANALYZER_MAP[ioc.type]
        runnable = [a for a in wanted if a in available]

        if not runnable:
            logger.warning("No Cortex analyzers available for IOC type=%s", ioc.type)
            return EnrichmentResult(ioc=ioc, source="cortex", verdict="unknown", details={"error": "no analyzers"})

        results = []
        for analyzer_name in runnable:
            result = await self._run_analyzer(analyzer_name, ioc)
            if result:
                results.append(result)

        if not results:
            return EnrichmentResult(ioc=ioc, source="cortex", verdict="unknown")

        # Merge results: worst verdict wins
        merged = self._merge_results(ioc, results)
        return merged

    async def _run_analyzer(self, analyzer_name: str, ioc: IOC) -> Optional[dict]:
        body = {
            "data": ioc.value,
            "dataType": ioc.type,
            "tlp": 2,
            "pap": 2,
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{self._url}/api/analyzer/{analyzer_name}/run",
                    headers=self._json_headers(),
                    json=body,
                )
                resp.raise_for_status()
                job_id = resp.json().get("id")

            report = await self._poll_job(job_id)
            return {"analyzer": analyzer_name, "report": report}
        except Exception as exc:
            logger.error("Cortex analyzer %s failed for %s: %s", analyzer_name, ioc.value, exc)
            return None

    async def _poll_job(self, job_id: str) -> dict:
        deadline = asyncio.get_event_loop().time() + _JOB_TIMEOUT
        async with httpx.AsyncClient(timeout=10) as client:
            while asyncio.get_event_loop().time() < deadline:
                resp = await client.get(
                    f"{self._url}/api/job/{job_id}",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()
                status = data.get("status", "")
                if status == "Success":
                    report_resp = await client.get(
                        f"{self._url}/api/job/{job_id}/report",
                        headers=self._headers(),  # GET — no Content-Type
                    )
                    return report_resp.json() if report_resp.status_code == 200 else data
                if status in ("Failure", "Deleted"):
                    logger.warning("Cortex job %s ended with status: %s", job_id, status)
                    return data
                await asyncio.sleep(_JOB_POLL_INTERVAL)
        logger.warning("Cortex job %s timed out after %ss", job_id, _JOB_TIMEOUT)
        return {}

    @staticmethod
    def _merge_results(ioc: IOC, results: list[dict]) -> EnrichmentResult:
        verdicts = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}
        worst = "unknown"
        score = None
        merged_details: dict = {}

        for r in results:
            analyzer = r.get("analyzer", "")
            report = r.get("report", {})
            summary = report.get("summary", {})
            taxonomies = summary.get("taxonomies", [])

            merged_details[analyzer] = summary

            for tax in taxonomies:
                level = tax.get("level", "unknown").lower()
                value = tax.get("value")

                if level == "malicious":
                    worst = "malicious"
                    if value and "/" in str(value):
                        try:
                            flagged, total = str(value).split("/")
                            score = int(int(flagged) / int(total) * 100)
                        except Exception:
                            pass
                elif level in ("suspicious", "info") and worst != "malicious":
                    worst = "suspicious"
                elif level == "safe" and worst == "unknown":
                    worst = "clean"

        return EnrichmentResult(
            ioc=ioc,
            source="cortex",
            verdict=worst,
            score=score,
            details=merged_details,
        )
