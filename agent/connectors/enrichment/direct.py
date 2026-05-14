"""
Direct enrichment connector — calls VirusTotal and AbuseIPDB APIs directly
without needing a Cortex instance. Use this if ENRICHMENT_BACKEND=direct.
"""
from __future__ import annotations
import logging
from typing import Optional

import httpx

from ..base import EnrichmentConnector, EnrichmentResult, IOC

logger = logging.getLogger(__name__)


class DirectEnrichmentConnector(EnrichmentConnector):
    def __init__(self, vt_api_key: str = "", abuseipdb_api_key: str = ""):
        self._vt_key = vt_api_key
        self._abuse_key = abuseipdb_api_key

    @property
    def name(self) -> str:
        return "direct"

    async def is_available(self) -> bool:
        return bool(self._vt_key or self._abuse_key)

    async def enrich(self, ioc: IOC) -> EnrichmentResult:
        results = []

        if self._vt_key and ioc.type in ("ip", "domain", "hash", "url"):
            vt = await self._virustotal(ioc)
            if vt:
                results.append(vt)

        if self._abuse_key and ioc.type == "ip":
            abuse = await self._abuseipdb(ioc)
            if abuse:
                results.append(abuse)

        if not results:
            return EnrichmentResult(ioc=ioc, source="direct", verdict="unknown")

        # Worst verdict wins
        worst = "unknown"
        score: Optional[int] = None
        details: dict = {}
        for r in results:
            details.update(r.details)
            if r.verdict == "malicious":
                worst = "malicious"
            elif r.verdict == "suspicious" and worst != "malicious":
                worst = "suspicious"
            elif r.verdict == "clean" and worst == "unknown":
                worst = "clean"
            if r.score is not None:
                score = max(score or 0, r.score)

        return EnrichmentResult(ioc=ioc, source="direct", verdict=worst, score=score, details=details)

    async def _virustotal(self, ioc: IOC) -> Optional[EnrichmentResult]:
        type_map = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}
        endpoint_type = type_map.get(ioc.type)
        if not endpoint_type:
            return None

        value = ioc.value
        if ioc.type == "url":
            import base64
            value = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/{endpoint_type}/{value}",
                    headers={"x-apikey": self._vt_key},
                )
                if resp.status_code == 404:
                    return EnrichmentResult(ioc=ioc, source="virustotal", verdict="unknown", details={"note": "not found"})
                resp.raise_for_status()
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) or 1
                score = int(malicious / total * 100)
                verdict = "malicious" if malicious > 0 else "clean"
                return EnrichmentResult(
                    ioc=ioc,
                    source="virustotal",
                    verdict=verdict,
                    score=score,
                    details={"stats": stats, "reputation": data.get("reputation")},
                )
        except Exception as exc:
            logger.error("VirusTotal lookup failed for %s: %s", ioc.value, exc)
            return None

    async def _abuseipdb(self, ioc: IOC) -> Optional[EnrichmentResult]:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self._abuse_key, "Accept": "application/json"},
                    params={"ipAddress": ioc.value, "maxAgeInDays": 90},
                )
                resp.raise_for_status()
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                verdict = "malicious" if score > 50 else ("suspicious" if score > 10 else "clean")
                return EnrichmentResult(
                    ioc=ioc,
                    source="abuseipdb",
                    verdict=verdict,
                    score=score,
                    details={
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "total_reports": data.get("totalReports"),
                        "last_reported": data.get("lastReportedAt"),
                    },
                )
        except Exception as exc:
            logger.error("AbuseIPDB lookup failed for %s: %s", ioc.value, exc)
            return None
