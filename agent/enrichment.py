"""
IOC enrichment orchestrator.
Takes a list of IOCs, deduplicates them, submits to the enrichment connector,
and returns results with a human-readable summary.
"""
from __future__ import annotations
import asyncio
import logging
from typing import Optional

from connectors.base import EnrichmentConnector, EnrichmentResult, IOC

logger = logging.getLogger(__name__)

# Max concurrent enrichment requests to avoid hammering the enrichment API
_MAX_CONCURRENT = 3


async def enrich_all(
    iocs: list[IOC],
    connector: EnrichmentConnector,
) -> list[EnrichmentResult]:
    if not iocs:
        return []

    # Deduplicate by (type, value)
    seen: set[tuple[str, str]] = set()
    unique_iocs: list[IOC] = []
    for ioc in iocs:
        key = (ioc.type, ioc.value.lower())
        if key not in seen:
            seen.add(key)
            unique_iocs.append(ioc)

    semaphore = asyncio.Semaphore(_MAX_CONCURRENT)

    async def enrich_one(ioc: IOC) -> Optional[EnrichmentResult]:
        async with semaphore:
            try:
                return await connector.enrich(ioc)
            except Exception as exc:
                logger.error("Enrichment failed for %s %s: %s", ioc.type, ioc.value, exc)
                return EnrichmentResult(
                    ioc=ioc,
                    source=connector.name,
                    verdict="unknown",
                    details={"error": str(exc)},
                )

    results = await asyncio.gather(*[enrich_one(ioc) for ioc in unique_iocs])
    return [r for r in results if r is not None]


def format_enrichment_summary(results: list[EnrichmentResult]) -> str:
    """Renders enrichment results as a Markdown table for case notes."""
    if not results:
        return "_No IOCs were enriched._"

    lines = [
        "| IOC | Type | Verdict | Score | Source | Details |",
        "|-----|------|---------|-------|--------|---------|",
    ]
    for r in results:
        verdict_emoji = {"malicious": "🔴", "suspicious": "🟡", "clean": "🟢"}.get(r.verdict, "⚪")
        score_str = f"{r.score}%" if r.score is not None else "-"
        details_short = "; ".join(
            f"{k}: {str(v)[:40]}" for k, v in r.details.items() if k != "error"
        )[:80]
        lines.append(
            f"| `{r.ioc.value}` | {r.ioc.type} | {verdict_emoji} {r.verdict} | {score_str} | {r.source} | {details_short} |"
        )
    return "\n".join(lines)
