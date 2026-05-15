"""
Reads SIEM_BACKEND, CASE_BACKEND, ENRICHMENT_BACKEND, SOAR_BACKEND from
environment and returns the appropriate connector instances.
Returns None for any backend set to 'none' or missing required config.
"""
from __future__ import annotations
import logging
import os
from typing import Optional

from .base import SIEMConnector, CaseConnector, EnrichmentConnector, SOARConnector

logger = logging.getLogger(__name__)


def get_siem_connector() -> Optional[SIEMConnector]:
    backend = os.getenv("SIEM_BACKEND", "wazuh").lower().strip()

    if backend == "none":
        logger.info("SIEM_BACKEND=none — SIEM disabled")
        return None

    if backend == "wazuh":
        from .siem.wazuh import WazuhConnector
        url = os.getenv("WAZUH_URL", "")
        user = os.getenv("WAZUH_USER", "wazuh-wui")
        password = os.getenv("WAZUH_PASSWORD", "")
        if not url or not password:
            logger.warning("Wazuh connector: WAZUH_URL or WAZUH_PASSWORD not set — SIEM disabled")
            return None
        verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "false").lower() != "false"
        alerts_url = os.getenv("WAZUH_ALERTS_URL", "")
        return WazuhConnector(url=url, user=user, password=password,
                              verify_ssl=verify_ssl, alerts_url=alerts_url or None)

    if backend == "elastic":
        from .siem.elastic import ElasticConnector
        url = os.getenv("ELASTIC_URL", "")
        if not url:
            logger.warning("Elastic connector: ELASTIC_URL not set — SIEM disabled")
            return None
        return ElasticConnector(
            url=url,
            user=os.getenv("ELASTIC_USER", "elastic"),
            password=os.getenv("ELASTIC_PASSWORD", ""),
            index=os.getenv("ELASTIC_INDEX", ".siem-signals-*"),
            verify_ssl=os.getenv("ELASTIC_VERIFY_SSL", "false").lower() != "false",
        )

    logger.warning("Unknown SIEM_BACKEND=%s — SIEM disabled", backend)
    return None


def get_case_connector() -> Optional[CaseConnector]:
    backend = os.getenv("CASE_BACKEND", "thehive").lower().strip()

    if backend == "none":
        logger.info("CASE_BACKEND=none — case management disabled")
        return None

    if backend == "thehive":
        from .case_management.thehive import TheHiveConnector
        url = os.getenv("THEHIVE_URL", "")
        api_key = os.getenv("THEHIVE_API_KEY", "")
        if not url or not api_key:
            logger.warning("TheHive connector: THEHIVE_URL or THEHIVE_API_KEY not set — case management disabled")
            return None
        return TheHiveConnector(
            url=url,
            api_key=api_key,
            org=os.getenv("THEHIVE_ORG", "SOCLab"),
        )

    if backend == "jira":
        from .case_management.jira import JiraConnector
        url = os.getenv("JIRA_URL", "")
        if not url:
            logger.warning("Jira connector: JIRA_URL not set — case management disabled")
            return None
        return JiraConnector(
            url=url,
            user=os.getenv("JIRA_USER", ""),
            token=os.getenv("JIRA_TOKEN", ""),
            project=os.getenv("JIRA_PROJECT", "SOC"),
        )

    logger.warning("Unknown CASE_BACKEND=%s — case management disabled", backend)
    return None


def get_enrichment_connector() -> Optional[EnrichmentConnector]:
    backend = os.getenv("ENRICHMENT_BACKEND", "cortex").lower().strip()

    if backend == "none":
        logger.info("ENRICHMENT_BACKEND=none — enrichment disabled")
        return None

    if backend == "cortex":
        from .enrichment.cortex import CortexConnector
        url = os.getenv("CORTEX_URL", "")
        api_key = os.getenv("CORTEX_API_KEY", "")
        if not url or not api_key:
            logger.warning("Cortex connector: CORTEX_URL or CORTEX_API_KEY not set — enrichment disabled")
            return None
        return CortexConnector(url=url, api_key=api_key)

    if backend == "direct":
        from .enrichment.direct import DirectEnrichmentConnector
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if not vt_key and not abuse_key:
            logger.warning("Direct enrichment: no API keys set — enrichment disabled")
            return None
        return DirectEnrichmentConnector(vt_api_key=vt_key, abuseipdb_api_key=abuse_key)

    logger.warning("Unknown ENRICHMENT_BACKEND=%s — enrichment disabled", backend)
    return None


def get_soar_connector() -> Optional[SOARConnector]:
    backend = os.getenv("SOAR_BACKEND", "shuffle").lower().strip()

    if backend == "none":
        logger.info("SOAR_BACKEND=none — SOAR disabled")
        return None

    if backend == "shuffle":
        from .soar.shuffle import ShuffleConnector
        webhook_url = os.getenv("SHUFFLE_WEBHOOK_URL", "")
        if not webhook_url:
            logger.info("Shuffle connector: SHUFFLE_WEBHOOK_URL not set — SOAR disabled")
            return None
        return ShuffleConnector(webhook_url=webhook_url)

    if backend == "generic_webhook":
        from .soar.webhook import GenericWebhookConnector
        webhook_url = os.getenv("SOAR_WEBHOOK_URL", "")
        if not webhook_url:
            logger.warning("Generic webhook: SOAR_WEBHOOK_URL not set — SOAR disabled")
            return None
        return GenericWebhookConnector(webhook_url=webhook_url)

    logger.warning("Unknown SOAR_BACKEND=%s — SOAR disabled", backend)
    return None
