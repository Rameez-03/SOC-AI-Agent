"""
Elastic SIEM connector stub.
Implement this if your stack uses Elastic Security instead of Wazuh.

To activate: set SIEM_BACKEND=elastic in your .env and fill in the
ELASTIC_* variables.
"""
from __future__ import annotations
import logging
from ..base import SIEMConnector, Alert, LogEntry, Case

logger = logging.getLogger(__name__)


class ElasticConnector(SIEMConnector):
    def __init__(self, url: str, user: str, password: str, index: str, verify_ssl: bool = False):
        self._url = url
        self._user = user
        self._password = password
        self._index = index
        self._verify_ssl = verify_ssl

    @property
    def name(self) -> str:
        return "elastic"

    async def is_available(self) -> bool:
        logger.warning("ElasticConnector is a stub — implement connectors/siem/elastic.py")
        return False

    async def get_alerts(self, limit: int = 100, min_level: int = 3, hours_back: int = 24) -> list[Alert]:
        raise NotImplementedError("ElasticConnector.get_alerts not implemented")

    async def get_logs_for_case(self, case: Case, hours_back: int = 24) -> list[LogEntry]:
        raise NotImplementedError("ElasticConnector.get_logs_for_case not implemented")
