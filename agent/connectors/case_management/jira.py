"""
Jira Service Management connector stub.
Implement this if your stack uses Jira instead of TheHive.

To activate: set CASE_BACKEND=jira in your .env and fill in the JIRA_* variables.
"""
from __future__ import annotations
import logging
from ..base import CaseConnector, Case, CaseUpdate

logger = logging.getLogger(__name__)


class JiraConnector(CaseConnector):
    def __init__(self, url: str, user: str, token: str, project: str):
        self._url = url
        self._user = user
        self._token = token
        self._project = project

    @property
    def name(self) -> str:
        return "jira"

    async def is_available(self) -> bool:
        logger.warning("JiraConnector is a stub — implement connectors/case_management/jira.py")
        return False

    async def get_open_cases(self) -> list[Case]:
        raise NotImplementedError

    async def get_case(self, case_id: str) -> Case:
        raise NotImplementedError

    async def add_note(self, case_id: str, note: str) -> None:
        raise NotImplementedError

    async def update_case(self, case_id: str, update: CaseUpdate) -> None:
        raise NotImplementedError

    async def close_case(self, case_id: str, resolution: str) -> None:
        raise NotImplementedError
