from __future__ import annotations
import logging

import httpx

from ..base import SOARConnector, WorkflowResult

logger = logging.getLogger(__name__)


class ShuffleConnector(SOARConnector):
    """
    Triggers Shuffle workflows via webhook.
    Each call POSTs a JSON payload to the configured webhook URL.
    The 'action' field tells your Shuffle workflow what to do.
    """

    def __init__(self, webhook_url: str):
        self._webhook_url = webhook_url

    @property
    def name(self) -> str:
        return "shuffle"

    async def is_available(self) -> bool:
        return bool(self._webhook_url)

    async def trigger(self, action: str, payload: dict) -> WorkflowResult:
        body = {"action": action, **payload}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(self._webhook_url, json=body)
                resp.raise_for_status()
                return WorkflowResult(
                    success=True,
                    workflow_name=f"shuffle:{action}",
                    response=resp.json() if resp.content else {},
                )
        except Exception as exc:
            logger.error("Shuffle trigger failed for action=%s: %s", action, exc)
            return WorkflowResult(
                success=False,
                workflow_name=f"shuffle:{action}",
                error=str(exc),
            )
