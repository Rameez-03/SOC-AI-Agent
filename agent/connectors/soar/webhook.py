from __future__ import annotations
import logging

import httpx

from ..base import SOARConnector, WorkflowResult

logger = logging.getLogger(__name__)


class GenericWebhookConnector(SOARConnector):
    """
    Generic SOAR connector for any platform that accepts a JSON POST to a webhook.
    Compatible with n8n, XSOAR, Tines, Make.com, etc.
    Set SOAR_BACKEND=generic_webhook and SOAR_WEBHOOK_URL=<your webhook URL>.
    """

    def __init__(self, webhook_url: str):
        self._webhook_url = webhook_url

    @property
    def name(self) -> str:
        return "generic_webhook"

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
                    workflow_name=f"webhook:{action}",
                    response=resp.json() if resp.content else {},
                )
        except Exception as exc:
            logger.error("Generic webhook failed for action=%s: %s", action, exc)
            return WorkflowResult(
                success=False,
                workflow_name=f"webhook:{action}",
                error=str(exc),
            )
