"""
Ollama API wrapper. Handles:
  - Structured (non-streaming) completion for background loop tasks
  - Streaming completion for interactive WebUI responses
  - Tool/function calling loop for interactive agentic tasks
"""
from __future__ import annotations
import json
import logging
from typing import Any, AsyncIterator, Optional

import httpx

logger = logging.getLogger(__name__)


class LLMClient:
    def __init__(self, base_url: str, model: str, keep_alive: int = 3600):
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._keep_alive = keep_alive

    # ------------------------------------------------------------------
    # Structured completion — for background loop (returns parsed JSON)
    # ------------------------------------------------------------------

    async def complete(self, system: str, user: str, temperature: float = 0.1) -> str:
        """Single-turn non-streaming completion. Returns assistant content string."""
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        body = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_ctx": 8192},
            "keep_alive": self._keep_alive,
        }
        async with httpx.AsyncClient(timeout=300) as client:
            resp = await client.post(f"{self._base_url}/api/chat", json=body)
            resp.raise_for_status()
            return resp.json()["message"]["content"]

    async def complete_json(self, system: str, user: str) -> dict:
        """Like complete() but parses the response as JSON. Raises on parse failure."""
        content = await self.complete(system, user)
        # Strip markdown code fences if present
        content = content.strip()
        if content.startswith("```"):
            content = content.split("```", 2)[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.rstrip("`").strip()
        return json.loads(content)

    # ------------------------------------------------------------------
    # Streaming completion — for interactive WebUI responses
    # ------------------------------------------------------------------

    async def stream(
        self,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
    ) -> AsyncIterator[str]:
        """
        Streams token-by-token. Yields content strings.
        If Ollama returns a tool_call, yields a special sentinel so the caller
        can detect it and run the tool.
        """
        body: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "stream": True,
            "options": {"temperature": 0.1, "num_ctx": 8192},
            "keep_alive": self._keep_alive,
        }
        if tools:
            body["tools"] = tools

        async with httpx.AsyncClient(timeout=300) as client:
            async with client.stream("POST", f"{self._base_url}/api/chat", json=body) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    msg = chunk.get("message", {})
                    content = msg.get("content", "")
                    if content:
                        yield content
                    if chunk.get("done"):
                        break

    # ------------------------------------------------------------------
    # Agentic loop — non-streaming, executes tool calls until final answer
    # ------------------------------------------------------------------

    async def agentic_complete(
        self,
        messages: list[dict],
        tools: list[dict],
        tool_executor,          # async callable(name: str, args: dict) -> str
        max_iterations: int = 10,
    ) -> str:
        """
        Runs the full tool-calling loop:
          LLM → tool_calls → execute → LLM → ... → final response
        Returns the final text content.
        """
        current_messages = list(messages)

        for iteration in range(max_iterations):
            body = {
                "model": self._model,
                "messages": current_messages,
                "tools": tools,
                "stream": False,
                "options": {"temperature": 0.1, "num_ctx": 8192},
                "keep_alive": self._keep_alive,
            }
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(f"{self._base_url}/api/chat", json=body)
                resp.raise_for_status()
                data = resp.json()

            msg = data.get("message", {})
            tool_calls = msg.get("tool_calls", [])
            content = msg.get("content", "")

            if not tool_calls:
                return content

            # Append assistant's tool-call turn
            current_messages.append({"role": "assistant", "content": content, "tool_calls": tool_calls})

            # Execute each tool call and append results
            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                args = fn.get("arguments", {})
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                try:
                    result = await tool_executor(name, args)
                except Exception as exc:
                    result = f"Tool {name} failed: {exc}"
                    logger.error("Tool %s failed: %s", name, exc)

                current_messages.append({
                    "role": "tool",
                    "content": str(result),
                    "name": name,
                })

        logger.warning("Agentic loop hit max_iterations=%d", max_iterations)
        return "I reached the maximum number of reasoning steps. Please try a more specific question."

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False
