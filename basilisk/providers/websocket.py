"""
Basilisk WebSocket Adapter — for WebSocket-based AI endpoints.

Pairs naturally with WSHawk for WebSocket AI application red teaming.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, AsyncIterator

import websockets

from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse

logger = logging.getLogger("basilisk.providers.websocket")


class WebSocketAdapter(ProviderAdapter):
    """
    Provider adapter for WebSocket-based AI services.

    Many real-time AI applications (chatbots, voice assistants, game AI)
    communicate over WebSocket rather than REST. This adapter handles
    the stateful, bidirectional connection.
    """

    def __init__(
        self,
        ws_url: str,
        auth_header: str = "",
        custom_headers: dict[str, str] | None = None,
        message_format: str = "json",  # json or plain
        response_content_path: str = "content",
        send_format_template: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._ws_url = ws_url
        self._auth_header = auth_header
        self._custom_headers = custom_headers or {}
        self._message_format = message_format
        self._response_content_path = response_content_path
        self._send_template = send_format_template or {}
        self._timeout = timeout
        self._ws: Any = None

    @property
    def name(self) -> str:
        return "websocket"

    async def _connect(self) -> Any:
        if self._ws is None or self._ws.closed:
            headers = {**self._custom_headers}
            if self._auth_header:
                headers["Authorization"] = self._auth_header
            self._ws = await websockets.connect(
                self._ws_url,
                additional_headers=headers,
                open_timeout=self._timeout,
                close_timeout=self._timeout,
            )
        return self._ws

    def _format_outgoing(self, messages: list[ProviderMessage], **kwargs: Any) -> str:
        if self._message_format == "plain":
            return messages[-1].content if messages else ""
        payload = {
            **self._send_template,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            **kwargs,
        }
        return json.dumps(payload)

    def _extract_content(self, raw: str) -> str:
        if self._message_format == "plain":
            return raw
        try:
            data = json.loads(raw)
            parts = self._response_content_path.split(".")
            current: Any = data
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list):
                    try:
                        current = current[int(part)]
                    except (ValueError, IndexError):
                        return raw
                else:
                    return raw
                if current is None:
                    return raw
            return str(current)
        except json.JSONDecodeError:
            return raw

    async def send(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> ProviderResponse:
        ws = await self._connect()
        outgoing = self._format_outgoing(messages, model=model, temperature=temperature, max_tokens=max_tokens, **kwargs)

        start = time.monotonic()
        try:
            await ws.send(outgoing)
            raw_response = await ws.recv()
            latency = (time.monotonic() - start) * 1000
            content = self._extract_content(raw_response)

            raw_dict: dict[str, Any] = {}
            try:
                raw_dict = json.loads(raw_response)
            except (json.JSONDecodeError, TypeError):
                raw_dict = {"raw": raw_response}

            return ProviderResponse(
                content=content,
                role="assistant",
                model=model,
                latency_ms=latency,
                raw_response=raw_dict,
            )
        except Exception as e:
            latency = (time.monotonic() - start) * 1000
            return ProviderResponse(content="", latency_ms=latency, error=str(e))

    async def send_streaming(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        ws = await self._connect()
        outgoing = self._format_outgoing(messages, model=model, temperature=temperature, max_tokens=max_tokens, stream=True, **kwargs)

        try:
            await ws.send(outgoing)
            async for raw in ws:
                content = self._extract_content(raw)
                if content:
                    yield content
                # Check for stream end signals
                try:
                    data = json.loads(raw)
                    if data.get("done") or data.get("finish_reason"):
                        break
                except (json.JSONDecodeError, TypeError):
                    pass
        except Exception as e:
            logger.warning(f"Streaming error: {e}")
            return

    async def close(self) -> None:
        """Close the WebSocket connection."""
        if self._ws and not self._ws.closed:
            await self._ws.close()
            self._ws = None
