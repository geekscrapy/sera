"""Shared raw `httpx` async HTTP engine with proxy, custom CA bundle, and `429 Retry-After` backoff."""

from __future__ import annotations

import asyncio
import email.utils
import random
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import httpx

from sera.config import NetworkConfig


RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class UpstreamApiError(RuntimeError):
    """Raised when an upstream API returns a non-retryable HTTP error or exhausts retries."""

    def __init__(self, status_code: int, message: str, body: str = "") -> None:
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.body = body


def parse_retry_after(header_value: str | None, fallback_seconds: float) -> float:
    """Parse HTTP `Retry-After` (delta-seconds or RFC 7231 HTTP-date) with safe bounds."""
    if not header_value:
        return fallback_seconds
    cleaned = header_value.strip()
    try:
        secs = float(cleaned)
        return max(0.05, min(secs, 300.0))
    except ValueError:
        pass
    try:
        parsed_dt = email.utils.parsedate_to_datetime(cleaned)
        if parsed_dt.tzinfo is None:
            parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
        delta = (parsed_dt - datetime.now(timezone.utc)).total_seconds()
        return max(0.05, min(delta, 300.0))
    except Exception:
        return fallback_seconds


class SeraHttpClient:
    """Raw JSON HTTP client preserving wire fidelity with proxy and retry handling."""

    def __init__(
        self,
        network: NetworkConfig,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.network = network
        self._sleep = sleep_fn
        self._client: httpx.AsyncClient | None = None

    def _build_client(self) -> httpx.AsyncClient:
        verify: bool | str = self.network.verify_tls
        if self.network.ca_bundle:
            verify = self.network.ca_bundle
        proxy = self.network.proxy_url or None
        return httpx.AsyncClient(
            proxy=proxy,
            verify=verify,
            timeout=httpx.Timeout(self.network.timeout_seconds),
            follow_redirects=False,
        )

    async def __aenter__(self) -> SeraHttpClient:
        self._client = self._build_client()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        refresh_headers_on_401: Callable[[], Awaitable[dict[str, str]]] | None = None,
    ) -> dict[str, Any]:
        """Perform an HTTP request and parse the response as a raw JSON object (`dict`)."""
        if self._client is None:
            self._client = self._build_client()

        req_headers = dict(headers or {})
        refreshed_401 = False
        max_attempts = max(1, self.network.max_retries + 1)

        for attempt in range(max_attempts):
            try:
                resp = await self._client.request(
                    method=method,
                    url=url,
                    headers=req_headers,
                    params=params,
                    json=json_body,
                )
            except httpx.TransportError as exc:
                if attempt + 1 >= max_attempts:
                    raise UpstreamApiError(0, f"Transport error contacting {url}: {exc}") from exc
                backoff = min(30.0, (0.5 * (2**attempt)) + random.uniform(0.0, 0.25))
                await self._sleep(backoff)
                continue

            if resp.status_code == 401 and refresh_headers_on_401 and not refreshed_401:
                refreshed_401 = True
                req_headers.update(await refresh_headers_on_401())
                continue

            if resp.status_code in RETRYABLE_STATUS_CODES and attempt + 1 < max_attempts:
                fallback = min(60.0, (0.5 * (2**attempt)) + random.uniform(0.0, 0.25))
                wait_s = parse_retry_after(resp.headers.get("Retry-After"), fallback)
                await self._sleep(wait_s)
                continue

            if resp.status_code >= 400:
                body_preview = resp.text[:1000]
                raise UpstreamApiError(
                    resp.status_code,
                    f"Request {method} {url} failed: {body_preview}",
                    body=resp.text,
                )

            if not resp.content:
                return {}
            data = resp.json()
            if not isinstance(data, dict):
                return {"value": data}
            return data

        raise UpstreamApiError(503, f"Exhausted {max_attempts} attempts for {method} {url}")
