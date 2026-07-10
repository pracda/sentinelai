"""
LLM client for SentinelAI.

Routing priority:
  1. LLM API Gateway  — when LLM_GATEWAY_ENABLED=true and LLM_GATEWAY_API_KEY is set.
     The key is generated from the gateway admin panel (Org → Keys → Generate).
     Sent as X-Api-Key header — no auth flow, no JWT, just one env var.
       complete() → POST /api/v1/chat        (full response)
       stream()   → POST /api/v1/chat/stream (real SSE, token by token)
  2. Direct Anthropic — automatic fallback if the gateway is disabled or unreachable.

Public interface (identical regardless of routing):
    client = get_llm_client()
    text   = await client.complete(prompt, system=..., max_tokens=...)
    async for chunk in client.stream(prompt): ...
    data   = await client.complete_json(prompt)
"""
import json
import asyncio
from typing import AsyncGenerator, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
import structlog

from sentinelai.core.config import get_settings

log = structlog.get_logger()

# ── Runtime gateway config ─────────────────────────────────────────────────
# Loaded from DB on startup and updated immediately when admin saves via UI.
# None = fall back to env vars (LLM_GATEWAY_* settings).

_gateway_override: Optional[dict] = None


def set_gateway_config(enabled: bool, url: str, api_key: str) -> None:
    """Apply gateway config from DB. Called on startup and on admin save."""
    global _gateway_override
    _gateway_override = {"enabled": enabled, "url": url, "api_key": api_key}
    log.info("LLM gateway config applied", enabled=enabled, url=url,
             key_prefix=api_key[:12] + "..." if api_key else "(none)")


def clear_gateway_config() -> None:
    """Remove DB override — gateway settings fall back to env vars."""
    global _gateway_override
    _gateway_override = None


class LLMClient:
    """
    Primary interface for all LLM calls in SentinelAI.

    When LLM_GATEWAY_ENABLED=true, every call goes through the gateway using
    the API key from LLM_GATEWAY_API_KEY — one env var, no auth flow.
    Falls back to direct Anthropic on any gateway error.
    """

    def __init__(self):
        self.settings = get_settings()
        self._anthropic_client = None

    # ── Routing helpers ────────────────────────────────────────────────────

    @property
    def _use_gateway(self) -> bool:
        if _gateway_override is not None:
            return bool(_gateway_override.get("enabled") and
                        _gateway_override.get("url") and
                        _gateway_override.get("api_key"))
        s = self.settings
        return bool(s.llm_gateway_enabled and s.llm_gateway_url and s.llm_gateway_api_key)

    def _gateway_headers(self) -> dict:
        key = (_gateway_override["api_key"] if _gateway_override
               else self.settings.llm_gateway_api_key)
        return {"X-Api-Key": key}

    def _gateway_base_url(self) -> str:
        return ((_gateway_override["url"] if _gateway_override
                 else self.settings.llm_gateway_url)).rstrip("/")

    def _gateway_body(self, user_message: str, system_prompt: Optional[str]) -> dict:
        body: dict = {
            "provider": "ANTHROPIC",
            "model": self.settings.anthropic_model,
            "userMessage": user_message[:8000],
        }
        if system_prompt:
            body["systemPrompt"] = system_prompt[:2000]
        return body

    async def _gateway_chat(
        self,
        user_message: str,
        system_prompt: Optional[str] = None,
    ) -> str:
        """POST /api/v1/chat — full response via org API key."""
        url = self._gateway_base_url() + "/api/v1/chat"
        async with httpx.AsyncClient(timeout=self.settings.llm_timeout_seconds) as http:
            resp = await http.post(
                url,
                json=self._gateway_body(user_message, system_prompt),
                headers=self._gateway_headers(),
            )
            resp.raise_for_status()
        data = resp.json()
        log.info("LLM gateway call complete",
                 request_id=data.get("requestId"),
                 total_tokens=data.get("usage", {}).get("totalTokens"),
                 latency_ms=data.get("latencyMs"))
        return data["content"]

    async def _gateway_stream(
        self,
        user_message: str,
        system_prompt: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """POST /api/v1/chat/stream — real SSE streaming via org API key."""
        url = self._gateway_base_url() + "/api/v1/chat/stream"
        async with httpx.AsyncClient(timeout=self.settings.llm_timeout_seconds) as http:
            async with http.stream(
                "POST",
                url,
                json=self._gateway_body(user_message, system_prompt),
                headers={**self._gateway_headers(), "Accept": "text/event-stream"},
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    chunk = line[5:].strip()
                    if chunk and chunk != "[DONE]":
                        yield chunk

    @property
    def _anthropic(self):
        if self._anthropic_client is None:
            from anthropic import Anthropic
            self._anthropic_client = Anthropic(api_key=self.settings.anthropic_api_key)
        return self._anthropic_client

    # ── Streaming response ─────────────────────────────────────────────────

    async def stream(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
    ) -> AsyncGenerator[str, None]:
        """Stream LLM response token by token. Gateway SSE first; direct Anthropic on fallback."""
        if self._use_gateway:
            try:
                async for chunk in self._gateway_stream(
                    prompt,
                    system_prompt=system or self._default_system_prompt(),
                ):
                    yield chunk
                return
            except Exception as e:
                log.warning("Gateway stream failed, falling back to Anthropic", error=str(e))

        async for chunk in self._stream_anthropic(prompt, system, max_tokens):
            yield chunk

    async def _stream_anthropic(
        self, prompt: str, system: Optional[str], max_tokens: Optional[int]
    ) -> AsyncGenerator[str, None]:
        from anthropic import AuthenticationError, RateLimitError

        if not self.settings.has_anthropic_key():
            yield "[No Anthropic API key configured — set ANTHROPIC_API_KEY in .env]\n"
            return

        system_prompt = system or self._default_system_prompt()
        try:
            loop = asyncio.get_event_loop()
            chunks = await loop.run_in_executor(
                None,
                lambda: self._collect_stream_sync(prompt, system_prompt, max_tokens),
            )
            for chunk in chunks:
                yield chunk
        except AuthenticationError:
            yield "[Authentication error — check your ANTHROPIC_API_KEY]\n"
        except RateLimitError:
            yield "[Rate limit exceeded — please wait and retry]\n"
        except Exception as e:
            log.error("LLM stream error", error=str(e))
            yield f"[LLM error: {str(e)}]\n"

    def _collect_stream_sync(
        self, prompt: str, system: str, max_tokens: Optional[int]
    ) -> list[str]:
        chunks: list[str] = []
        with self._anthropic.messages.stream(
            model=self.settings.anthropic_model,
            max_tokens=max_tokens or self.settings.llm_max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            for text in stream.text_stream:
                chunks.append(text)
        return chunks

    # ── Full response ──────────────────────────────────────────────────────

    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Full LLM response. Gateway first; direct Anthropic on fallback."""
        if self._use_gateway:
            try:
                return await self._gateway_chat(
                    prompt,
                    system_prompt=system or self._default_system_prompt(),
                )
            except Exception as e:
                log.warning("Gateway complete failed, falling back to Anthropic", error=str(e))

        return await self._complete_anthropic(prompt, system, max_tokens)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def _complete_anthropic(
        self,
        prompt: str,
        system: Optional[str],
        max_tokens: Optional[int],
    ) -> str:
        if not self.settings.has_anthropic_key():
            return "[No Anthropic API key configured]"

        system_prompt = system or self._default_system_prompt()
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._anthropic.messages.create(
                model=self.settings.anthropic_model,
                max_tokens=max_tokens or self.settings.llm_max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}],
            ),
        )
        log.info("LLM direct call complete",
                 input_tokens=response.usage.input_tokens,
                 output_tokens=response.usage.output_tokens)
        return response.content[0].text

    # ── Structured JSON output ─────────────────────────────────────────────

    async def complete_json(self, prompt: str, system: Optional[str] = None) -> dict:
        """Get a structured JSON response from the LLM."""
        json_system = (system or self._default_system_prompt()) + (
            "\n\nIMPORTANT: Respond ONLY with valid JSON. "
            "No preamble, no markdown code fences, no explanation. "
            "Just the raw JSON object."
        )
        raw = await self.complete(prompt, system=json_system)
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            log.error("JSON parse error from LLM", raw=raw[:200], error=str(e))
            return {"error": "Failed to parse LLM JSON response", "raw": raw}

    # ── System prompts ─────────────────────────────────────────────────────

    def _default_system_prompt(self) -> str:
        return (
            "You are SentinelAI, an expert cybersecurity analyst assistant.\n"
            "You combine deep knowledge of offensive security (red teaming, penetration "
            "testing, vulnerability research) with defensive security (threat hunting, "
            "incident response, log analysis, SIEM operations).\n\n"
            "Your analysis is:\n"
            "- Precise and technical — you use correct security terminology\n"
            "- Actionable — you give specific, implementable recommendations\n"
            "- Risk-aware — you always quantify severity and business impact\n"
            "- MITRE ATT&CK aligned — you map findings to the ATT&CK framework where relevant\n\n"
            "You operate under strict ethical guidelines. You only assist with authorized "
            "security testing and defensive operations. You never assist with unauthorized access."
        )

    def security_analyst_system(self) -> str:
        return self._default_system_prompt()

    def log_analyst_system(self) -> str:
        return self._default_system_prompt() + (
            "\n\nYou are specifically analysing security logs. When you see suspicious patterns:\n"
            "1. Identify the attack technique (MITRE ATT&CK TTP)\n"
            "2. Extract exact IOCs (IPs, hashes, domains, user agents)\n"
            "3. Reconstruct the attack timeline\n"
            "4. Assess severity (Critical/High/Medium/Low/Info)\n"
            "5. Recommend immediate response actions"
        )

    def vuln_analyst_system(self) -> str:
        return self._default_system_prompt() + (
            "\n\nYou are specifically analysing vulnerabilities. For each finding:\n"
            "1. Assess real-world exploitability (not just CVSS score)\n"
            "2. Consider the specific environment context\n"
            "3. Identify the most likely attack path\n"
            "4. Provide a CVSS v3.1 vector string\n"
            "5. Map to MITRE ATT&CK technique"
        )


# ── Module-level singleton ─────────────────────────────────────────────────

_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    """Returns the shared LLM client instance."""
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
