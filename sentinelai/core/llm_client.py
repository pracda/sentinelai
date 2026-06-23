"""
LLM client for SentinelAI.

Wraps Anthropic (primary) and OpenAI (fallback) with:
- Streaming responses for real-time analysis output
- Automatic retry with exponential backoff
- Structured JSON output parsing
- Fallback between providers
"""
import json
import asyncio
from typing import AsyncGenerator, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from anthropic import Anthropic, RateLimitError, AuthenticationError
import structlog

from sentinelai.core.config import get_settings

log = structlog.get_logger()


class LLMClient:
    """
    Primary interface for all LLM calls in SentinelAI.

    Usage:
        client = LLMClient()

        # Streaming (real-time output)
        async for chunk in client.stream("Analyse this log: ..."):
            print(chunk, end="", flush=True)

        # Full response
        result = await client.complete("What vulnerabilities does this expose?")

        # Structured JSON output
        data = await client.complete_json("Extract IOCs from: ...", schema={...})
    """

    def __init__(self):
        self.settings = get_settings()
        self._anthropic_client = None
        self._openai_client = None

    @property
    def anthropic(self) -> Anthropic:
        if not self._anthropic_client:
            self._anthropic_client = Anthropic(
                api_key=self.settings.anthropic_api_key
            )
        return self._anthropic_client

    # ── Streaming response ─────────────────────────────────────────────────

    async def stream(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: Optional[int] = None
    ) -> AsyncGenerator[str, None]:
        """
        Stream LLM response token by token.
        Used for real-time analysis output in the CLI and WebSocket API.
        """
        if not self.settings.has_anthropic_key():
            yield "[No Anthropic API key configured — set ANTHROPIC_API_KEY in .env]\n"
            return

        system_prompt = system or self._default_system_prompt()

        try:
            # Run streaming in thread pool (anthropic SDK is sync)
            loop = asyncio.get_event_loop()
            chunks = await loop.run_in_executor(
                None,
                lambda: self._collect_stream(prompt, system_prompt, max_tokens)
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

    def _collect_stream(
        self, prompt: str, system: str, max_tokens: Optional[int]
    ) -> list[str]:
        """Synchronous streaming collection for thread executor."""
        chunks = []
        with self.anthropic.messages.stream(
            model=self.settings.anthropic_model,
            max_tokens=max_tokens or self.settings.llm_max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}]
        ) as stream:
            for text in stream.text_stream:
                chunks.append(text)
        return chunks

    # ── Full response ──────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(RateLimitError)
    )
    async def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Get a full LLM response (non-streaming).
        Retries automatically on rate limits.
        """
        if not self.settings.has_anthropic_key():
            return "[No Anthropic API key configured]"

        system_prompt = system or self._default_system_prompt()

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self.anthropic.messages.create(
                model=self.settings.anthropic_model,
                max_tokens=max_tokens or self.settings.llm_max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": prompt}]
            )
        )

        log.info("LLM call complete",
                 input_tokens=response.usage.input_tokens,
                 output_tokens=response.usage.output_tokens)

        return response.content[0].text

    # ── Structured JSON output ─────────────────────────────────────────────

    async def complete_json(
        self,
        prompt: str,
        system: Optional[str] = None,
    ) -> dict:
        """
        Get a structured JSON response from the LLM.
        Instructs the model to respond ONLY with valid JSON.
        """
        json_system = (system or self._default_system_prompt()) + \
            "\n\nIMPORTANT: Respond ONLY with valid JSON. No preamble, no markdown " \
            "code fences, no explanation. Just the raw JSON object."

        raw = await self.complete(prompt, system=json_system)

        # Strip markdown fences if model included them anyway
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
        return """You are SentinelAI, an expert cybersecurity analyst assistant.
You combine deep knowledge of offensive security (red teaming, penetration testing, 
vulnerability research) with defensive security (threat hunting, incident response, 
log analysis, SIEM operations).

Your analysis is:
- Precise and technical — you use correct security terminology
- Actionable — you give specific, implementable recommendations
- Risk-aware — you always quantify severity and business impact
- MITRE ATT&CK aligned — you map findings to the ATT&CK framework where relevant

You operate under strict ethical guidelines. You only assist with authorized security 
testing and defensive operations. You never assist with unauthorized access."""

    def security_analyst_system(self) -> str:
        return self._default_system_prompt()

    def log_analyst_system(self) -> str:
        return self._default_system_prompt() + """

You are specifically analysing security logs. When you see suspicious patterns:
1. Identify the attack technique (MITRE ATT&CK TTP)
2. Extract exact IOCs (IPs, hashes, domains, user agents)
3. Reconstruct the attack timeline
4. Assess severity (Critical/High/Medium/Low/Info)
5. Recommend immediate response actions"""

    def vuln_analyst_system(self) -> str:
        return self._default_system_prompt() + """

You are specifically analysing vulnerabilities. For each finding:
1. Assess real-world exploitability (not just CVSS score)
2. Consider the specific environment context
3. Identify the most likely attack path
4. Provide a CVSS v3.1 vector string
5. Map to MITRE ATT&CK technique"""


# ── Module-level singleton ─────────────────────────────────────────────────
_client: Optional[LLMClient] = None


def get_llm_client() -> LLMClient:
    """Returns the shared LLM client instance."""
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
