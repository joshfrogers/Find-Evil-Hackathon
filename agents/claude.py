"""Interface to Claude for forensic reasoning, over the Anthropic Messages API.

Calls the Messages API directly with the Python standard library (``http.client``
+ ``ssl``) — no third-party SDK, no ``pip`` — so it runs on a stdlib-only SIFT
workstation. Each call is a single short-lived HTTPS request (~1-2s).

The Messages API is authenticated by ``ANTHROPIC_API_KEY`` and reached at
``api.anthropic.com`` by default; ``AGENTIC_SIFT_API_HOST`` can override the host
to route through a self-hosted proxy. No deployment specifics are baked into the
source.

The LLM decides what to investigate and how to interpret results; our Python
code controls what can be executed and what tools are available.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import ssl
import sys
import time
from typing import Optional

_DEBUG_LOG = os.environ.get("AGENTIC_SIFT_CLAUDE_DEBUG_LOG")


def _debug(msg: str) -> None:
    if _DEBUG_LOG:
        try:
            with open(_DEBUG_LOG, "a") as f:
                f.write(msg.rstrip() + "\n")
        except OSError:
            pass
    print(f"[claude-debug] {msg}", file=sys.stderr, flush=True)


class ClaudeError(Exception):
    """Base exception for Claude failures."""


class ClaudeTimeoutError(ClaudeError):
    """Claude call timed out."""


class ClaudeNotFoundError(ClaudeError):
    """No Claude transport configured (ANTHROPIC_API_KEY is not set)."""


# Transient gateway/network failures (5xx, connection resets, timeouts) are
# retried a few times before giving up.
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF_S = 3

# Model + token budget. Overridable by env so the public repo / a different
# deployment can swap models without code changes.
_MODEL = os.environ.get("AGENTIC_SIFT_MODEL", "claude-opus-4-8")
_MAX_TOKENS = int(os.environ.get("AGENTIC_SIFT_MAX_TOKENS", "8192"))
_ANTHROPIC_VERSION = "2023-06-01"

# Default to the public Anthropic API. Configuration is purely environmental
# (no endpoint or credential is baked into the source):
#   ANTHROPIC_API_KEY      - Anthropic API key (required)
#   AGENTIC_SIFT_API_HOST  - override host to route through a self-hosted proxy (optional)
_DEFAULT_API_HOST = "api.anthropic.com"

# Only the SSL context is cached (building one is the expensive part, and it is a
# read-only object safe to share across calls/threads — a fresh HTTPSConnection
# per call is created from it). The host/headers/API key are re-read from the
# environment on every call so a changed ANTHROPIC_API_KEY / AGENTIC_SIFT_API_HOST
# takes effect immediately rather than being pinned at first use.
_SSL_CONTEXT: Optional[ssl.SSLContext] = None


def _request_target() -> tuple:
    """Resolve (host, base_headers, ssl_context) for the Messages API.

    Authenticated by ``ANTHROPIC_API_KEY`` against ``api.anthropic.com`` (or
    ``AGENTIC_SIFT_API_HOST`` if set). Re-resolved each call (only the SSL context
    is cached).
    """
    global _SSL_CONTEXT

    # NOTE: no ``anthropic-beta: prompt-caching-*`` header. Prompt caching is GA
    # — ``cache_control`` blocks are honored without it.
    headers = {
        "content-type": "application/json",
        "anthropic-version": _ANTHROPIC_VERSION,
    }
    host = os.environ.get("AGENTIC_SIFT_API_HOST", _DEFAULT_API_HOST)

    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise ClaudeNotFoundError(
            "No Claude credentials: set ANTHROPIC_API_KEY for the Anthropic "
            "Messages API."
        )
    headers["x-api-key"] = key

    if _SSL_CONTEXT is None:
        _SSL_CONTEXT = ssl.create_default_context()
    return (host, headers, _SSL_CONTEXT)


def _int_env(name: str, default: int) -> int:
    """Read an int from the environment (at call time), else ``default``."""
    try:
        return int(os.environ.get(name) or default)
    except (TypeError, ValueError):
        return default


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse a Retry-After header (delta-seconds form) into seconds, or None."""
    if not value:
        return None
    try:
        return max(0.0, float(value.strip()))
    except (TypeError, ValueError):
        return None


def _post_messages(
    prompt: str, system_prompt: "str | list", timeout: int
) -> str:
    """One Messages-API request; return the concatenated text, or raise.

    ``system_prompt`` may be a plain string (sent as the ``system`` field
    verbatim) or a list of Anthropic content blocks (sent through unchanged, so a
    block carrying ``cache_control: {"type": "ephemeral"}`` enables prompt
    caching of the stable preamble). Empty string / empty list omits ``system``.

    Raises ClaudeTimeoutError on timeout and ClaudeError on a non-200 status or
    transport/parse failure (both retried by ``call_claude``).
    """
    host, base_headers, ctx = _request_target()
    payload: dict = {
        "model": _MODEL,
        "max_tokens": _MAX_TOKENS,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system_prompt:
        payload["system"] = system_prompt
    body = json.dumps(payload)

    conn = http.client.HTTPSConnection(host, 443, context=ctx, timeout=timeout)
    try:
        conn.request("POST", "/v1/messages", body=body, headers=base_headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        status = resp.status
        retry_after = resp.getheader("retry-after")
    except (socket.timeout, TimeoutError) as e:
        raise ClaudeTimeoutError(f"Claude request timed out after {timeout}s") from e
    except OSError as e:
        raise ClaudeError(f"Claude transport error: {e}") from e
    finally:
        conn.close()

    if status != 200:
        err = ClaudeError(f"Claude API returned status {status}: {data[:500]}")
        # Rate-limit (429) / overloaded (529) / transient 5xx are retryable; carry
        # the server's Retry-After (seconds) so the caller can honor it.
        if status in (429, 500, 502, 503, 529):
            err.retry_after = _parse_retry_after(retry_after)  # type: ignore[attr-defined]
        raise err

    try:
        obj = json.loads(data)
    except json.JSONDecodeError as e:
        raise ClaudeError(f"Claude API returned non-JSON body: {data[:300]}") from e
    # Anthropic Messages response: ``content`` is a list of blocks; join text ones.
    parts = [b.get("text", "") for b in obj.get("content", []) if b.get("type") == "text"]
    return "".join(parts).strip()


def _strip_nul_system(system_prompt: "str | list") -> "str | list":
    """Strip NUL bytes from a system prompt, string or block-list form.

    For a list of content blocks, NUL is stripped from each block's ``text``
    while ``cache_control`` and other keys pass through unchanged (so caching
    breakpoints survive). A string is stripped directly.
    """
    if isinstance(system_prompt, list):
        cleaned = []
        for block in system_prompt:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                block = {**block, "text": block["text"].replace("\x00", "")}
            cleaned.append(block)
        return cleaned
    return (system_prompt or "").replace("\x00", "")


def call_claude(
    prompt: str,
    system_prompt: "str | list" = "",
    timeout: "int | None" = None,
) -> str:
    """Call Claude (Anthropic Messages API) and return the response text.

    Retries transient failures (5xx, resets, timeouts). ``system_prompt`` is
    either a plain string or a list of Anthropic content blocks (one of which may
    carry ``cache_control`` to cache the stable preamble).

    ``timeout`` (per-attempt, seconds) defaults to ``AGENTIC_SIFT_LLM_TIMEOUT``
    (or 300) and the retry count to ``AGENTIC_SIFT_MAX_ATTEMPTS`` (or 3), both
    read here at call time. The worst case for ONE stuck call is
    ``timeout × attempts`` — keep that bounded (e.g. --fast lowers the timeout)
    so a single hung gateway request can't stall a whole run for many minutes.

    Raises:
        ClaudeTimeoutError: If every attempt times out.
        ClaudeNotFoundError: If no transport/credentials are available.
        ClaudeError: If every attempt fails for another reason.
    """
    if timeout is None:
        timeout = _int_env("AGENTIC_SIFT_LLM_TIMEOUT", 300)
    max_attempts = _int_env("AGENTIC_SIFT_MAX_ATTEMPTS", _MAX_ATTEMPTS)

    # Forensic tool output fed back into prompts (reading a registry hive, a
    # binary file, raw strings) can contain NUL bytes. They are harmless inside a
    # JSON body (escaped), but stripping keeps prompts clean and matches the old
    # contract.
    prompt = prompt.replace("\x00", "")
    system_prompt = _strip_nul_system(system_prompt)

    last_error: ClaudeError = ClaudeError("Claude call failed")
    for attempt in range(max_attempts):
        try:
            return _post_messages(prompt, system_prompt, timeout)
        except ClaudeNotFoundError:
            # A missing transport is not transient — fail fast.
            raise
        except ClaudeError as e:
            last_error = e

        if attempt < max_attempts - 1:
            # Honor the server's Retry-After on a 429/529; otherwise exponential
            # backoff so a burst of rate-limited calls doesn't thundering-herd.
            retry_after = getattr(last_error, "retry_after", None)
            delay = (
                retry_after
                if retry_after is not None
                else _RETRY_BACKOFF_S * (2**attempt)
            )
            time.sleep(delay)

    raise last_error


def call_claude_json(
    prompt: str,
    system_prompt: "str | list" = "",
    timeout: "int | None" = None,
) -> Optional[dict]:
    """Call Claude and parse the response as JSON.

    Returns None if the call fails or parsing fails.
    """
    try:
        response = call_claude(prompt, system_prompt, timeout)
    except ClaudeError as e:
        _debug(f"call_claude raised {type(e).__name__}: {e}")
        return None

    parsed = _parse_json_response(response)
    if parsed is None:
        _debug(
            f"json parse failed; raw response ({len(response)} chars): "
            f"{response[:1000]!r}"
        )
        return None
    if not isinstance(parsed, dict):
        _debug(
            f"json parse returned non-object {type(parsed).__name__}; "
            f"raw response ({len(response)} chars): {response[:1000]!r}"
        )
        return None
    return parsed


def _loads_or_none(candidate: str):
    """json.loads that returns None on failure or a non-object/array result."""
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, (dict, list)) else None


def _first_json_span(text: str) -> Optional[str]:
    """The FIRST balanced ``{...}`` or ``[...]`` span embedded in prose.

    A best-effort fallback for JSON without a code fence. Scans from the first
    opener and tracks nesting depth, skipping braces/brackets inside string
    literals (honoring backslash escapes). This matters because the model
    (Opus) is chatty: it prepends prose and sometimes emits MORE THAN ONE
    top-level object. Spanning first-opener-to-last-closer would concatenate
    those into one invalid blob (``{...}\\n{...}``) that fails to parse, dropping
    the whole turn; returning the first balanced object recovers it. A value
    like ``"a}b"`` likewise must not end the span early. Returns None when no
    balanced span exists.
    """
    openers = {"{": "}", "[": "]"}
    start = next((i for i, ch in enumerate(text) if ch in openers), -1)
    if start == -1:
        return None
    opener = text[start]
    closer = openers[opener]
    depth = 0
    in_str = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _parse_json_response(response: str) -> Optional[dict]:
    """Extract a JSON object/array from an LLM response, tolerating surrounding
    prose or code fences.

    The model sometimes wraps the JSON in a ```` ```json ```` fence and/or
    prepends commentary. Requiring the response to *start* with JSON drops those
    otherwise-valid replies, silently yielding no hypotheses/findings. This pulls
    the JSON out regardless of leading/trailing text; returns None if nothing
    parses.
    """
    if not response:
        return None
    text = response.strip()
    # Prefer the contents of a fenced code block if one appears anywhere.
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        obj = _loads_or_none(fence.group(1).strip())
        if obj is not None:
            return obj
    # Then the whole response (covers a clean JSON-only reply).
    obj = _loads_or_none(text)
    if obj is not None:
        return obj
    # Finally, the first balanced {...}/[...] span embedded in prose.
    span = _first_json_span(text)
    if span is not None:
        return _loads_or_none(span)
    return None
