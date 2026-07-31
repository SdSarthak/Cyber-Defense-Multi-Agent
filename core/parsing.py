"""
Tolerant JSON extraction for LLM output.

Every agent prompt asks Gemini for "ONLY valid JSON", but models routinely wrap the
payload in ```json fences or add a sentence before it. A bare ``json.loads`` on that
text fails and the agent silently drops to its fallback verdict, which is how a
correctly-classified critical threat ends up recorded as "unknown/medium".

``parse_json_response`` strips fences and, failing that, extracts the outermost
balanced JSON object or array before giving up.
"""
from __future__ import annotations

import json
import re
from typing import Any

_FENCE_RE = re.compile(r"^\s*```(?:json|JSON)?\s*(.*?)\s*```\s*$", re.DOTALL)


def _strip_fence(text: str) -> str:
    match = _FENCE_RE.match(text)
    return match.group(1) if match else text


def _balanced_from(text: str, start: int) -> str | None:
    """Return the balanced block opening at ``start``, ignoring brackets inside strings."""
    opener = text[start]
    closer = "}" if opener == "{" else "]"
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _balanced_candidates(text: str):
    """
    Yield every balanced {...} / [...] block in ``text``, outermost first.

    Anchoring on the *first* bracket alone is not enough: models routinely preface
    the payload with prose that contains one ("Analysis [step 1]: {...}", "use
    {curly} braces"). That leading bracket either fails to parse or — worse — parses
    into an unrelated value, and the agent silently records its fallback verdict.
    Scanning every opener and letting the caller keep the first block that is valid
    JSON recovers the real payload.
    """
    i = 0
    n = len(text)
    while i < n:
        if text[i] in "{[":
            block = _balanced_from(text, i)
            if block is not None:
                yield block
                # Skip past this block: nested blocks are already inside it.
                i += len(block)
                continue
        i += 1


def parse_json_response(content: Any, default: dict | None = None) -> dict | None:
    """
    Best-effort parse of an LLM response into a dict.

    Returns ``default`` (None unless supplied) when nothing JSON-shaped is found.
    A JSON array is wrapped as ``{"items": [...]}`` so callers always get a mapping.
    """
    if isinstance(content, dict):
        return content
    if content is None:
        return default

    text = content if isinstance(content, str) else str(content)
    unfenced = _strip_fence(text)

    def _candidates():
        yield text
        yield unfenced
        yield from _balanced_candidates(unfenced)

    fallback: dict | None = None
    for candidate in _candidates():
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list) and fallback is None:
            # A bare array may well be a bracket in the preamble ("[step 1]"), so
            # keep looking for an object and only fall back to the array if the
            # rest of the text yields nothing better.
            fallback = {"items": parsed}
    return fallback if fallback is not None else default
