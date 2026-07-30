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


def _extract_balanced(text: str) -> str | None:
    """Return the first balanced {...} or [...] block, ignoring braces inside strings."""
    start = None
    opener = closer = ""
    for i, ch in enumerate(text):
        if ch in "{[":
            start = i
            opener = ch
            closer = "}" if ch == "{" else "]"
            break
    if start is None:
        return None

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

    for candidate in (text, _strip_fence(text), _extract_balanced(_strip_fence(text))):
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list):
            return {"items": parsed}
    return default
