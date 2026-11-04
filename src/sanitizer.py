"""Egress scanner: replaces sensitive values with deterministic semantic tokens before data leaves the host."""

import copy
import re
from collections.abc import Callable
from typing import Any

from .tool_interceptor import sanitize_json_arguments
from .vault import PIIVault

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"


def _phone_digits_ok(value: str) -> bool:
    return 8 <= sum(c.isdigit() for c in value) <= 15


# (entity_type, pattern, optional validator). Earlier detectors win ties between equally long overlapping matches.
DETECTORS: list[tuple[str, re.Pattern[str], Callable[[str], bool] | None]] = [
    (
        "API_KEY",
        re.compile(r"(?<![A-Za-z0-9_-])(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]+)"),
        None,
    ),
    (
        "EMAIL",
        re.compile(
            r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
            r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
            r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
        ),
        None,
    ),
    ("IPV4", re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\d|\.\d)"), None),
    (
        "PHONE",
        re.compile(
            r"(?<![\w+])(?:"
            r"\+61[ -]?(?:\(0\)[ -]?)?[2-478](?:[ -]?\d){8}"  # +61 4xx xxx xxx, +61 2 xxxx xxxx
            r"|\(0[2-478]\)[ -]?\d{4}[ -]?\d{4}"  # (02) xxxx xxxx
            r"|0[2-478](?:[ -]?\d){8}"  # 04xx xxx xxx, 02 xxxx xxxx
            r"|1[38]00(?:[ -]?\d){6}"  # 1300 / 1800 numbers
            r"|\+[1-9]\d{0,2}(?:[ .-]?\(?\d{1,4}\)?){2,6}"  # generic international (validated below)
            r"|\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}"  # North American local
            r")(?!\d)"
        ),
        _phone_digits_ok,
    ),
]


def extract_unstructured_entities(text: str) -> list[tuple[str, str]]:
    """Pluggable NER hook returning ``(entity_type, value)`` pairs, e.g. ``("PERSON", "Jane Doe")``.

    The default finds nothing. Pass a GLiNER/Presidio-backed callable with the same signature
    as ``Sanitizer(ner=...)`` to add unstructured entity detection without touching the pipeline.
    """
    return []


class Sanitizer:
    def __init__(self, vault: PIIVault, ner: Callable[[str], list[tuple[str, str]]] = extract_unstructured_entities):
        self.vault = vault
        self.ner = ner

    def find_entities(self, text: str) -> list[tuple[int, int, str]]:
        """Non-overlapping ``(start, end, entity_type)`` spans, preferring the earliest, then longest, match."""
        candidates: list[tuple[int, int, int, str]] = []
        for priority, (entity_type, pattern, validator) in enumerate(DETECTORS):
            for m in pattern.finditer(text):
                if validator is None or validator(m.group()):
                    candidates.append((m.start(), -(m.end() - m.start()), priority, entity_type))
        for entity_type, value in self.ner(text):
            if value:
                for m in re.finditer(re.escape(value), text):
                    candidates.append((m.start(), -len(value), len(DETECTORS), entity_type))
        spans: list[tuple[int, int, str]] = []
        last_end = 0
        for start, neg_len, _, entity_type in sorted(candidates):
            if start >= last_end:
                spans.append((start, start - neg_len, entity_type))
                last_end = start - neg_len
        return spans

    def sanitize_text(self, session_id: str, text: str) -> str:
        parts: list[str] = []
        pos = 0
        for start, end, entity_type in self.find_entities(text):
            parts.append(text[pos:start])
            parts.append(self.vault.get_or_create_token(session_id, entity_type, text[start:end]))
            pos = end
        parts.append(text[pos:])
        return "".join(parts)

    def sanitize_messages(self, session_id: str, messages: list[dict]) -> list[dict]:
        """Scrub every text-bearing field of chat messages, including ``role == "tool"`` outputs
        and the arguments of earlier assistant tool calls. Non-text parts (e.g. images) are untouched."""
        scrub = lambda s: self.sanitize_text(session_id, s)  # noqa: E731
        cleaned = copy.deepcopy(messages)
        for message in cleaned:
            content = message.get("content")
            if isinstance(content, str):
                message["content"] = scrub(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        part["text"] = scrub(part["text"])
            calls = [c.get("function") or {} for c in message.get("tool_calls") or []]
            if isinstance(message.get("function_call"), dict):
                calls.append(message["function_call"])
            for function in calls:
                if isinstance(function.get("arguments"), str):
                    function["arguments"] = sanitize_json_arguments(function["arguments"], scrub)
        return cleaned

    def sanitize_payload(self, session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        sanitized = dict(payload)
        if isinstance(payload.get("messages"), list):
            sanitized["messages"] = self.sanitize_messages(session_id, payload["messages"])
        return sanitized
