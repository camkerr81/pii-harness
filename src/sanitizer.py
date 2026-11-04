"""Egress scanner: replaces sensitive values with deterministic semantic tokens before data leaves the host."""

import copy
import json
import re
from collections.abc import Callable
from typing import Any

from .vault import TOKEN_RE, PIIVault

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

# Names of fields that hold secrets: password, db.password, client_secret, AWS_SECRET_ACCESS_KEY, x-api-key, token...
_SECRET_NAME = (
    r"(?:[A-Za-z0-9]+[_.-])*"
    r"(?:password|passwd|pwd|passphrase|secret|(?:api|access|secret|private)[_-]?key|apikey"
    r"|(?:auth|access|refresh|session|bearer)?[_-]?token|credentials?)"
)
SECRET_NAME_RE = re.compile(rf"(?i)^{_SECRET_NAME}$")
# Unquoted values that are code or placeholders rather than secrets (``password: str``, ``token = None``).
_NOT_A_SECRET = r"(?:none|null|nil|true|false|undefined|str|string|bytes|int|bool|any|object|number|optional|required)"


def _phone_digits_ok(value: str) -> bool:
    return 8 <= sum(c.isdigit() for c in value) <= 15


def _not_local_ip(value: str) -> bool:
    """Loopback and wildcard addresses stay readable so local dev URLs keep working."""
    return not value.startswith("127.") and value != "0.0.0.0"


# (entity_type, pattern, optional validator). When a pattern has a group named "v", only that group is
# replaced (e.g. the password in "password=hunter2"). Overlaps resolve to the earliest match; at the
# same start the earlier detector in this list wins, then the longer match.
DETECTORS: list[tuple[str, re.Pattern[str], Callable[[str], bool] | None]] = [
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
            r"(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|[A-Za-z0-9+/=\s\\]*)"  # or truncated
        ),
        None,
    ),
    (
        "API_KEY",
        re.compile(
            r"(?<![A-Za-z0-9_-])(?:"
            r"sk-[A-Za-z0-9_-]{16,}"  # OpenAI, Anthropic, DeepSeek, ...
            r"|(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"  # Stripe
            r"|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{22,}"  # GitHub
            r"|glpat-[A-Za-z0-9_-]{20,}"  # GitLab
            r"|xox[abposr]-[A-Za-z0-9-]+|xapp-[A-Za-z0-9-]+"  # Slack
            r"|(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"  # AWS access key ID
            r"|AIza[A-Za-z0-9_-]{35}"  # Google
            r"|hf_[A-Za-z0-9]{30,}"  # Hugging Face
            r"|npm_[A-Za-z0-9]{36}"  # npm
            r"|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"  # SendGrid
            r")(?![A-Za-z0-9])"
        ),
        None,
    ),
    ("JWT", re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), None),
    (
        "CREDENTIAL",  # password = "correct horse"  /  "client_secret": "abc def"
        re.compile(rf"(?i)(?<![A-Za-z0-9_.-]){_SECRET_NAME}[\"']?\s*[:=]\s*([\"'])(?P<v>(?:(?!\1)[^\n]){{3,}}?)\1"),
        None,
    ),
    (
        "CREDENTIAL",  # PASSWORD=hunter2  /  token: abc123  (but not ``password: str`` or ``getpass()``)
        re.compile(
            rf"(?i)(?<![A-Za-z0-9_.-]){_SECRET_NAME}[\"']?\s*[:=]\s*"
            rf"(?!{_NOT_A_SECRET}(?![^\s\"'`,;]))(?P<v>[^\s\"'`,;(){{}}\[\]<>$]{{3,}})(?=[\s\"'`,;)}}\]]|$)"
        ),
        None,
    ),
    ("CREDENTIAL", re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<v>[^\s@/]+)@"), None),  # scheme://user:pass@
    ("CREDENTIAL", re.compile(r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._~+/=-]{16,})"), None),
    ("CREDENTIAL", re.compile(r"(?i)\bbasic\s+(?P<v>[A-Za-z0-9+/]{16,}={0,2})"), None),
    (
        "EMAIL",
        re.compile(
            r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
            r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
            r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"
        ),
        None,
    ),
    ("IPV4", re.compile(rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\d|\.\d)"), _not_local_ip),
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

    The default finds nothing. ``src.ner.build_ner`` returns a GLiNER-backed callable with the same
    signature when ``NER_BACKEND=gliner``; any other model can be passed as ``Sanitizer(ner=...)``.
    """
    return []


class Sanitizer:
    def __init__(
        self,
        vault: PIIVault,
        ner: Callable[[str], list[tuple[str, str]]] = extract_unstructured_entities,
        custom_terms: list[str] = (),
    ):
        self.vault = vault
        self.ner = ner
        # Site-specific names, domains, and hostnames (CUSTOM_REDACT_TERMS), matched case-insensitively
        # as whole words. Longest first, so "db.corp.example" wins over "corp.example".
        terms = sorted({t.strip() for t in custom_terms if t.strip()}, key=len, reverse=True)
        self.custom_re = (
            re.compile(r"(?i)(?<!\w)(?:" + "|".join(map(re.escape, terms)) + r")(?!\w)") if terms else None
        )

    def find_entities(self, text: str) -> list[tuple[int, int, str]]:
        """Non-overlapping ``(start, end, entity_type)`` spans."""
        candidates: list[tuple[int, int, int, str]] = []  # (start, priority, -length, type)
        for priority, (entity_type, pattern, validator) in enumerate(DETECTORS):
            for m in pattern.finditer(text):
                start, end = m.span("v") if "v" in pattern.groupindex else m.span()
                if end > start and not TOKEN_RE.fullmatch(text, start, end) and (validator is None or validator(m.group())):
                    candidates.append((start, priority, start - end, entity_type))
        # Custom terms and NER rank after the detectors, so at the same start a structured match such as
        # a whole email address wins over a custom term or name that is only its local part.
        if self.custom_re:
            for m in self.custom_re.finditer(text):
                candidates.append((m.start(), len(DETECTORS), m.start() - m.end(), "CUSTOM"))
        for entity_type, value in self.ner(text):
            if value.strip():
                # Whole-word occurrences only, so "Jane" never matches inside "Janet".
                for m in re.finditer(rf"(?<!\w){re.escape(value)}(?!\w)", text):
                    candidates.append((m.start(), len(DETECTORS) + 1, m.start() - m.end(), entity_type))
        spans: list[tuple[int, int, str]] = []
        last_end = 0
        for start, _, neg_len, entity_type in sorted(candidates):
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

    def sanitize_json_value(self, session_id: str, value: Any) -> Any:
        """Scrub a decoded JSON value. Values under secret-named keys (``"password": ...``) are
        tokenised whole even when no detector recognises them."""
        if isinstance(value, str):
            return self.sanitize_text(session_id, value)
        if isinstance(value, list):
            return [self.sanitize_json_value(session_id, v) for v in value]
        if not isinstance(value, dict):
            return value
        out = {}
        for key, item in value.items():
            new_key = self.sanitize_text(session_id, key)
            is_secret = isinstance(item, (str, int)) and not isinstance(item, bool) and SECRET_NAME_RE.match(key)
            if is_secret and str(item).strip() and not TOKEN_RE.fullmatch(str(item)):
                scrubbed = self.sanitize_text(session_id, str(item))
                out[new_key] = scrubbed if scrubbed != str(item) else self.vault.get_or_create_token(session_id, "CREDENTIAL", str(item))
            else:
                out[new_key] = self.sanitize_json_value(session_id, item)
        return out

    def sanitize_json_arguments(self, session_id: str, raw_json_str: str) -> str:
        try:
            data = json.loads(raw_json_str)
        except ValueError:
            return self.sanitize_text(session_id, raw_json_str)  # tokens contain no JSON metacharacters
        return json.dumps(self.sanitize_json_value(session_id, data), ensure_ascii=False)

    def sanitize_messages(self, session_id: str, messages: list[dict]) -> list[dict]:
        """Scrub every text-bearing field of chat messages, including ``role == "tool"`` outputs
        and the arguments of earlier assistant tool calls. Non-text parts (e.g. images) are untouched."""
        cleaned = copy.deepcopy(messages)
        for message in cleaned:
            content = message.get("content")
            if isinstance(content, str):
                message["content"] = self.sanitize_text(session_id, content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        part["text"] = self.sanitize_text(session_id, part["text"])
            calls = [c.get("function") or {} for c in message.get("tool_calls") or []]
            if isinstance(message.get("function_call"), dict):
                calls.append(message["function_call"])
            for function in calls:
                if isinstance(function.get("arguments"), str):
                    function["arguments"] = self.sanitize_json_arguments(session_id, function["arguments"])
        return cleaned

    def sanitize_payload(self, session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        sanitized = dict(payload)
        if isinstance(payload.get("messages"), list):
            sanitized["messages"] = self.sanitize_messages(session_id, payload["messages"])
        return sanitized
