"""Local NER backends for unstructured entities (people, schools, ...) that regexes cannot find."""

import logging
import re
import threading
from collections.abc import Callable
from functools import lru_cache

from .config import Settings
from .sanitizer import extract_unstructured_entities

logger = logging.getLogger("pii_harness")

# GLiNER silently ignores text past ~384 words, so long inputs are scanned in overlapping windows.
CHUNK_WORDS = 150
CHUNK_OVERLAP = 30
# Token types must stay short: "<<" + TYPE + "_NNN>>" has to fit the hydrator's 32-character lookahead.
MAX_TYPE_LEN = 24

_WORD_RE = re.compile(r"\S+")
_CODE_CHARS_RE = re.compile(r"[_(){}\[\]=<>/\\;:@#$%^*|~`\"]")


def parse_labels(spec: str) -> dict[str, str]:
    """``"person:PERSON,school:SCHOOL"`` -> ``{"person": "PERSON", "school": "SCHOOL"}``."""
    labels: dict[str, str] = {}
    for item in filter(None, (part.strip() for part in spec.split(","))):
        label, sep, entity_type = item.rpartition(":")
        entity_type = entity_type.strip().upper()
        if not sep or not label.strip() or not re.fullmatch(r"[A-Z][A-Z0-9_]*", entity_type):
            raise ValueError(f"NER_LABELS entry {item!r} must look like 'label:TYPE' with TYPE in [A-Z0-9_]")
        if len(entity_type) > MAX_TYPE_LEN:
            raise ValueError(f"NER_LABELS type {entity_type!r} is longer than {MAX_TYPE_LEN} characters")
        labels[label.strip()] = entity_type
    if not labels:
        raise ValueError("NER_LABELS is empty")
    return labels


def chunk_text(text: str, words: int = CHUNK_WORDS, overlap: int = CHUNK_OVERLAP) -> list[str]:
    spans = [m.span() for m in _WORD_RE.finditer(text)]
    if len(spans) <= words:
        return [text] if spans else []
    step = words - overlap
    return [text[spans[i][0] : spans[min(i + words, len(spans)) - 1][1]] for i in range(0, len(spans) - overlap, step)]


def plausible_entity(text: str, value: str) -> bool:
    """Reject the model's typical false positives in code and logs: lowercase words (``name``,
    ``user admin``), identifiers with code punctuation, and single words used as code (``User.name``,
    ``query(User)``)."""
    value = value.strip()
    if len(value) < 2 or "<<" in value or not any(c.isupper() for c in value) or _CODE_CHARS_RE.search(value):
        return False
    if " " not in value:
        code_use = rf"(?:[.(\[]{re.escape(value)}(?!\w))|(?:(?<!\w){re.escape(value)}(?:\(|\[|\.\w|\s*=[^=]))"
        if re.search(code_use, text):
            return False
    return True


def load_gliner(model_name: str):
    try:
        from gliner import GLiNER
    except ImportError as exc:
        raise RuntimeError(
            "NER_BACKEND=gliner but the 'gliner' package is not installed. "
            "Install pii-harness[ner] (or build the image with NER_BACKEND=gliner), or set NER_BACKEND=none."
        ) from exc
    return GLiNER.from_pretrained(model_name)


class GlinerExtractor:
    """NER hook backed by a loaded GLiNER model (anything with GLiNER's ``inference`` method)."""

    def __init__(self, model, labels: dict[str, str], threshold: float, ignore: set[str]):
        self.model = model
        self.labels = labels
        self.threshold = threshold
        self.ignore = {s.casefold() for s in ignore}
        self._lock = threading.Lock()
        # Chat clients resend the whole history every turn; cache results per text.
        self._cached = lru_cache(maxsize=4096)(self._extract)

    def __call__(self, text: str) -> list[tuple[str, str]]:
        return list(self._cached(text))

    def _extract(self, text: str) -> tuple[tuple[str, str], ...]:
        if not any(c.isupper() for c in text):
            return ()  # every accepted entity contains a capital letter
        with self._lock:
            results = self.model.inference(chunk_text(text), list(self.labels), threshold=self.threshold, batch_size=8)
        found = dict.fromkeys((self.labels[e["label"]], e["text"].strip()) for chunk in results for e in chunk)
        return tuple(
            (entity_type, value)
            for entity_type, value in found
            if value.casefold() not in self.ignore and plausible_entity(text, value)
        )


def build_ner(settings: Settings) -> Callable[[str], list[tuple[str, str]]]:
    if settings.NER_BACKEND == "none":
        logger.warning("NER_BACKEND=none: names, schools, and other unstructured entities will NOT be redacted.")
        return extract_unstructured_entities
    labels = parse_labels(settings.NER_LABELS)
    ignore = {s.strip() for s in settings.NER_IGNORE.split(",") if s.strip()}
    logger.info("Loading GLiNER model %s for labels %s", settings.NER_MODEL, labels)
    return GlinerExtractor(load_gliner(settings.NER_MODEL), labels, settings.NER_THRESHOLD, ignore)
