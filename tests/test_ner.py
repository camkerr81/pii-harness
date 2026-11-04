import re

import pytest

from src.ner import CHUNK_WORDS, GlinerExtractor, chunk_text, parse_labels
from src.sanitizer import Sanitizer
from src.vault import PIIVault

LABELS = {"person": "PERSON", "school": "SCHOOL"}


class FakeGliner:
    """Mimics GLiNER: finds known entities, but like the real model ignores text past 384 words."""

    KNOWN = {"Sarah O'Connor": "person", "Mia Chen": "person", "Jane Doe": "person", "Claude": "person",
             "name": "person", "User": "person", "Baulkham Hills High School": "school"}

    def __init__(self):
        self.calls: list[list[str]] = []

    def inference(self, texts, labels, threshold, batch_size):
        self.calls.append(texts)
        results = []
        for text in texts:
            visible = " ".join(text.split()[:384])
            results.append([{"text": v, "label": label} for v, label in self.KNOWN.items()
                            if label in labels and re.search(rf"(?<!\w){re.escape(v)}(?!\w)", visible)])
        return results


def test_parse_labels():
    assert parse_labels("person:PERSON, street address:address ,") == {"person": "PERSON", "street address": "ADDRESS"}
    for bad in ["", "person", "person:", "person:bad-type", "school:" + "X" * 25]:
        with pytest.raises(ValueError):
            parse_labels(bad)


def test_long_text_is_scanned_to_the_end():
    filler = "The quarterly report covers routine maintenance and upgrades. " * 80
    text = f"Sarah O'Connor wrote this. {filler} Signed, Mia Chen of Baulkham Hills High School."
    model = FakeGliner()
    found = GlinerExtractor(model, LABELS, 0.5, set())(text)
    assert set(found) == {("PERSON", "Sarah O'Connor"), ("PERSON", "Mia Chen"), ("SCHOOL", "Baulkham Hills High School")}
    assert all(len(chunk.split()) <= CHUNK_WORDS for chunk in model.calls[0])


def test_chunks_overlap_so_entities_on_a_boundary_are_kept():
    words = [f"w{i}" for i in range(400)]
    chunks = chunk_text(" ".join(words))
    for i in range(len(words) - 1):  # every adjacent word pair appears together in some chunk
        assert any(f"{words[i]} {words[i + 1]}" in c for c in chunks), i
    assert chunk_text("") == [] and chunk_text("short text") == ["short text"]


def test_code_identifiers_and_ignored_words_are_not_entities():
    text = "def find(name): return db.query(User).filter(User.name == name)\n# reviewed by Jane Doe with Claude"
    assert GlinerExtractor(FakeGliner(), LABELS, 0.5, {"claude"})(text) == [("PERSON", "Jane Doe")]


def test_results_are_cached_per_text():
    model = FakeGliner()
    extractor = GlinerExtractor(model, LABELS, 0.5, set())
    for _ in range(3):
        extractor("Ask Jane Doe.")
    extractor("no capitals here, so the model is skipped")
    assert len(model.calls) == 1


def test_extractor_plugs_into_sanitizer():
    vault = PIIVault(":memory:", "test-secret")
    sanitizer = Sanitizer(vault, ner=GlinerExtractor(FakeGliner(), LABELS, 0.5, set()))
    text = "Mia Chen (Year 9, Baulkham Hills High School) emailed mia@example.com; Mia Chen again."
    assert sanitizer.sanitize_text("s", text) == "<<PERSON_01>> (Year 9, <<SCHOOL_01>>) emailed <<EMAIL_01>>; <<PERSON_01>> again."
    vault.close()
