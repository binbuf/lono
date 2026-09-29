from __future__ import annotations

from lono_gateway.audit.store import AuditStore
from lono_gateway.models import Detection
from lono_gateway.pseudonymizer import Pseudonymizer, ResolvedDetection
from lono_gateway.rehydrator import StreamingRehydrator, load_rehydrator
from lono_gateway.settings import PseudonymizationConfig

EMAIL = "steve@mycompany.com"


def _email_detection(text: str) -> Detection:
    start = text.index(EMAIL)
    return Detection(
        detector="pii.regex",
        kind="EMAIL_ADDRESS",
        start=start,
        end=start + len(EMAIL),
        score=0.9,
        suggested="pseudonymize",
    )


def test_deterministic_across_instances_and_scoped_by_session(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    cfg = PseudonymizationConfig(secret="s3cret")
    text = "Email steve@mycompany.com about the invoice"
    detection = _email_detection(text)

    first = Pseudonymizer(store, cfg, "session-1").substitute(text, [ResolvedDetection(detection, "pseudonymize")])
    assert EMAIL not in first.text
    assert "@example.com" in first.text

    second = Pseudonymizer(store, cfg, "session-1").substitute(text, [ResolvedDetection(detection, "pseudonymize")])
    assert second.text == first.text

    other = Pseudonymizer(store, cfg, "session-2").substitute(text, [ResolvedDetection(detection, "pseudonymize")])
    assert other.text != first.text

    rehydrator = load_rehydrator(store, "session-1")
    assert rehydrator.rehydrate(first.text) == text
    store.close()


def test_mask_action_is_irreversible(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    cfg = PseudonymizationConfig(secret="s3cret")
    text = "password=hunter2secret"
    detection = Detection(
        detector="secrets", kind="PASSWORD_ASSIGNMENT", start=9, end=len(text), score=0.8, suggested="mask"
    )
    result = Pseudonymizer(store, cfg, "s").substitute(text, [ResolvedDetection(detection, "mask")])
    assert result.text == "password=[REDACTED:PASSWORD_ASSIGNMENT]"
    assert result.findings[0].action == "masked"
    assert not result.mappings
    store.close()


def test_streaming_rehydrator_reassembles_split_pseudonyms() -> None:
    mappings = {"Bob": "Steve", "bob@example.com": "steve@example.org"}
    stream = StreamingRehydrator(mappings)
    assert stream.feed("Hello ") == "Hello "
    assert stream.feed("Bo") == ""
    assert stream.feed("b!") == "Steve!"
    assert stream.feed(" write to bob@exa") == " write to "
    assert stream.feed("mple.com now") == "steve@example.org now"
    assert stream.flush() == ""


def test_streaming_rehydrator_handles_pseudonym_starting_with_last_char() -> None:
    # "mona...com" begins and ends with "m"; the trailing "m" must not be
    # mistaken for the start of a new pseudonym once the match is complete.
    mappings = {"mona.irwin35@example.com": "steve@mycompany.com"}
    stream = StreamingRehydrator(mappings)
    assert stream.feed("Contact ") == "Contact "
    assert stream.feed("mona.irwin3") == ""
    assert stream.feed("5@example.com") == "steve@mycompany.com"
    assert stream.flush() == ""


def test_streaming_rehydrator_does_not_break_words() -> None:
    stream = StreamingRehydrator({"Bob": "Steve"})
    assert stream.feed("Bobbing along") == "Bobbing along"
    assert stream.flush() == ""


def test_streaming_rehydrator_flush_emits_partial_prefix() -> None:
    stream = StreamingRehydrator({"Bob": "Steve"})
    assert stream.feed("Bo") == ""
    assert stream.flush() == "Bo"