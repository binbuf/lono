from __future__ import annotations

from lono_gateway.detectors.terms import WatchlistDetector
from lono_gateway.settings import WatchlistConfig, WatchTerm


def test_inline_terms_with_replacement_type() -> None:
    cfg = WatchlistConfig(
        file="",
        terms=[
            WatchTerm(
                term="Bluebird",
                category="PROJECT_CODENAME",
                replacement_type="PROJECT_CODENAME",
                action="pseudonymize",
            )
        ],
    )
    detector = WatchlistDetector(cfg)
    hits = detector.scan("The Bluebird project ships Friday")
    assert hits
    assert hits[0].kind == "PROJECT_CODENAME"
    assert hits[0].suggested == "pseudonymize"


def test_word_match_does_not_hit_substrings() -> None:
    detector = WatchlistDetector(WatchlistConfig(file="", terms=[WatchTerm(term="ace", category="T", match="word")]))
    assert detector.scan("placeholder text") == []
    hits = detector.scan("ace of base")
    assert hits and hits[0].start == 0


def test_regex_term_from_file(tmp_path) -> None:
    path = tmp_path / "watchlist.yaml"
    path.write_text(
        "terms:\n"
        "  - term: '\\bCUST-\\d{6}\\b'\n"
        "    category: CUSTOMER_ID\n"
        "    match: regex\n"
        "    action: mask\n",
        encoding="utf-8",
    )
    detector = WatchlistDetector(WatchlistConfig(file=str(path)))
    hits = detector.scan("customer CUST-123456 called")
    assert hits
    assert hits[0].kind == "CUSTOMER_ID"
    assert hits[0].suggested == "mask"
    assert detector.scan("customer NOPE-1 called") == []


def test_disabled_watchlist_returns_nothing() -> None:
    detector = WatchlistDetector(
        WatchlistConfig(enabled=False, file="", terms=[WatchTerm(term="secret", category="T")])
    )
    assert detector.scan("secret") == []