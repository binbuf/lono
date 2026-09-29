from __future__ import annotations

from lono_gateway.lists import build_lists, build_pools, parse_list_text
from lono_gateway.settings import PseudonymizationConfig


def test_parse_list_text_filters_comments_blanks_and_duplicates() -> None:
    text = "# comment\n\nAlice\nalice\nBob  \n# another\n"
    assert parse_list_text(text) == ["Alice", "Bob"]


def test_file_overrides_builtin_and_falls_back(tmp_path) -> None:
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "first_names.txt").write_text("Zephyr\nQuill\n", encoding="utf-8")

    cfg = PseudonymizationConfig(lists_dir=str(lists_dir), lists={"first_names": "first_names.txt"})
    resolved = build_lists(cfg)
    assert resolved["first_names"] == ["Zephyr", "Quill"]
    assert resolved["cities"]  # unconfigured categories keep the built-in list


def test_inline_pools_win_over_files(tmp_path) -> None:
    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "first_names.txt").write_text("Zephyr\n", encoding="utf-8")

    cfg = PseudonymizationConfig(
        lists_dir=str(lists_dir),
        lists={"first_names": "first_names.txt"},
        pools={"first_names": ["Inline"]},
    )
    pools = build_pools(cfg)
    assert pools.get("first_names") == ["Inline"]


def test_missing_file_falls_back_to_builtin() -> None:
    cfg = PseudonymizationConfig(lists_dir="/does/not/exist", lists={"first_names": "missing.txt"})
    resolved = build_lists(cfg)
    assert "Alex" in resolved["first_names"]


def test_builtin_keyword_uses_defaults() -> None:
    cfg = PseudonymizationConfig(lists={"first_names": "builtin"})
    resolved = build_lists(cfg)
    assert "Alex" in resolved["first_names"]


def test_any_category_can_be_list_backed(tmp_path) -> None:
    import random

    from lono_gateway.pools import generate_pseudonym

    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "PHONE_NUMBER.txt").write_text("+44 20 7946 0001\n+44 20 7946 0002\n", encoding="utf-8")

    cfg = PseudonymizationConfig(lists_dir=str(lists_dir), lists={"PHONE_NUMBER": "PHONE_NUMBER.txt"})
    pools = build_pools(cfg)
    assert pools.custom_pool("PHONE_NUMBER") == ["+44 20 7946 0001", "+44 20 7946 0002"]

    value = generate_pseudonym("PHONE_NUMBER", "+1 202 555 0100", random.Random(1), pools)
    assert value in pools.custom_pool("PHONE_NUMBER")


def test_custom_pool_is_deterministic(tmp_path) -> None:
    import random

    from lono_gateway.pools import generate_pseudonym

    lists_dir = tmp_path / "lists"
    lists_dir.mkdir()
    (lists_dir / "CUSTOMER_ID.txt").write_text("C-100\nC-200\nC-300\n", encoding="utf-8")
    cfg = PseudonymizationConfig(lists_dir=str(lists_dir), lists={"CUSTOMER_ID": "CUSTOMER_ID.txt"})
    pools = build_pools(cfg)

    first = generate_pseudonym("CUSTOMER_ID", "CUST-9", random.Random(7), pools)
    second = generate_pseudonym("CUSTOMER_ID", "CUST-9", random.Random(7), pools)
    assert first == second
    assert first.startswith("C-")