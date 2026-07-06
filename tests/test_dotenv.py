"""Tests for the .env parser/serialiser."""

from __future__ import annotations

from dotmage import dotenv


def test_parse_basic() -> None:
    text = "A=1\nB=two\n"
    assert dotenv.parse(text) == {"A": "1", "B": "two"}


def test_parse_comments_blanks_and_export() -> None:
    text = "# comment\n\nexport FOO=bar\n  # indented comment\nBAZ=qux\n"
    assert dotenv.parse(text) == {"FOO": "bar", "BAZ": "qux"}


def test_parse_quoted_values() -> None:
    text = 'A="hello world"\nB=\'single #notcomment\'\nC="line\\nbreak"\n'
    parsed = dotenv.parse(text)
    assert parsed["A"] == "hello world"
    assert parsed["B"] == "single #notcomment"
    assert parsed["C"] == "line\nbreak"


def test_parse_ignores_lines_without_equals_and_empty_keys() -> None:
    assert dotenv.parse("NOEQUALS\n=novalue\nOK=1\n") == {"OK": "1"}


def test_serialize_sorted_and_minimal_quoting() -> None:
    out = dotenv.serialize({"B": "plain", "A": "needs space"})
    assert out == 'A="needs space"\nB=plain\n'


def test_serialize_empty() -> None:
    assert dotenv.serialize({}) == ""


def test_roundtrip_through_quoting() -> None:
    data = {"K": 'a "quote" and #hash and =eq', "EMPTY": "", "MULTI": "l1\nl2"}
    assert dotenv.parse(dotenv.serialize(data)) == data
