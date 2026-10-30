"""Tests for zero-RAM streaming wordlist loader with compression support."""

from pathlib import Path

from crackerjack.wordlist import (
    open_wordlist_file,
    stream_candidates,
    stream_wordlist_lines,
)


def test_stream_plain_text(tmp_path: Path):
    plain_file = tmp_path / "words.txt"
    plain_file.write_text("alpha\nbeta\n# comment\n\ngamma\n", encoding="utf-8")

    lines = list(stream_wordlist_lines(plain_file))
    assert lines == ["alpha", "beta", "gamma"]


def test_stream_gzip_compressed(tmp_path: Path):
    import gzip
    gz_file = tmp_path / "words.txt.gz"
    content = b"apple\nbanana\n# ignore\ncherry\n"
    with gzip.open(gz_file, "wb") as f:
        f.write(content)

    lines = list(stream_wordlist_lines(gz_file))
    assert lines == ["apple", "banana", "cherry"]


def test_stream_candidates_lazy(tmp_path: Path):
    test_file = tmp_path / "dict.txt"
    test_file.write_text("admin\nroot\n", encoding="utf-8")

    # With rules disabled, yields plain words
    plain_stream = stream_candidates(test_file, use_rules=False)
    assert list(plain_stream) == ["admin", "root"]

    # With rules enabled, yields generator with mutations
    rule_stream = stream_candidates(test_file, use_rules=True, max_variants_per_word=10)
    items = list(rule_stream)
    assert len(items) > 5
    assert "admin" in items
    assert "root" in items
