"""Zero-RAM streaming wordlist loader with multi-compression support.

Transparently streams dictionary wordlists from:
- Plain text (.txt, .dic, .words, etc.)
- Gzip compressed (.gz)
- Bzip2 compressed (.bz2)
- Xz/LZMA compressed (.xz)

Generates candidate mutations lazily on-the-fly, enabling processing of
multi-gigabyte wordlists with negligible resident memory footprint.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, TextIO

from crackerjack.rules import mutate_word


def open_wordlist_file(file_path: Path | str) -> TextIO:
    """Transparently open plain or compressed text files."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Wordlist file not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".gz":
        import gzip
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    elif suffix == ".bz2":
        import bz2
        return bz2.open(path, mode="rt", encoding="utf-8", errors="replace")
    elif suffix in (".xz", ".lzma"):
        import lzma
        return lzma.open(path, mode="rt", encoding="utf-8", errors="replace")
    else:
        return path.open(mode="r", encoding="utf-8", errors="replace")


def stream_wordlist_lines(file_path: Path | str) -> Iterator[str]:
    """Stream non-empty, stripped lines from a wordlist without loading into memory."""
    with open_wordlist_file(file_path) as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                yield stripped


def stream_candidates(
    file_path: Path | str,
    use_rules: bool = True,
    max_variants_per_word: int = 40,
) -> Iterator[str]:
    """Stream candidate passwords lazily, optionally expanding via rule mutations.

    Operates in O(1) memory space regardless of file size.
    """
    for base_word in stream_wordlist_lines(file_path):
        if not use_rules:
            yield base_word
        else:
            for variant in mutate_word(base_word, max_variants=max_variants_per_word):
                yield variant
