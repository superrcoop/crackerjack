"""Tests for multi-core bcrypt auditing engine and benchmarking."""

import bcrypt
import pytest
from crackerjack.engine import (
    MultiCoreAuditEngine,
    chunk_iterable,
    is_bcrypt_hash,
    run_benchmark,
    verify_bcrypt_single,
)


def test_is_bcrypt_hash():
    valid = "$2b$12$e8POdGlHFgqWq7GfQ1L46.kIeD5W3hF9qgJ4z7r0u6t5g8v9k3y5e"
    assert is_bcrypt_hash(valid) is True
    assert is_bcrypt_hash("not_a_hash") is False
    assert is_bcrypt_hash("$2b$12$short") is False


def test_verify_bcrypt_single():
    salt = bcrypt.gensalt(rounds=4)
    hashed = bcrypt.hashpw(b"testpass123", salt)
    assert verify_bcrypt_single("testpass123", hashed) is True
    assert verify_bcrypt_single("wrongpass", hashed) is False


def test_chunk_iterable():
    items = ["a", "b", "c", "d", "e"]
    chunks = list(chunk_iterable(items, chunk_size=2))
    assert chunks == [["a", "b"], ["c", "d"], ["e"]]


def test_multicore_engine_audit():
    # Generate 2 low-cost test hashes
    pw1 = "crackerjack_alpha"
    pw2 = "crackerjack_beta"
    h1 = bcrypt.hashpw(pw1.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("ascii")
    h2 = bcrypt.hashpw(pw2.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("ascii")

    engine = MultiCoreAuditEngine(workers=2)
    candidates = [
        "wrong1", "wrong2", "crackerjack_alpha", "wrong3", "crackerjack_beta", "wrong4"
    ]

    results = engine.audit_hashes(
        target_hashes=[h1, h2],
        candidate_words=candidates,
        chunk_size=2,
    )

    assert len(results) == 2
    r_map = {r.target_hash: r for r in results}
    assert r_map[h1].cracked is True
    assert r_map[h1].plaintext == pw1
    assert r_map[h2].cracked is True
    assert r_map[h2].plaintext == pw2


def test_benchmark_run():
    # Test benchmark with cost=4 and small rounds for fast test execution
    res = run_benchmark(cost_factor=4, rounds=4, workers=2)
    assert res.algorithm == "bcrypt"
    assert res.cost_factor == 4
    assert res.workers == 2
    assert res.single_core_rate > 0
    assert res.multi_core_rate > 0
