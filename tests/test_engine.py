"""Tests for multi-core multi-algorithm auditing engine and benchmarking."""

import bcrypt
from crackerjack.engine import (
    MultiCoreAuditEngine,
    chunk_iterable,
    detect_hash_type,
    hash_password,
    is_argon2_hash,
    is_bcrypt_hash,
    is_pbkdf2_hash,
    run_benchmark,
    verify_bcrypt_single,
    verify_pbkdf2_single,
)


def test_hash_type_detection():
    bcrypt_h = "$2b$12$e8POdGlHFgqWq7GfQ1L46.kIeD5W3hF9qgJ4z7r0u6t5g8v9k3y5e"
    argon2_h = "$argon2id$v=19$m=65536,t=2,p=1$fakeSalt$fakeHash"
    pbkdf2_h = "$pbkdf2-sha256$20000$c2FsdDEyMzQ$hash12345"

    assert is_bcrypt_hash(bcrypt_h) is True
    assert is_argon2_hash(argon2_h) is True
    assert is_pbkdf2_hash(pbkdf2_h) is True

    assert detect_hash_type(bcrypt_h) == "bcrypt"
    assert detect_hash_type(argon2_h) == "argon2"
    assert detect_hash_type(pbkdf2_h) == "pbkdf2"
    assert detect_hash_type("unknown_random_string") == "unknown"


def test_pbkdf2_generation_and_verification():
    pw = "pbkdf2_secret_pass"
    h = hash_password(pw, algorithm="pbkdf2-sha256", cost=1000)
    assert h.startswith("$pbkdf2-sha256$1000$")

    assert verify_pbkdf2_single(pw, h) is True
    assert verify_pbkdf2_single("wrong_password", h) is False


def test_verify_bcrypt_single():
    salt = bcrypt.gensalt(rounds=4)
    hashed = bcrypt.hashpw(b"testpass123", salt)
    assert verify_bcrypt_single("testpass123", hashed) is True
    assert verify_bcrypt_single("wrongpass", hashed) is False


def test_chunk_iterable():
    items = ["a", "b", "c", "d", "e"]
    chunks = list(chunk_iterable(items, chunk_size=2))
    assert chunks == [["a", "b"], ["c", "d"], ["e"]]


def test_multicore_engine_multi_algo_audit():
    # Target 1: Bcrypt
    pw_bcrypt = "alpha_bcrypt"
    h_bcrypt = bcrypt.hashpw(pw_bcrypt.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("ascii")

    # Target 2: PBKDF2
    pw_pbkdf2 = "beta_pbkdf2"
    h_pbkdf2 = hash_password(pw_pbkdf2, algorithm="pbkdf2-sha256", cost=500)

    engine = MultiCoreAuditEngine(workers=2)
    candidates = [
        "wrong1", "alpha_bcrypt", "wrong2", "beta_pbkdf2", "wrong3"
    ]

    results = engine.audit_hashes(
        target_hashes=[h_bcrypt, h_pbkdf2],
        candidate_words=candidates,
        chunk_size=2,
    )

    assert len(results) == 2
    r_map = {r.target_hash: r for r in results}

    assert r_map[h_bcrypt].cracked is True
    assert r_map[h_bcrypt].plaintext == pw_bcrypt
    assert r_map[h_bcrypt].hash_type == "bcrypt"

    assert r_map[h_pbkdf2].cracked is True
    assert r_map[h_pbkdf2].plaintext == pw_pbkdf2
    assert r_map[h_pbkdf2].hash_type == "pbkdf2"


def test_benchmark_run():
    # Test bcrypt benchmark with cost=4
    res_bcrypt = run_benchmark(algorithm="bcrypt", cost_factor=4, rounds=4, workers=2)
    assert res_bcrypt.algorithm == "bcrypt"
    assert res_bcrypt.cost_factor == 4
    assert res_bcrypt.single_core_rate > 0
    assert res_bcrypt.multi_core_rate > 0

    # Test pbkdf2 benchmark with small iterations
    res_pbkdf2 = run_benchmark(algorithm="pbkdf2-sha256", cost_factor=1000, rounds=4, workers=2)
    assert res_pbkdf2.algorithm == "pbkdf2-sha256"
    assert res_pbkdf2.cost_factor == 1000
    assert res_pbkdf2.single_core_rate > 0
    assert res_pbkdf2.multi_core_rate > 0
