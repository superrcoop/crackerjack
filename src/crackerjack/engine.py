"""High-performance multi-algorithm password auditing and hashing engine.

Supports multi-core multiprocessing across:
- Bcrypt ($2a$, $2b$, $2y$)
- Argon2 ($argon2id$, $argon2i$, $argon2d$) via argon2-cffi
- PBKDF2-HMAC-SHA256 ($pbkdf2-sha256$, pbkdf2_sha256) via standard library hashlib
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Callable, Iterable, Iterator, Sequence

import bcrypt

from crackerjack.models import BenchmarkResult, HashAuditResult

try:
    import argon2
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False


def is_bcrypt_hash(hash_str: str) -> bool:
    """Check if a string matches standard modular crypt bcrypt format."""
    clean = hash_str.strip()
    return clean.startswith(("$2a$", "$2b$", "$2y$", "$2x$")) and len(clean) == 60


def is_argon2_hash(hash_str: str) -> bool:
    """Check if a string matches standard Argon2 modular crypt format."""
    clean = hash_str.strip()
    return clean.startswith(("$argon2id$", "$argon2i$", "$argon2d$"))


def is_pbkdf2_hash(hash_str: str) -> bool:
    """Check if a string matches PBKDF2 modular crypt or Django format."""
    clean = hash_str.strip()
    return clean.startswith(("$pbkdf2-sha256$", "$pbkdf2$", "pbkdf2_sha256$"))


def detect_hash_type(hash_str: str) -> str:
    """Detect the hashing algorithm of a candidate hash string."""
    clean = hash_str.strip()
    if is_bcrypt_hash(clean):
        return "bcrypt"
    if is_argon2_hash(clean):
        return "argon2"
    if is_pbkdf2_hash(clean):
        return "pbkdf2"
    return "unknown"


def hash_password(
    password: str,
    algorithm: str = "bcrypt",
    cost: int | None = None,
) -> str:
    """Generate a password hash using the specified algorithm.

    Args:
        password: The plaintext password.
        algorithm: 'bcrypt', 'argon2id', or 'pbkdf2-sha256'.
        cost: Algorithmic cost factor (rounds for bcrypt, time_cost for argon2, iterations for pbkdf2).
    """
    algo = algorithm.lower().strip()
    if algo == "bcrypt":
        rounds = cost if cost is not None else 12
        salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(password.encode("utf-8"), salt).decode("ascii")

    elif algo in ("argon2", "argon2id"):
        if not HAS_ARGON2:
            raise RuntimeError(
                "The 'argon2-cffi' package is required for Argon2 support. "
                "Install it with: pip install argon2-cffi"
            )
        time_cost = cost if cost is not None else 2
        ph = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=65536,
            parallelism=4,
            type=argon2.Type.ID,
        )
        return ph.hash(password)

    elif algo in ("pbkdf2", "pbkdf2-sha256"):
        iterations = cost if cost is not None else 100_000
        salt_bytes = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
        salt_b64 = base64.b64encode(salt_bytes).decode("ascii")
        hash_b64 = base64.b64encode(dk).decode("ascii")
        return f"$pbkdf2-sha256${iterations}${salt_b64}${hash_b64}"

    else:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: bcrypt, argon2id, pbkdf2-sha256")


def verify_bcrypt_single(candidate: str, hash_bytes: bytes) -> bool:
    """Safely check candidate against a bcrypt hash."""
    try:
        cand_bytes = candidate.encode("utf-8")
        if len(cand_bytes) > 72:
            cand_bytes = cand_bytes[:72]
        return bcrypt.checkpw(cand_bytes, hash_bytes)
    except Exception:
        return False


def verify_argon2_single(candidate: str, hash_str: str) -> bool:
    """Safely check candidate against an Argon2 hash."""
    if not HAS_ARGON2:
        return False
    try:
        ph = argon2.PasswordHasher()
        return ph.verify(hash_str.strip(), candidate)
    except Exception:
        return False


def verify_pbkdf2_single(candidate: str, hash_str: str) -> bool:
    """Safely check candidate against a PBKDF2 hash using constant-time comparison."""
    try:
        clean = hash_str.strip()
        parts = clean.split("$")
        if len(parts) == 5 and parts[1] == "pbkdf2-sha256":
            iterations = int(parts[2])
            salt = base64.b64decode(parts[3])
            expected_dk = base64.b64decode(parts[4])
            cand_dk = hashlib.pbkdf2_hmac("sha256", candidate.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(cand_dk, expected_dk)
        elif clean.startswith("pbkdf2_sha256$"):
            dj_parts = clean.split("$")
            iterations = int(dj_parts[1])
            salt = dj_parts[2].encode("utf-8")
            expected_hash = dj_parts[3]
            cand_dk = hashlib.pbkdf2_hmac("sha256", candidate.encode("utf-8"), salt, iterations)
            cand_hash = base64.b64encode(cand_dk).decode("ascii")
            return hmac.compare_digest(cand_hash, expected_hash)
        return False
    except Exception:
        return False


def verify_single_hash(candidate: str, hash_str: str, algo_type: str) -> bool:
    """Unified verification dispatcher."""
    if algo_type == "bcrypt":
        return verify_bcrypt_single(candidate, hash_str.encode("ascii"))
    elif algo_type == "argon2":
        return verify_argon2_single(candidate, hash_str)
    elif algo_type == "pbkdf2":
        return verify_pbkdf2_single(candidate, hash_str)
    return False


def _worker_check_batch_multi(
    candidates: list[str],
    target_hashes: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Worker task executed in a separate process for multi-algorithm targets.

    target_hashes is a list of (hash_str, algo_type).
    Returns list of (target_hash_str, matched_plaintext).
    """
    found: list[tuple[str, str]] = []
    for candidate in candidates:
        for hash_str, algo_type in target_hashes:
            if verify_single_hash(candidate, hash_str, algo_type):
                found.append((hash_str, candidate))
    return found


def chunk_iterable(iterable: Iterable[str], chunk_size: int = 100) -> Iterator[list[str]]:
    """Yield successive chunks of items from an iterable."""
    chunk: list[str] = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


class MultiCoreAuditEngine:
    """Auditing engine utilizing multiprocessing for parallel hash verification."""

    def __init__(self, workers: int | None = None) -> None:
        self.workers = workers or max(1, os.cpu_count() or 1)

    def audit_hashes(
        self,
        target_hashes: Sequence[str],
        candidate_words: Iterable[str],
        chunk_size: int = 100,
        progress_callback: Callable[[int, float, float, dict[str, str]], None] | None = None,
    ) -> list[HashAuditResult]:
        """Audit a collection of hashes (bcrypt, argon2, pbkdf2) against candidates.

        Args:
            target_hashes: List of hash strings to audit.
            candidate_words: Stream of candidate plaintext words.
            chunk_size: Size of candidate batches dispatched to each worker core.
            progress_callback: Optional callback(checked_count, elapsed_sec, hash_rate, cracked_map).

        Returns:
            List of HashAuditResult objects for each target hash.
        """
        valid_targets: list[tuple[str, str]] = []
        for h in target_hashes:
            h_clean = h.strip()
            algo = detect_hash_type(h_clean)
            if algo != "unknown":
                valid_targets.append((h_clean, algo))

        if not valid_targets:
            return []

        uncracked: dict[str, str] = dict(valid_targets)
        cracked: dict[str, str] = {}
        total_checked = 0
        start_time = time.perf_counter()

        with ProcessPoolExecutor(max_workers=self.workers) as executor:
            chunk_iter = chunk_iterable(candidate_words, chunk_size=chunk_size)
            max_pending = self.workers * 4
            future_to_chunk_size = {}

            for chunk in chunk_iter:
                if not uncracked:
                    break

                target_list = list(uncracked.items())
                fut = executor.submit(_worker_check_batch_multi, chunk, target_list)
                future_to_chunk_size[fut] = len(chunk)

                if len(future_to_chunk_size) >= max_pending:
                    done = []
                    for future in as_completed(future_to_chunk_size):
                        done.append(future)
                        c_size = future_to_chunk_size.pop(future)
                        total_checked += c_size
                        matches = future.result()
                        for h_str, pw in matches:
                            if h_str in uncracked:
                                cracked[h_str] = pw
                                uncracked.pop(h_str, None)

                        if progress_callback:
                            elapsed = time.perf_counter() - start_time
                            rate = total_checked / max(elapsed, 0.001)
                            progress_callback(total_checked, elapsed, rate, cracked)

                        if not uncracked:
                            for pending in future_to_chunk_size:
                                pending.cancel()
                            future_to_chunk_size.clear()
                            break

                        if len(future_to_chunk_size) < self.workers * 2:
                            break

            for future in as_completed(list(future_to_chunk_size.keys())):
                c_size = future_to_chunk_size.pop(future, 0)
                total_checked += c_size
                try:
                    matches = future.result()
                    for h_str, pw in matches:
                        if h_str in uncracked:
                            cracked[h_str] = pw
                            uncracked.pop(h_str, None)
                except Exception:
                    pass

                if progress_callback:
                    elapsed = time.perf_counter() - start_time
                    rate = total_checked / max(elapsed, 0.001)
                    progress_callback(total_checked, elapsed, rate, cracked)

        total_elapsed = time.perf_counter() - start_time
        final_rate = total_checked / max(total_elapsed, 0.001)

        results: list[HashAuditResult] = []
        for h_str, algo in valid_targets:
            is_cracked = h_str in cracked
            pw = cracked.get(h_str)
            results.append(
                HashAuditResult(
                    target_hash=h_str,
                    cracked=is_cracked,
                    plaintext=pw,
                    hash_type=algo,
                    attempts=total_checked,
                    elapsed_seconds=total_elapsed,
                    hash_rate=final_rate,
                )
            )

        return results


def run_benchmark(
    algorithm: str = "bcrypt",
    cost_factor: int | None = None,
    rounds: int = 16,
    workers: int | None = None,
) -> BenchmarkResult:
    """Benchmark single-core vs multi-core throughput for a given algorithm."""
    num_workers = workers or max(1, os.cpu_count() or 1)
    algo = algorithm.lower().strip()

    if algo == "bcrypt":
        effective_cost = cost_factor if cost_factor is not None else 10
    elif algo in ("argon2", "argon2id"):
        effective_cost = cost_factor if cost_factor is not None else 2
    elif algo in ("pbkdf2", "pbkdf2-sha256"):
        effective_cost = cost_factor if cost_factor is not None else 50_000
    else:
        effective_cost = cost_factor if cost_factor is not None else 10

    test_password = "CrackerjackBenchmarkTest#2026"
    test_hash_str = hash_password(test_password, algorithm=algo, cost=effective_cost)

    candidates = [f"candidate_attempt_{i}" for i in range(rounds)]

    # 1. Single-core benchmark
    single_start = time.perf_counter()
    _worker_check_batch_multi(candidates, [(test_hash_str, algo)])
    single_elapsed = time.perf_counter() - single_start
    single_rate = rounds / max(single_elapsed, 0.0001)

    # 2. Multi-core benchmark
    multi_rounds = rounds * num_workers
    multi_candidates = [f"multi_attempt_{i}" for i in range(multi_rounds)]
    engine = MultiCoreAuditEngine(workers=num_workers)

    multi_start = time.perf_counter()
    engine.audit_hashes(
        target_hashes=[test_hash_str],
        candidate_words=multi_candidates,
        chunk_size=max(2, rounds // 2),
    )
    multi_elapsed = time.perf_counter() - multi_start
    multi_rate = multi_rounds / max(multi_elapsed, 0.0001)

    speedup = multi_rate / max(single_rate, 0.0001)

    return BenchmarkResult(
        algorithm=algo,
        cost_factor=effective_cost,
        workers=num_workers,
        single_core_rate=single_rate,
        multi_core_rate=multi_rate,
        speedup=speedup,
    )
