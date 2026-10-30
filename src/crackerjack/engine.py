"""High-performance multi-core bcrypt auditing engine.

Uses multiprocessing to distribute CPU-bound bcrypt calculations across
all available CPU cores, providing significant speedups on multi-core processors.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Sequence

import bcrypt

from crackerjack.models import BenchmarkResult, HashAuditResult


def is_bcrypt_hash(hash_str: str) -> bool:
    """Check if a string matches the standard modular crypt bcrypt format."""
    clean = hash_str.strip()
    return (
        clean.startswith(("$2a$", "$2b$", "$2y$", "$2x$"))
        and len(clean) == 60
    )


def verify_bcrypt_single(candidate: str, hash_bytes: bytes) -> bool:
    """Safely check candidate against a bcrypt hash."""
    try:
        cand_bytes = candidate.encode("utf-8")
        # Bcrypt max password length is 72 bytes
        if len(cand_bytes) > 72:
            cand_bytes = cand_bytes[:72]
        return bcrypt.checkpw(cand_bytes, hash_bytes)
    except Exception:
        return False


def _worker_check_batch(
    candidates: list[str],
    target_hashes: list[tuple[str, bytes]],
) -> list[tuple[str, str]]:
    """Worker task executed in a separate process.

    Checks a list of candidate plaintexts against a list of target hashes.
    Returns list of (target_hash_str, matched_plaintext).
    """
    found: list[tuple[str, str]] = []
    for candidate in candidates:
        cand_bytes = candidate.encode("utf-8")
        if len(cand_bytes) > 72:
            cand_bytes = cand_bytes[:72]

        for hash_str, hash_bytes in target_hashes:
            try:
                if bcrypt.checkpw(cand_bytes, hash_bytes):
                    found.append((hash_str, candidate))
            except Exception:
                continue
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
    """Auditing engine utilizing multiprocessing for parallel bcrypt hashing."""

    def __init__(self, workers: int | None = None) -> None:
        self.workers = workers or max(1, os.cpu_count() or 1)

    def audit_hashes(
        self,
        target_hashes: Sequence[str],
        candidate_words: Iterable[str],
        chunk_size: int = 100,
        progress_callback: Callable[[int, float, float, dict[str, str]], None] | None = None,
    ) -> list[HashAuditResult]:
        """Audit a collection of bcrypt hashes against a candidate stream.

        Args:
            target_hashes: List of bcrypt hash strings to identify.
            candidate_words: Stream of candidate plaintext words.
            chunk_size: Size of candidate batches dispatched to each worker core.
            progress_callback: Optional callback(checked_count, elapsed_sec, hash_rate, cracked_map).

        Returns:
            List of HashAuditResult objects for each target hash.
        """
        valid_targets: list[tuple[str, bytes]] = []
        for h in target_hashes:
            h_clean = h.strip()
            if is_bcrypt_hash(h_clean):
                valid_targets.append((h_clean, h_clean.encode("ascii")))

        if not valid_targets:
            return []

        uncracked: dict[str, bytes] = dict(valid_targets)
        cracked: dict[str, str] = {}
        total_checked = 0
        start_time = time.perf_counter()

        # Submit chunks to ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=self.workers) as executor:
            chunk_iter = chunk_iterable(candidate_words, chunk_size=chunk_size)
            # Maintain active futures pipeline
            max_pending = self.workers * 4
            future_to_chunk_size = {}

            for chunk in chunk_iter:
                if not uncracked:
                    break

                target_list = list(uncracked.items())
                fut = executor.submit(_worker_check_batch, chunk, target_list)
                future_to_chunk_size[fut] = len(chunk)

                if len(future_to_chunk_size) >= max_pending:
                    # Collect finished futures before queueing more
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
                            # Cancel remaining
                            for pending in future_to_chunk_size:
                                pending.cancel()
                            future_to_chunk_size.clear()
                            break

                        # Break after consuming at least one batch to keep pipeline filled
                        if len(future_to_chunk_size) < self.workers * 2:
                            break

            # Drain any remaining active futures
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
        for h_str, _ in valid_targets:
            is_cracked = h_str in cracked
            pw = cracked.get(h_str)
            results.append(
                HashAuditResult(
                    target_hash=h_str,
                    cracked=is_cracked,
                    plaintext=pw,
                    hash_type="bcrypt",
                    attempts=total_checked,
                    elapsed_seconds=total_elapsed,
                    hash_rate=final_rate,
                )
            )

        return results


def run_benchmark(
    cost_factor: int = 10,
    rounds: int = 16,
    workers: int | None = None,
) -> BenchmarkResult:
    """Benchmark single-core vs multi-core bcrypt throughput."""
    num_workers = workers or max(1, os.cpu_count() or 1)
    # Generate a reference bcrypt hash with specified cost
    test_password = "CrackerjackBenchmarkTest#2026"
    test_hash_bytes = bcrypt.hashpw(
        test_password.encode("utf-8"),
        bcrypt.gensalt(rounds=cost_factor),
    )
    test_hash_str = test_hash_bytes.decode("ascii")

    candidates = [f"candidate_attempt_{i}" for i in range(rounds)]

    # 1. Single-core benchmark
    single_start = time.perf_counter()
    _worker_check_batch(candidates, [(test_hash_str, test_hash_bytes)])
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
        algorithm="bcrypt",
        cost_factor=cost_factor,
        workers=num_workers,
        single_core_rate=single_rate,
        multi_core_rate=multi_rate,
        speedup=speedup,
    )
