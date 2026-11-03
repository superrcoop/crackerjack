"""Active Cyber Deception: Honeyword generation, decoy injection, and canary tripwires."""

from __future__ import annotations

import math
import random
import secrets
import string
import uuid
from typing import Any

from crackerjack.models import CompositionFlags, HoneywordSet


def _analyze_composition(password: str) -> tuple[int, CompositionFlags]:
    """Analyze character diversity and length for honeyword parity."""
    flags = CompositionFlags(
        has_lower=any(c.islower() for c in password),
        has_upper=any(c.isupper() for c in password),
        has_digit=any(c.isdigit() for c in password),
        has_symbol=any(not c.isalnum() for c in password),
    )
    return len(password), flags


def _generate_plausible_decoy(password: str, flags: CompositionFlags) -> str:
    """Generate a single plausible decoy password matching the structural profile."""
    chars = list(password)
    length = len(chars)

    # Strategy 1: Mutate characters while keeping structural shape
    sub_count = max(1, length // 4)
    csprng = random.SystemRandom()
    mutation_indices = csprng.sample(range(length), sub_count)

    for idx in mutation_indices:
        orig = chars[idx]
        if orig.islower():
            chars[idx] = secrets.choice(string.ascii_lowercase)
        elif orig.isupper():
            chars[idx] = secrets.choice(string.ascii_uppercase)
        elif orig.isdigit():
            chars[idx] = secrets.choice(string.digits)
        else:
            chars[idx] = secrets.choice("!@#$%^&*-_+=?")

    decoy = "".join(chars)
    # Ensure decoy is not identical to original
    if decoy == password:
        if decoy[-1].isdigit():
            decoy = decoy[:-1] + str((int(decoy[-1]) + secrets.choice([1, 2, 3])) % 10)
        else:
            decoy = decoy + secrets.choice("123!")
    return decoy


def generate_honeywords(
    real_password: str,
    count: int = 5,
    custom_words: list[str] | None = None,
) -> HoneywordSet:
    """Generate k-1 decoy honeywords for a real password matching entropy and length.
    
    The real password is inserted into a random position among the decoys.
    """
    if count < 2:
        count = 2

    length, flags = _analyze_composition(real_password)
    pool_size = flags.character_pool_size
    entropy_bits = length * math.log2(pool_size) if pool_size > 1 else 0.0

    decoys: set[str] = set()
    attempts = 0

    while len(decoys) < (count - 1) and attempts < 100:
        attempts += 1
        decoy = _generate_plausible_decoy(real_password, flags)
        if decoy != real_password:
            decoys.add(decoy)

    # Fallback padding if unique mutations run out
    while len(decoys) < (count - 1):
        suffix = secrets.token_hex(2)
        decoys.add(f"{real_password[:max(1, length - 4)]}{suffix}")

    decoy_list = list(decoys)
    # Pick a secure random slot for the real password
    real_index = secrets.randbelow(count)
    honeywords = decoy_list[:real_index] + [real_password] + decoy_list[real_index:]

    canary_tag = f"cj-canary-{uuid.uuid4().hex[:8]}"

    return HoneywordSet(
        real_password=real_password,
        honeywords=honeywords,
        real_index=real_index,
        decoy_count=count - 1,
        avg_entropy_bits=entropy_bits,
        canary_tag=canary_tag,
    )


def inject_honey_hash(
    target_type: str,
    identity: str,
    hash_val: str,
    canary_tag: str | None = None,
) -> str:
    """Format a canary credential record for injection into credential stores."""
    canary = canary_tag or f"cj-canary-{secrets.token_hex(4)}"
    fmt = target_type.lower()

    if fmt in ("shadow", "linux"):
        return f"{identity}:{hash_val}:19000:0:99999:7::: # {canary}"
    elif fmt in ("ntds", "windows", "activedirectory"):
        return f"{identity}:9999:aad3b435b51404eeaad3b435b51404ee:{hash_val}::: # {canary}"
    elif fmt in ("sql", "database"):
        return f"INSERT INTO users (username, password_hash, is_canary, canary_tag) VALUES ('{identity}', '{hash_val}', 1, '{canary}');"
    else:
        return f"{identity}:{hash_val}  # {canary}"


def verify_honeyword(
    input_password: str,
    honeyword_set: HoneywordSet,
) -> dict[str, Any]:
    """Verify an authentication attempt against a HoneywordSet.
    
    If the submitted password matches one of the decoys, an intruder has
    cracked or stolen the credential store — triggering a canary tripwire alarm!
    """
    if input_password == honeyword_set.real_password:
        return {
            "authenticated": True,
            "tripped_canary": False,
            "canary_tag": honeyword_set.canary_tag,
            "incident_level": "INFO",
            "message": "Valid primary credential authenticated.",
        }

    if input_password in honeyword_set.honeywords:
        return {
            "authenticated": False,
            "tripped_canary": True,
            "canary_tag": honeyword_set.canary_tag,
            "incident_level": "CRITICAL",
            "message": (
                f"🚨 CRITICAL SECURITY ALARM: Decoy honeyword used for canary '{honeyword_set.canary_tag}'! "
                "Database dump or unauthorized credential recovery detected."
            ),
        }

    return {
        "authenticated": False,
        "tripped_canary": False,
        "canary_tag": honeyword_set.canary_tag,
        "incident_level": "NOTICE",
        "message": "Invalid password provided.",
    }
