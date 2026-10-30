"""HaveIBeenPwned (HIBP) k-anonymity breach auditor.

Queries the Pwned Passwords API using SHA-1 prefix hashing (k-anonymity model).
The plaintext password never leaves the local machine.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Optional

import httpx

from crackerjack.models import BreachInfo

HIBP_API_URL = "https://api.pwnedpasswords.com/range"
USER_AGENT = "Crackerjack-Audit-3.0 (+https://github.com/superrcoop/crackerjack)"

logger = logging.getLogger(__name__)


def compute_sha1_prefix_suffix(password: str) -> tuple[str, str]:
    """Compute the uppercase SHA-1 hash and split into 5-char prefix and 35-char suffix."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return sha1[:5], sha1[5:]


def check_password_breached(
    password: str,
    client: Optional[httpx.Client] = None,
    timeout: float = 4.0,
) -> BreachInfo:
    """Check a plaintext password against HIBP using the k-anonymity range API.

    Args:
        password: The plaintext password to inspect.
        client: Optional existing httpx.Client instance for connection pooling.
        timeout: Request timeout in seconds.

    Returns:
        BreachInfo object with breach count and status.
    """
    if not password:
        return BreachInfo(
            pwned=False,
            breach_count=0,
            status_message="Empty password provided.",
        )

    prefix, suffix = compute_sha1_prefix_suffix(password)
    url = f"{HIBP_API_URL}/{prefix}"
    headers = {
        "User-Agent": USER_AGENT,
        "Add-Padding": "true",  # Ensures constant response sizes for padding privacy
    }

    own_client = client is None
    http = client or httpx.Client(timeout=timeout)

    try:
        response = http.get(url, headers=headers)
        if response.status_code == 200:
            breach_count = 0
            for line in response.text.splitlines():
                if ":" in line:
                    res_suffix, res_count = line.strip().split(":", 1)
                    if res_suffix.upper() == suffix:
                        try:
                            breach_count = int(res_count)
                        except ValueError:
                            breach_count = 1
                        break

            if breach_count > 0:
                return BreachInfo(
                    pwned=True,
                    breach_count=breach_count,
                    sha1_prefix=prefix,
                    sha1_suffix=suffix,
                    offline=False,
                    status_message=f"CRITICAL: Found in {breach_count:,} known data breaches!",
                )
            return BreachInfo(
                pwned=False,
                breach_count=0,
                sha1_prefix=prefix,
                sha1_suffix=suffix,
                offline=False,
                status_message="SAFE: Not found in any known public data breaches.",
            )
        elif response.status_code == 429:
            return BreachInfo(
                pwned=False,
                breach_count=0,
                sha1_prefix=prefix,
                offline=True,
                status_message="Rate limit exceeded on HIBP API (HTTP 429).",
            )
        else:
            return BreachInfo(
                pwned=False,
                breach_count=0,
                sha1_prefix=prefix,
                offline=True,
                status_message=f"HIBP API returned unexpected status {response.status_code}.",
            )
    except (httpx.RequestError, httpx.TimeoutException, OSError) as exc:
        logger.debug("Network error checking HIBP: %s", exc)
        return BreachInfo(
            pwned=False,
            breach_count=0,
            sha1_prefix=prefix,
            offline=True,
            status_message=f"Offline / network unavailable ({exc.__class__.__name__}). HIBP check skipped.",
        )
    finally:
        if own_client:
            http.close()
