"""Tests for HaveIBeenPwned k-anonymity client."""

import httpx
from crackerjack.breach import (
    check_password_breached,
    compute_sha1_prefix_suffix,
)


def test_sha1_prefix_suffix():
    # SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    prefix, suffix = compute_sha1_prefix_suffix("password")
    assert prefix == "5BAA6"
    assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    assert len(prefix) == 5
    assert len(suffix) == 35


def test_check_password_breached_mock():
    # Mock httpx client response
    fake_prefix = "5BAA6"
    fake_suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    mock_body = f"00000000000000000000000000000000000:1\r\n{fake_suffix}:9876543\r\n"

    def custom_handler(request: httpx.Request) -> httpx.Response:
        if fake_prefix in str(request.url):
            return httpx.Response(200, text=mock_body)
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(custom_handler))
    info = check_password_breached("password", client=client)

    assert info.pwned is True
    assert info.breach_count == 9876543
    assert info.offline is False
    assert "CRITICAL" in info.status_message


def test_check_password_clean_mock():
    def custom_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="00000000000000000000000000000000000:1\r\n")

    client = httpx.Client(transport=httpx.MockTransport(custom_handler))
    info = check_password_breached("UnlikelyToEverBeBreached#2026_xyz!", client=client)

    assert info.pwned is False
    assert info.breach_count == 0
    assert "SAFE" in info.status_message


def test_check_password_offline():
    def custom_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Simulated DNS failure")

    client = httpx.Client(transport=httpx.MockTransport(custom_handler))
    info = check_password_breached("testpass", client=client)

    assert info.offline is True
    assert info.pwned is False
    assert "Offline" in info.status_message
