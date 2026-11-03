"""Unit tests for SIEM, Slack, and Microsoft Teams webhook dispatching."""

from crackerjack.models import WebhookNotification
from crackerjack.webhooks import (
    build_generic_payload,
    build_slack_payload,
    build_teams_payload,
    dispatch_webhook,
)


def test_build_generic_payload():
    payload = build_generic_payload("audit_completed", {"overall_score": 88, "total_evaluated": 12})
    assert payload["source"] == "crackerjack"
    assert payload["event_type"] == "audit_completed"
    assert "timestamp" in payload
    assert payload["data"]["overall_score"] == 88


def test_build_slack_payload():
    data = {
        "total_evaluated": 50,
        "total_cracked_or_weak": 5,
        "overall_score": 85,
        "overall_grade": "A",
    }
    slack_msg = build_slack_payload("audit_completed", data)
    assert "text" in slack_msg
    assert "blocks" in slack_msg
    assert len(slack_msg["blocks"]) >= 2
    # Verify fields are formatted
    fields = slack_msg["blocks"][1]["fields"]
    field_texts = [f["text"] for f in fields]
    assert any("50" in t for t in field_texts)
    assert any("85/100" in t for t in field_texts)


def test_build_teams_payload():
    data = {
        "tripped_credential": "fake_honeyword123",
        "canary_tag": "cj-canary-test1234",
    }
    teams_msg = build_teams_payload("honeyword_tripped", data)
    assert teams_msg["@type"] == "MessageCard"
    assert teams_msg["themeColor"] == "E81123"  # Red for critical incidents
    assert len(teams_msg["sections"]) == 1
    facts = teams_msg["sections"][0]["facts"]
    assert any(f["name"] == "Canary Tag" and f["value"] == "cj-canary-test1234" for f in facts)


def test_dispatch_webhook_invalid_endpoint():
    # Test graceful error handling against an unresolvable URL
    res = dispatch_webhook(
        url="http://invalid-nonexistent-domain-crackerjack.test/webhook",
        event_type="audit_completed",
        payload_data={"test": True},
        format_type="generic",
        secret="test_secret_key",
        timeout=0.5,
    )
    assert isinstance(res, WebhookNotification)
    assert res.success is False
    assert res.event_type == "audit_completed"
    assert len(res.error_message) > 0
