"""SIEM & ChatOps webhook dispatching for real-time security alerts."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
from typing import Any
import urllib.request
import urllib.error

from crackerjack.models import WebhookNotification


def build_generic_payload(event_type: str, data: dict[str, Any]) -> dict[str, Any]:
    """Build a standard JSON SIEM alert payload."""
    return {
        "source": "crackerjack",
        "event_type": event_type,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "data": data,
    }


def build_slack_payload(event_type: str, data: dict[str, Any]) -> dict[str, Any]:
    """Format payload as a Slack Block Kit message."""
    title_map = {
        "audit_completed": "🛡️ *Crackerjack Compliance Audit Completed*",
        "secret_detected": "🚨 *Crackerjack Secret Scan Alert: Leaked Credentials*",
        "honeyword_tripped": "🔥 *CRITICAL INCIDENT: Deception Honeyword Tripped!*",
    }
    title = title_map.get(event_type, f"📢 *Crackerjack Alert: {event_type}*")

    fields = []
    if "total_evaluated" in data:
        fields.append({"type": "mrkdwn", "text": f"*Evaluated Accounts:* {data.get('total_evaluated', 0)}"})
    if "total_cracked_or_weak" in data:
        fields.append({"type": "mrkdwn", "text": f"*Compromised / Weak:* {data.get('total_cracked_or_weak', 0)}"})
    if "overall_score" in data:
        fields.append({"type": "mrkdwn", "text": f"*Health Score:* {data.get('overall_score', 0)}/100 ({data.get('overall_grade', 'N/A')})"})
    if "findings_count" in data:
        fields.append({"type": "mrkdwn", "text": f"*Secrets Detected:* {data.get('findings_count', 0)}"})
    if "tripped_credential" in data:
        fields.append({"type": "mrkdwn", "text": f"*Tripped Canary:* `{data.get('tripped_credential')}`"})

    blocks = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": title},
        }
    ]
    if fields:
        blocks.append({
            "type": "section",
            "fields": fields,
        })

    return {"text": title, "blocks": blocks}


def build_teams_payload(event_type: str, data: dict[str, Any]) -> dict[str, Any]:
    """Format payload as a Microsoft Teams MessageCard."""
    title_map = {
        "audit_completed": "Crackerjack Compliance Audit Completed",
        "secret_detected": "Crackerjack Alert: Leaked Credentials",
        "honeyword_tripped": "CRITICAL INCIDENT: Honeyword Tripped",
    }
    title = title_map.get(event_type, f"Crackerjack Alert: {event_type}")

    facts = []
    for k, v in data.items():
        if isinstance(v, (int, str, float, bool)):
            facts.append({"name": str(k).replace("_", " ").title(), "value": str(v)})

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "E81123" if "tripped" in event_type or "secret" in event_type else "0078D7",
        "summary": title,
        "sections": [
            {
                "activityTitle": title,
                "activitySubtitle": f"Timestamp: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
                "facts": facts[:8],
                "markdown": True,
            }
        ],
    }


def dispatch_webhook(
    url: str,
    event_type: str,
    payload_data: dict[str, Any],
    format_type: str = "generic",
    secret: str | None = None,
    timeout: float = 5.0,
) -> WebhookNotification:
    """Dispatch an alert payload to a configured webhook endpoint."""
    if format_type.lower() == "slack":
        body_dict = build_slack_payload(event_type, payload_data)
    elif format_type.lower() == "teams":
        body_dict = build_teams_payload(event_type, payload_data)
    else:
        body_dict = build_generic_payload(event_type, payload_data)

    raw_body = json.dumps(body_dict, default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Crackerjack-Audit-Engine/3.3.0",
    }

    if secret:
        sig = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        headers["X-Crackerjack-Signature"] = f"sha256={sig}"

    req = urllib.request.Request(url, data=raw_body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            success = 200 <= status < 300
            return WebhookNotification(
                url=url,
                format_type=format_type,
                event_type=event_type,
                status_code=status,
                success=success,
                payload_preview=body_dict,
            )
    except urllib.error.HTTPError as err:
        return WebhookNotification(
            url=url,
            format_type=format_type,
            event_type=event_type,
            status_code=err.code,
            success=False,
            error_message=f"HTTP {err.code}: {err.reason}",
            payload_preview=body_dict,
        )
    except Exception as exc:
        return WebhookNotification(
            url=url,
            format_type=format_type,
            event_type=event_type,
            status_code=0,
            success=False,
            error_message=str(exc),
            payload_preview=body_dict,
        )
