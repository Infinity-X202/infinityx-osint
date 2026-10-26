"""Optional Telegram notifications. Disabled until configured."""

from __future__ import annotations

import json
from typing import Any

import requests

from infinityx.config import AppConfig
from infinityx.intel_models import NotificationResult
from infinityx.safety import clean_text


def send_scan_alert(config: AppConfig, message: str) -> NotificationResult:
    """Send one message when alerts are enabled and credentials exist."""
    if not config.telegram_enabled or not config.telegram_bot_token or not config.telegram_chat_id:
        return NotificationResult(False, "Telegram alerts are disabled or not configured.")
    text = clean_text(message, 3500)
    url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"
    try:
        response = requests.post(
            url,
            json={"chat_id": config.telegram_chat_id, "text": text},
            timeout=20,
            trust_env=False,
        )
    except requests.RequestException as exc:
        return NotificationResult(False, f"Telegram request failed: {exc}")
    if response.status_code != 200:
        return NotificationResult(False, f"Telegram API returned {response.status_code}.")
    try:
        payload = response.json()
    except json.JSONDecodeError:
        return NotificationResult(False, "Telegram returned non-JSON.")
    if not payload.get("ok"):
        return NotificationResult(False, "Telegram API reported failure.")
    message_id = str(payload.get("result", {}).get("message_id", ""))
    return NotificationResult(True, "Delivered.", message_id or None)


def build_change_alert(domain: str, comparison: dict[str, Any] | None, audit_rows: list[dict[str, Any]]) -> str:
    """Short alert text without secrets."""
    lines = [f"InfinityX scan update for {domain}"]
    if comparison:
        for section in comparison.get("sections") or []:
            if section.get("status") in {"added", "removed", "changed"}:
                lines.append(f"{section['name']}: {section['status']}")
    for row in audit_rows:
        if row.get("severity") in {"MEDIUM", "HIGH", "CRITICAL"}:
            lines.append(f"{row['title']}: {row['severity']}")
    if len(lines) == 1:
        lines.append("No configured alert condition matched.")
    return "\n".join(lines)


def send_test_notification(config: AppConfig) -> NotificationResult:
    return send_scan_alert(config, "InfinityX test notification. Alerts are configured.")
