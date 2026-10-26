"""Local configuration from environment variables. Secrets stay out of git."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AppConfig:
    reports_dir: Path
    telegram_bot_token: str | None
    telegram_chat_id: str | None
    telegram_enabled: bool
    ai_api_key: str | None
    ai_api_base: str | None
    ai_model: str
    ai_enabled: bool
    passive_dns_api_url: str | None

    @classmethod
    def load(cls, reports_dir: Path) -> "AppConfig":
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip() or None
        chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip() or None
        ai_key = os.environ.get("INFINITYX_AI_API_KEY", "").strip() or None
        ai_base = os.environ.get("INFINITYX_AI_API_BASE", "").strip() or None
        passive = os.environ.get("INFINITYX_PASSIVE_DNS_URL", "").strip() or None
        telegram_on = os.environ.get("INFINITYX_TELEGRAM_ALERTS", "").strip().lower() in {"1", "true", "yes"}
        ai_on = os.environ.get("INFINITYX_AI_ENABLED", "").strip().lower() in {"1", "true", "yes"}
        model = os.environ.get("INFINITYX_AI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
        return cls(
            reports_dir=reports_dir,
            telegram_bot_token=token,
            telegram_chat_id=chat,
            telegram_enabled=telegram_on and bool(token and chat),
            ai_api_key=ai_key,
            ai_api_base=ai_base,
            ai_model=model,
            ai_enabled=ai_on and bool(ai_key and ai_base),
            passive_dns_api_url=passive,
        )
