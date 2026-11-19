"""Telegram bot: forward or paste a suspicious SMS, get a verdict.

Setup:
  1. Create a bot with @BotFather and copy its token.
  2. export TELEGRAM_BOT_TOKEN="123456:ABC..."   (Windows: set TELEGRAM_BOT_TOKEN=...)
  3. python bot.py
"""

from __future__ import annotations

import logging
import os

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from src.detector.model import ScamDetector

logging.basicConfig(level=logging.INFO)
detector = ScamDetector.load()

WELCOME = (
    "Привет! Перешли мне подозрительное SMS или вставь его текст — "
    "я скажу, похоже ли это на мошенничество, и объясню почему."
)


def format_verdict(text: str) -> str:
    v = detector.check(text[:1000])
    icon = "🚨" if v.is_scam else "✅"
    lines = [f"{icon} {v.label}", f"Риск: {v.score * 100:.0f}%"]
    if v.flags:
        lines.append("")
        lines.extend(f"• {f.reason}" for f in v.flags)
    if v.is_scam:
        lines.append("\nНе переходите по ссылкам и никому не сообщайте коды из SMS.")
    return "\n".join(lines)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(WELCOME)


async def check(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(format_verdict(update.message.text))


def main() -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("Set the TELEGRAM_BOT_TOKEN environment variable first (see the docstring).")
    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check))
    app.run_polling()


if __name__ == "__main__":
    main()
