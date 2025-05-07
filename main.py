#!/usr/bin/env python3
"""Главный файл запуска Telegram-бота.
Обработка подписок, опрос TRC-20, ежедневные задачи и логирование.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from aiogram import Dispatcher
from apscheduler.schedulers.asyncio import AsyncIOScheduler

import logger_config
import config                          # ← токены, настройки, make_bot()
from config import CHECK_INTERVAL_MIN, DAILY_ANALYSIS_TIME, make_bot

import supabase_client
from join_router import join_router
from start import start_router
from subscription import subscription_router
from tron_service import (
    poll_trc20_transactions,
    print_master_balance_at_start,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ---------------------------------------------------------------------------

async def scheduled_tron_poll(bot):
    """Опрос входящих TRC-20 транзакций с обработкой ошибок."""
    try:
        await poll_trc20_transactions(bot)
    except Exception:
        log.exception("scheduled_tron_poll crashed")
        if getattr(config, "ADMIN_CHAT_ID", None):
            try:
                await bot.send_message(
                    config.ADMIN_CHAT_ID,
                    "❗️ Tron poll task crashed, см. логи."
                )
            except Exception:
                log.exception("Cannot notify admin about crash")


async def scheduled_daily_job(bot):
    """Ежедневные задачи + отчёт администратору."""
    from daily_tasks import run_daily_tasks
    from admin_report import send_admin_report
    await run_daily_tasks(bot)
    await send_admin_report(bot)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

async def main() -> None:
    # 1. Логирование
    logger_config.setup_logger()
    log.info("Bot is starting…")

    # 2. Проверяем структуру БД
    supabase_client.check_db_structure()

    # 3. Создаём экземпляр Bot c «правильным» SSL-контекстом
    bot = make_bot()
    config.bot = bot        # <<< ключевая строка ─ остальные модули используют config.bot

    # 4. Диспетчер Aiogram
    dp = Dispatcher()
    dp.include_router(start_router)
    dp.include_router(subscription_router)
    dp.include_router(join_router)

    # 5. Печатаем баланс master-адреса
    await print_master_balance_at_start(bot)

    # 6. Планировщик APScheduler
    scheduler = AsyncIOScheduler()

    scheduler.add_job(
        scheduled_tron_poll,
        "interval",
        minutes=CHECK_INTERVAL_MIN,
        args=[bot],
    )

    hour, minute = map(int, DAILY_ANALYSIS_TIME.split(":"))
    scheduler.add_job(
        scheduled_daily_job,
        "cron",
        hour=hour,
        minute=minute,
        args=[bot],
    )

    scheduler.start()
    log.info("Scheduler started; Dispatcher polling…")

    # 7. Запуск бота; по Ctrl-C корректно закрываем сессию
    try:
        await dp.start_polling(bot, skip_updates=True)
    finally:
        await bot.session.close()
        log.info("Bot session closed, bye.")


if __name__ == "__main__":
    asyncio.run(main())