#!/usr/bin/env python3
import asyncio
import logging
from aiogram import Dispatcher
import logger_config
from config import bot, CHECK_INTERVAL_MIN, DAILY_ANALYSIS_TIME
import supabase_client
from start import start_router
from subscription import subscription_router
from tron_service import poll_trc20_transactions, print_master_balance_at_start
from apscheduler.schedulers.asyncio import AsyncIOScheduler

async def scheduled_tron_poll():
    """Вызывается каждые CHECK_INTERVAL_MIN минут для опроса сети Tron."""
    await poll_trc20_transactions(bot)

async def scheduled_daily_job():
    """Вызывается в DAILY_ANALYSIS_TIME для ежедневных задач (чистим триал, шлём отчёт)."""
    from daily_tasks import run_daily_tasks
    from admin_report import send_admin_report
    await run_daily_tasks(bot)
    await send_admin_report(bot)

async def main():
    # 1) Настраиваем логгеры
    logger_config.setup_logger()
    logging.info("Bot is starting...")

    # 2) Проверяем структуру БД (таблицы users/payments)
    supabase_client.check_db_structure()

    # 3) Создаём диспетчер Aiogram 3.x
    dp = Dispatcher()

    # Подключаем роутеры
    dp.include_router(start_router)
    dp.include_router(subscription_router)

    # *** НОВОЕ: печатаем баланс мастер-адреса при старте ***
    await print_master_balance_at_start(bot)

    # 4) Поднимаем планировщик (APSсheduler)
    scheduler = AsyncIOScheduler()
    scheduler.add_job(scheduled_tron_poll, "interval", minutes=CHECK_INTERVAL_MIN)

    hour, minute = map(int, DAILY_ANALYSIS_TIME.split(":"))
    scheduler.add_job(scheduled_daily_job, "cron", hour=hour, minute=minute)
    scheduler.start()

    logging.info("Dispatcher setup complete. Starting polling.")

    # ВАЖНО: skip_updates=True, чтобы бот пропустил старые нажатия/сообщения
    await dp.start_polling(bot, skip_updates=True)

if __name__ == "__main__":
    asyncio.run(main())