#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# main.py

import asyncio
import logging
from aiogram import Dispatcher
from config import bot
import logger_config
import supabase_client
from daily_tasks import run_daily_tasks
from admin_report import send_admin_report
from start import start_router
from subscription import subscription_router
from tron_service import poll_trc20_transactions
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from config import CHECK_INTERVAL_MIN, DAILY_ANALYSIS_TIME


async def scheduled_tron_poll():
    """Вызывается каждые CHECK_INTERVAL_MIN минут для опроса Tron-сети."""
    await poll_trc20_transactions()


async def scheduled_daily_job():
    """Вызывается в DAILY_ANALYSIS_TIME для ежедневных задач."""
    # run daily tasks
    await run_daily_tasks(bot)
    # send admin report
    await send_admin_report(bot)


async def main():
    # 1) Настройка логгера
    logger_config.setup_logger()
    logging.info("Bot is starting...")

    # 2) Проверка структуры БД
    supabase_client.check_db_structure()

    # 3) Создаём Dispatcher
    dp = Dispatcher()

    # Подключаем роутеры
    dp.include_router(start_router)
    dp.include_router(subscription_router)

    # 4) Настраиваем APScheduler
    scheduler = AsyncIOScheduler()
    # - каждые N минут опрашиваем Tron
    scheduler.add_job(scheduled_tron_poll, "interval", minutes=CHECK_INTERVAL_MIN)

    # - ежедневная задача (ежедневные проверки + отчёт)
    hour, minute = map(int, DAILY_ANALYSIS_TIME.split(':'))
    scheduler.add_job(scheduled_daily_job, "cron", hour=hour, minute=minute)

    scheduler.start()

    logging.info("Dispatcher setup complete. Starting polling.")
    # 5) Запуск бота
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())