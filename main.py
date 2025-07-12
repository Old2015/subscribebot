#!/usr/bin/env python3
"""Главный файл запуска Telegram-бота.
Обработка подписок, опрос TRC-20, ежедневные задачи и логирование.
"""

import asyncio                           # асинхронный цикл событий
import logging                          # стандартный логгер
from datetime import datetime, timedelta, timezone   # работа с датами

from aiogram import Dispatcher                       # диспетчер бота
from apscheduler.schedulers.asyncio import AsyncIOScheduler  # планировщик задач

import logger_config                   # модуль настройки логирования
import config                          # ← токены, настройки, make_bot()
from config import CHECK_INTERVAL_MIN, DAILY_ANALYSIS_TIME, make_bot

import supabase_client                 # работа с базой Supabase
from join_router import join_router    # обработка запросов на вход в группу
from start import start_router         # команда /start
from subscription import subscription_router  # команды меню подписки
from tron_service import (
    poll_trc20_transactions,      # функция опроса депозитов
    print_master_balance_at_start, # печать баланса при старте
)

log = logging.getLogger(__name__)      # общий логгер модуля


# ---------------------------------------------------------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ---------------------------------------------------------------------------

async def scheduled_tron_poll(bot):
    """Опрос входящих TRC-20 транзакций с обработкой ошибок."""
    # Эта функция вызывается планировщиком каждые N минут
    try:
        await poll_trc20_transactions(bot)   # основной опрос депозитов
    except Exception:
        log.exception("scheduled_tron_poll crashed")  # фиксируем исключение
        if getattr(config, "ADMIN_CHAT_ID", None):
            try:
                await bot.send_message(
                    config.ADMIN_CHAT_ID,
                    "❗️ Tron poll task crashed, см. логи."  # уведомляем админа
                )
            except Exception:
                log.exception("Cannot notify admin about crash")


async def scheduled_daily_job(bot):
    """Ежедневные задачи + отчёт администратору."""
    # Тут выполняются периодические напоминания и отправляется статистика
    from daily_tasks import run_daily_tasks
    from admin_report import send_admin_report
    stats, kicked = await run_daily_tasks(bot)
    await send_admin_report(bot, kicked)


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
    bot = make_bot()                     # создаём экземпляр Bot с SSL
    config.bot = bot        # <<< ключевая строка ─ остальные модули используют config.bot

    # 4. Диспетчер Aiogram
    dp = Dispatcher()                    # основной диспетчер aiogram
    dp.include_router(start_router)      # регистрируем роутеры
    dp.include_router(subscription_router)
    dp.include_router(join_router)

    # 5. Печатаем баланс master-адреса
    await print_master_balance_at_start(bot)

    # 6. Планировщик APScheduler
    scheduler = AsyncIOScheduler()       # планировщик фоновых задач

    scheduler.add_job(
        scheduled_tron_poll,
        "interval",
        minutes=CHECK_INTERVAL_MIN,
        args=[bot],                        # передаём экземпляр бота
    )

    hour, minute = map(int, DAILY_ANALYSIS_TIME.split(":"))
    scheduler.add_job(
        scheduled_daily_job,
        "cron",
        hour=hour,
        minute=minute,
        args=[bot],                        # чтобы задачи имели доступ к боту
    )

    scheduler.start()                    # запускаем планировщик
    log.info("Scheduler started; Dispatcher polling…")

    # 7. Запуск бота; по Ctrl-C корректно закрываем сессию
    try:
        await dp.start_polling(bot, skip_updates=True)   # основная точка входа
    finally:
        await bot.session.close()        # корректно завершаем aiohttp-сессию
        log.info("Bot session closed, bye.")


if __name__ == "__main__":
    asyncio.run(main())                  # точка входа при запуске скрипта
