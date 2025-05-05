#!/usr/bin/env python3
"""Главный файл запуска Telegram‑бота.
Обработка подписок, опрос TRC‑20, ежедневные задачи и логирование.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from aiogram import Dispatcher
from apscheduler.schedulers.asyncio import AsyncIOScheduler

import logger_config
import config  # полный модуль конфигурации, нужен для ADMIN_CHAT_ID и др.
from config import bot, CHECK_INTERVAL_MIN, DAILY_ANALYSIS_TIME

import supabase_client
from start import start_router
from subscription import subscription_router
from tron_service import poll_trc20_transactions, print_master_balance_at_start

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ---------------------------------------------------------------------------

def _log_freeze_summary() -> None:
    """Логирует общую сумму и количество пока неразмороженных TRX."""
    resp_sum = (
        supabase_client.table("freeze_records")
        .select("*")
        .eq("unfrozen", False)
        .execute()
    )

    if not resp_sum.data:
        log.info("Осталось в заморозке 0.00 TRX на 0 адресах.")
        return

    records = resp_sum.data
    total_sun = sum(r["freeze_amount_sun"] for r in records)
    total_trx = total_sun / 1_000_000
    cnt = len(records)
    log.info("Осталось в заморозке %.2f TRX на %d адресах.", total_trx, cnt)


async def scheduled_daily_unfreeze() -> None:
    """Размораживает TRX, замороженные больше трёх суток."""
    log.info("Start daily unfreeze check…")

    cutoff_time = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()

    resp = (
        supabase_client.table("freeze_records")
        .select("*")
        .eq("unfrozen", False)
        .lt("frozen_at", cutoff_time)
        .execute()
    )

    records = resp.data or []
    if not records:
        log.info("No freeze records to unfreeze today.")
        _log_freeze_summary()
        return

    unfrozen_ok = 0
    unfrozen_trx_sun = 0

    for rec in records:
        freeze_id = rec["id"]
        deposit_addr = rec["deposit_address"]
        freeze_amt_sun = rec["freeze_amount_sun"]
        resource = rec["resource"]

        # Пытаемся разморозить
        unfreeze_tx = unfreeze_balance_v2(
            owner_address=MASTER_ADDR,  # предполагается, что импортированы где‑то сверху
            receiver_address=deposit_addr,
            resource=resource,
        )
        if unfreeze_tx:
            record_unfreeze_in_db(freeze_id, unfreeze_tx)
            log.info("Deposit=%s unfreeze successful ⇒ tx=%s", deposit_addr, unfreeze_tx)
            unfrozen_ok += 1
            unfrozen_trx_sun += freeze_amt_sun
        else:
            log.warning("Unfreeze failed deposit=%s, freeze_id=%s", deposit_addr, freeze_id)

    if unfrozen_ok:
        unfrozen_trx = unfrozen_trx_sun / 1_000_000
        log.info("Разморожено %.2f TRX на %d адресах.", unfrozen_trx, unfrozen_ok)

    _log_freeze_summary()
    log.info("Daily unfreeze check done.")


# ---------------------------------------------------------------------------
# ПЕРИОДИЧЕСКИЙ ОПРОС СЕТИ TRON
# ---------------------------------------------------------------------------

async def scheduled_tron_poll(bot, cfg):
    """Опрос входящих TRC‑20 транзакций с обработкой ошибок."""
    try:
        await poll_trc20_transactions(bot)
    except Exception:  # pylint: disable=broad-except
        log.exception("scheduled_tron_poll crashed")
        # Уведомление администратора, если указан чат‑ID
        if getattr(cfg, "ADMIN_CHAT_ID", None):
            try:
                await bot.send_message(cfg.ADMIN_CHAT_ID, "❗️ Tron poll task crashed, см. логи.")
            except Exception:  # pylint: disable=broad-except
                log.exception("Failed to notify admin about crash")


# ---------------------------------------------------------------------------
# ДНЕВНЫЕ ЗАДАЧИ
# ---------------------------------------------------------------------------

async def scheduled_daily_job() -> None:
    """Запуск ежедневных задач и отчёта администратору."""
    from daily_tasks import run_daily_tasks  # локальный импорт, чтобы избежать циклов
    from admin_report import send_admin_report

    await run_daily_tasks(bot)
    await send_admin_report(bot)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

async def main() -> None:
    # 1. Настройка логирования
    logger_config.setup_logger()
    log.info("Bot is starting…")

    # 2. Проверяем структуру БД
    supabase_client.check_db_structure()

    # 3. Диспетчер Aiogram
    dp = Dispatcher()
    dp.include_router(start_router)
    dp.include_router(subscription_router)

    # 4. Печатаем баланс мастер‑адреса при старте
    await print_master_balance_at_start(bot)

    # 5. Планировщик задач (APScheduler)
    scheduler = AsyncIOScheduler()
    scheduler.add_job(  # опрос TRON
        scheduled_tron_poll,
        "interval",
        minutes=CHECK_INTERVAL_MIN,
        args=[bot, config],  # ← передаём и bot, и весь модуль config
    )

    hour, minute = map(int, DAILY_ANALYSIS_TIME.split(":"))
    scheduler.add_job(scheduled_daily_job, "cron", hour=hour, minute=minute)
    # scheduler.add_job(scheduled_daily_unfreeze, "cron", hour=hour, minute=minute) разморозку не используем
    scheduler.start()

    log.info("Dispatcher setup complete. Starting polling.")

    # Запускаем бота (skip_updates=True, чтобы игнорировать старые события)
    await dp.start_polling(bot, skip_updates=True)


if __name__ == "__main__":
    asyncio.run(main())
