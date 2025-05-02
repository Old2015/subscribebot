#!/usr/bin/env python3
import asyncio
import logging
from aiogram import Dispatcher
import logger_config
from datetime import datetime, timedelta
from config import bot, CHECK_INTERVAL_MIN, DAILY_ANALYSIS_TIME
import supabase_client
from start import start_router
from subscription import subscription_router
from tron_service import poll_trc20_transactions, print_master_balance_at_start
from apscheduler.schedulers.asyncio import AsyncIOScheduler

def _log_freeze_summary():
    """Считает общее кол-во замороженных TRX и кол-во таких записей, выводит в лог."""
    resp_sum = supabase_client.table("freeze_records").select("*")\
        .eq("unfrozen", False)\
        .execute()

    if not resp_sum.data:
        log.info("Осталось в заморозке 0.00 TRX на 0 адресах.")
        return

    records = resp_sum.data
    total_sun = sum(r["freeze_amount_sun"] for r in records)
    total_trx = total_sun / 1_000_000
    cnt = len(records)
    log.info(f"Осталось в заморозке {total_trx:.2f} TRX на {cnt} адресах.")

async def scheduled_daily_unfreeze():
    log.info("Start daily unfreeze check...")

    cutoff_time = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()

    # Берём все незамороженные записи, которым > 3 дней
    resp = supabase_client.table("freeze_records").select("*")\
        .eq("unfrozen", False)\
        .lt("frozen_at", cutoff_time)\
        .execute()

    records = resp.data or []
    if not records:
        log.info("No freeze records to unfreeze today.")
        # Даже если ничего не разморозили, вывести сводку о том, сколько всего ещё заморожено
        _log_freeze_summary()
        return

    unfrozen_ok = 0
    unfrozen_trx_sun = 0

    for rec in records:
        freeze_id = rec["id"]
        deposit_addr = rec["deposit_address"]
        freeze_amt_sun = rec["freeze_amount_sun"]  # в sun
        resource = rec["resource"]

        # Пытаемся разморозить
        unfreeze_tx = unfreeze_balance_v2(
            owner_address=MASTER_ADDR,
            receiver_address=deposit_addr,
            resource=resource
        )
        if unfreeze_tx:
            record_unfreeze_in_db(freeze_id, unfreeze_tx)
            log.info(f"Deposit={deposit_addr} unfreeze successful => tx={unfreeze_tx}")

            unfrozen_ok += 1
            unfrozen_trx_sun += freeze_amt_sun
        else:
            log.warning(f"Unfreeze failed deposit={deposit_addr}, freeze_id={freeze_id}")

    # После цикла выводим сводку
    if unfrozen_ok > 0:
        unfrozen_trx = unfrozen_trx_sun / 1_000_000  # переводим sun -> TRX
        log.info(
            f"Разморожено {unfrozen_trx:.2f} TRX на {unfrozen_ok} адресах."
        )
    
    # А также хотим вывести, сколько всего осталось заморожено
    _log_freeze_summary()

    log.info("Daily unfreeze check done.")


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
    scheduler.add_job(scheduled_daily_unfreeze, "cron", hour=hour, minute=minute)
    scheduler.start()

    logging.info("Dispatcher setup complete. Starting polling.")

    # ВАЖНО: skip_updates=True, чтобы бот пропустил старые нажатия/сообщения
    await dp.start_polling(bot, skip_updates=True)

if __name__ == "__main__":
    asyncio.run(main())