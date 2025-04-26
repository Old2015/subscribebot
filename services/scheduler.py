# services/scheduler.py
import asyncio
import os
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from services.tron_service import poll_tron_transactions
from services.supabase_client import reset_deposit_address, get_user_by_telegram_id, ...
from bot_handlers.daily_tasks import daily_check
from bot_handlers.admin_report import send_daily_report
from config import CHECK_INTERVAL_MIN, DAILY_ANALYSIS_TIME, bot

async def poll_trc20():
    """
    Запускается каждые CHECK_INTERVAL_MIN минут
    1) Получаем события из Tron
    2) Сопоставляем с deposit_address
    3) Начисляем подписку, etc.
    """
    tx_list = poll_tron_transactions()  # вернёт список транзакций
    for tx in tx_list:
        # tx = { 'to':..., 'amount':..., 'hash':..., 'timestamp':... }
        # 1) Найти user по deposit_address == tx['to']
        # 2) Если user найден, проверить не просрочен ли адрес
        # 3) Рассчитать дни => subscription_end
        # 4) Добавить запись в payments
        # 5) reset_deposit_address(user_id)
        # 6) Пригласить в группу
        ...
    # Также можно проверить, у кого более 24ч назад выдан address, но не поступили платежи -> сбросить

async def daily_job():
    """
    Запускается раз в сутки в DAILY_ANALYSIS_TIME
    1) Выполняем daily_check
    2) Отправляем админ-отчёт
    """
    await daily_check(bot)  # чистим просроченных
    await send_daily_report(bot)

def setup_scheduler(loop):
    scheduler = AsyncIOScheduler(event_loop=loop)

    # 1) Поллинг каждые N минут
    scheduler.add_job(poll_trc20, "interval", minutes=CHECK_INTERVAL_MIN)

    # 2) daily job
    # DAILY_ANALYSIS_TIME='09:00'
    hour, minute = map(int, DAILY_ANALYSIS_TIME.split(':'))
    scheduler.add_job(daily_job, "cron", hour=hour, minute=minute)

    scheduler.start()
