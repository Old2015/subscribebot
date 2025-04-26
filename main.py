import asyncio
from aiogram import executor
from config import dp, bot
import start
import subscription

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from daily_tasks import daily_check
from admin_report import send_daily_report
import config

async def on_startup(_):
    print("Bot is online.")

    # Запустим планировщик (для поллинга TRC20 и ежедневных задач)
    loop = asyncio.get_event_loop()
    scheduler = AsyncIOScheduler(event_loop=loop)

    # Каждые config.CHECK_INTERVAL_MIN минут опрашиваем Tron
    # (Реализовать poll_trc20 в tron_service, сопоставлять транзакции и т.д.)
    # from tron_service import poll_trc20_transactions
    # async def poll_tron_job():
    #     ...
    # scheduler.add_job(poll_trc20_transactions, "interval", minutes=config.CHECK_INTERVAL_MIN)

    # Раз в сутки делаем чистку + отчет
    h, m = map(int, config.DAILY_ANALYSIS_TIME.split(':'))
    scheduler.add_job(daily_job, "cron", hour=h, minute=m)

    scheduler.start()

async def daily_job():
    await daily_check(bot)        # чистка просроченных
    await send_daily_report(bot)  # отчет в админ-чат

def register_handlers():
    dp.register_message_handler(start.cmd_start, commands=["start"], state="*")
    dp.register_message_handler(subscription.cmd_status, commands=["status"], state="*")
    dp.register_message_handler(subscription.cmd_subscribe, commands=["subscribe"], state="*")
    # Или если хотите ловить по кнопкам:
    # dp.register_message_handler(subscription.cmd_status, lambda msg: msg.text == "СтатусПодписки")

def main():
    register_handlers()
    executor.start_polling(dp, skip_updates=True, on_startup=on_startup)

if __name__ == "__main__":
    main()
