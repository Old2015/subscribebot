# admin_report.py
import logging
from aiogram import Bot
import config
import supabase_client

log = logging.getLogger(__name__)

async def send_admin_report(bot: Bot):
    """
    Пример: собираем статистику и шлём в админ-группу.
    """
    # data = supabase_client.get_admin_report_data()
    # text = ...
    # await bot.send_message(config.ADMIN_CHAT_ID, text)
    log.info("Sending admin report (placeholder).")
    # Пример заглушки:
    await bot.send_message(config.ADMIN_CHAT_ID, "Ежедневный отчёт (заглушка).")