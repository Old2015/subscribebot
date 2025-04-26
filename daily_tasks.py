# daily_tasks.py
import logging
import config
import supabase_client
from aiogram import Bot

log = logging.getLogger(__name__)

async def run_daily_tasks(bot: Bot):
    """
    Вызывается раз в сутки.
    1) Проверяем и удаляем просроченные триалы
    2) Удаляем просроченные подписки
    3) Можно отправлять отчёт, и т.д.
    """
    log.info("Running daily tasks...")

    # Например:
    # expired_trial = supabase_client.get_users_for_trial_expiration()
    # for user in expired_trial:
    #     ...
    
    log.info("Daily tasks completed.")