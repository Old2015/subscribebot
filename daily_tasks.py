import logging
from datetime import datetime
import config
import supabase_client
from aiogram import Bot

log = logging.getLogger(__name__)

async def run_daily_tasks(bot: Bot):
    """
    Каждый день:
    1. Уведомляем trial-пользователей, сколько осталось.
    2. Удаляем тех, у кого trial_end < now и нет подписки, subscription_end < now
    3. Уведомляем подписчиков, сколько осталось.
    """
    log.info("Running daily tasks...")

    # 1) Получить всех пользователей
    with supabase_client._get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users")
            rows = cur.fetchall()
            cols = [desc[0] for desc in cur.description]
            all_users = [dict(zip(cols, r)) for r in rows]

    now = datetime.now()

    for user in all_users:
        user_id = user["id"]
        tg_id = user["telegram_id"]
        trial_end = user.get("trial_end")
        sub_end = user.get("subscription_end")  # может быть None
        # 1) Trial active?
        if trial_end and trial_end > now:
            days_left = (trial_end - now).days
            try:
                await bot.send_message(
                    chat_id=tg_id,
                    text=f"У вас ещё активен триал, осталось {days_left} дней."
                )
            except Exception as e:
                log.error(f"Error sending trial info to user {tg_id}: {e}")
        # 2) Trial ended, no subscription => remove
        elif (trial_end and trial_end < now) and (not sub_end or sub_end < now):
            # удаляем
            try:
                await bot.ban_chat_member(
                    chat_id=config.PRIVATE_GROUP_ID,
                    user_id=tg_id
                )
                await bot.send_message(
                    tg_id,
                    text="Триал закончился, у вас нет подписки. Вы удалены из группы."
                )
            except Exception as e:
                log.error(f"Error removing user {tg_id}: {e}")
        # 3) subscription active => сообщаем сколько осталось
        elif sub_end and sub_end > now:
            sub_days_left = (sub_end - now).days
            try:
                await bot.send_message(
                    chat_id=tg_id,
                    text=f"Ваша подписка действует до {sub_end}. Осталось {sub_days_left} дней."
                )
            except Exception as e:
                log.error(f"Error sending sub info to user {tg_id}: {e}")

    log.info("Daily tasks completed.")