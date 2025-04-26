# bot_handlers/daily_tasks.py
from aiogram import Bot
from services.supabase_client import get_users_for_trial_expiration, get_users_for_subscription_expiration
from config import PRIVATE_GROUP_ID

async def daily_check(bot: Bot):
    """
    Запускается планировщиком раз в день (например, 09:00).
    1) Удаляем тех, у кого trial_end < now() и нет подписки
    2) Удаляем тех, у кого subscription_end < now()
    3) Предупреждаем за 3 дня
    """
    # Удаляем пользователей по trial
    trial_expired_users = get_users_for_trial_expiration()
    for user in trial_expired_users:
        # Удалить из группы
        await bot.kick_chat_member(PRIVATE_GROUP_ID, user['telegram_id'])
        # Отправить личное сообщение
        try:
            await bot.send_message(
                user['telegram_id'],
                "Бесплатный период закончился, и у вас нет активной подписки. Вы были удалены из группы."
            )
        except:
            pass

    # Удаляем просроченных подписчиков
    expired_users = get_users_for_subscription_expiration()
    for user in expired_users:
        await bot.kick_chat_member(PRIVATE_GROUP_ID, user['telegram_id'])
        try:
            await bot.send_message(
                user['telegram_id'],
                "Ваша платная подписка закончилась. Вы удалены из группы."
            )
        except:
            pass

    # Другие проверки (предупреждение за 3 дня и т.д.)
    # ...
