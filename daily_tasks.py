import config
import supabase_client
from aiogram import Bot

async def daily_check(bot: Bot):
    """
    Удаляем пользователей, у кого trial_end < now и subscription_end < now,
    а также пользователей с просроченной подпиской.
    """
    # 1) trial
    expired_trial = supabase_client.get_users_for_trial_expiration()
    for user in expired_trial:
        tg_id = user['telegram_id']
        # Удаляем из группы
        await bot.ban_chat_member(config.PRIVATE_GROUP_ID, tg_id)
        await bot.send_message(tg_id, "Ваш бесплатный период истёк.")

    # 2) подписка
    expired_sub = supabase_client.get_users_for_subscription_expiration()
    for user in expired_sub:
        tg_id = user['telegram_id']
        await bot.ban_chat_member(config.PRIVATE_GROUP_ID, tg_id)
        await bot.send_message(tg_id, "Срок вашей платной подписки истёк.")
