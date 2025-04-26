from aiogram import types
import config
import supabase_client

async def cmd_start(message: types.Message):
    telegram_id = message.from_user.id
    username = message.from_user.username or ""

    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if user:
        await message.answer("Добро пожаловать, вы уже зарегистрированы!")
    else:
        # Создаём запись в БД
        row = supabase_client.create_user(telegram_id, username)
        user_id = row[0]  # допустим, row=(id, telegram_id)
        # Даём триал
        supabase_client.update_trial_info(user_id, config.FREE_TRIAL_DAYS)
        # Добавляем в группу
        # В aiogram v2.x нет прямого add_chat_member, можно bot.invite_link
        # или unbanChatMember...
        await config.bot.send_message(telegram_id, 
            f"Вам предоставлен триал на {config.FREE_TRIAL_DAYS} дней.")
        # Или приглашение:
        # await config.bot.unban_chat_member(config.PRIVATE_GROUP_ID, telegram_id)
        # (пользователь сам зайдет по ссылке) 
        # или высылаем invite link

    await message.answer("Используйте команды /status и /subscribe для подписки.")
