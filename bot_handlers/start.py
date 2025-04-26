# bot_handlers/start.py
from aiogram import types
from aiogram.dispatcher import FSMContext
from services.supabase_client import get_user_by_telegram_id, create_user, update_trial_info
from services.utils import now_utc
from config import FREE_TRIAL_DAYS, PRIVATE_GROUP_ID, bot

async def cmd_start(message: types.Message, state: FSMContext):
    """
    Handler for /start command.
    - Checks if user exists in DB
    - If new -> create user, provide free trial if not used
    - Otherwise, greet and show subscription status
    """
    telegram_id = message.from_user.id

    user = get_user_by_telegram_id(telegram_id)
    if not user:
        # Create new user with trial
        user = create_user(telegram_id, message.from_user.username)
        # Update trial info - set trial_end = now + FREE_TRIAL_DAYS
        update_trial_info(user['id'], FREE_TRIAL_DAYS)
        await bot.add_chat_member(chat_id=PRIVATE_GROUP_ID, user_id=telegram_id)
        await message.answer(
            "Добро пожаловать! Вам предоставлен бесплатный триал на "
            f"{FREE_TRIAL_DAYS} дней.\n"
            "Нажмите «СтатусПодписки» или «ОформитьПодписку» для дальнейших действий."
        )
    else:
        # If existing user, just greet
        # Could check if trial is still available, etc.
        await message.answer(
            "С возвращением!\n"
            "Нажмите «СтатусПодписки» или «ОформитьПодписку»."
        )
