# start.py
from aiogram import Router, types
from aiogram.filters import Command
import logging
import supabase_client
import config

log = logging.getLogger(__name__)
start_router = Router()  # создаём роутер для команды /start

@start_router.message(Command("start"))
async def cmd_start(message: types.Message):
    telegram_id = message.from_user.id
    log.info(f"/start from user {telegram_id}")

    # Пример проверки пользователя
    # user = supabase_client.get_user_by_telegram_id(telegram_id)
    # if not user:
    #     supabase_client.create_user(...)
    #     ...
    
    await message.answer("Привет! Это новая версия бота на Aiogram 3.\nПопробуйте /status или /subscribe")