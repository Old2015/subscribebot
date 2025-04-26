# start.py
from aiogram import types
import logging

log = logging.getLogger(__name__)

def register_handlers(dp):
    @dp.message_handler(commands=["start"])
    async def cmd_start(message: types.Message):
        log.info(f"User {message.from_user.id} invoked /start")
        await message.answer("Привет, это /start (демо)")