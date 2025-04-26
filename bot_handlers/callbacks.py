# bot_handlers/callbacks.py
from aiogram import types

async def process_callback(call: types.CallbackQuery):
    """
    Обработка нажатий inline-кнопок (callback_data).
    """
    data = call.data
    if data.startswith("something"):
        # ...
        await call.answer("Вы нажали кнопку!")
    else:
        await call.answer("Неизвестная команда.")
