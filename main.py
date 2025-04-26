# main.py
import asyncio
from aiogram import Dispatcher, executor
from bot_handlers.start import cmd_start
from bot_handlers.subscription import cmd_subscription_status, cmd_subscribe
from bot_handlers.callbacks import process_callback
from services.scheduler import setup_scheduler
from config import bot

dp = Dispatcher(bot)

def register_handlers(dp: Dispatcher):
    # Регистрация хендлеров команд
    dp.register_message_handler(cmd_start, commands=["start"], state="*")
    dp.register_message_handler(cmd_subscription_status, lambda msg: msg.text == "СтатусПодписки")
    dp.register_message_handler(cmd_subscribe, lambda msg: msg.text == "ОформитьПодписку")
    # Если используем callback_data
    dp.register_callback_query_handler(process_callback)

async def on_startup(_):
    loop = asyncio.get_event_loop()
    setup_scheduler(loop)

def main():
    register_handlers(dp)
    executor.start_polling(dp, skip_updates=True, on_startup=on_startup)

if __name__ == "__main__":
    main()
