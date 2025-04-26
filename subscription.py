# subscription.py
from aiogram import Router, types
from aiogram.filters import Command
import logging
import config
import supabase_client
import tron_service
import os

log = logging.getLogger(__name__)
subscription_router = Router()

@subscription_router.message(Command("status"))
async def cmd_status(message: types.Message):
    telegram_id = message.from_user.id
    log.info(f"/status from user {telegram_id}")
    # check subscription status from DB
    # ...
    await message.answer("Ваш статус: (заглушка)")

@subscription_router.message(Command("subscribe"))
async def cmd_subscribe(message: types.Message):
    telegram_id = message.from_user.id
    log.info(f"/subscribe from user {telegram_id}")

    # Генерируем Tron-адрес:
    addr = tron_service.generate_new_tron_address()
    qr_path = tron_service.create_qr_code(addr)

    text = f"Отправьте {config.SUBSCRIPTION_PRICE_USDT} USDT на адрес: {addr} (TRC20)"
    if qr_path and os.path.exists(qr_path):
        await message.answer_photo(types.FSInputFile(qr_path), caption=text)
    else:
        await message.answer(text)