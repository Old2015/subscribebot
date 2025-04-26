from aiogram import types
import config
import supabase_client
import tron_service
import math
from datetime import datetime

async def cmd_status(message: types.Message):
    telegram_id = message.from_user.id
    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if not user:
        await message.answer("Вы не зарегистрированы! Нажмите /start.")
        return
    
    # Проверяем подписку
    sub_end = user.get('subscription_end')
    trial_end = user.get('trial_end')

    now_time = datetime.now()
    text_msg = "У вас нет активной подписки."
    
    if trial_end:
        # trial_end - datetime из БД
        if trial_end > now_time and (user.get('subscription_end') is None or user['subscription_end'] < now_time):
            text_msg = f"У вас действует бесплатный триал до {trial_end}."
    
    if sub_end and sub_end > now_time:
        text_msg = f"Ваша платная подписка действует до {sub_end}."
    
    await message.answer(text_msg)

async def cmd_subscribe(message: types.Message):
    telegram_id = message.from_user.id
    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if not user:
        await message.answer("Сначала /start.")
        return

    # Генерим уникальный адрес Tron
    deposit_addr = tron_service.generate_new_tron_address()
    supabase_client.set_deposit_address(user['id'], deposit_addr)

    # Формируем QR
    qr_path = tron_service.create_qr_code(deposit_addr)

    text = (
        f"Отправьте {config.SUBSCRIPTION_PRICE_USDT} USDT (TRC20) на адрес:\n"
        f"{deposit_addr}\n"
        "Адрес будет активен 24 часа."
    )
    if qr_path:
        await message.answer_photo(open(qr_path, 'rb'), caption=text)
    else:
        await message.answer(text)
