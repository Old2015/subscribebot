# bot_handlers/subscription.py
from aiogram import types
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from services.supabase_client import (
    get_user_by_telegram_id,
    update_deposit_address,
    reset_deposit_address,
)
from services.tron_service import generate_new_tron_address, create_qr_code
from services.utils import format_datetime

async def cmd_subscription_status(message: types.Message):
    telegram_id = message.from_user.id
    user = get_user_by_telegram_id(telegram_id)

    if not user:
        await message.answer("Вы не зарегистрированы. Нажмите /start.")
        return

    # Проверяем триал
    trial_end = user.get('trial_end')
    subscription_end = user.get('subscription_end')

    if subscription_end and subscription_end > format_datetime():
        # У пользователя есть платная подписка
        end_str = format_datetime(subscription_end)
        await message.answer(f"Ваша платная подписка действует до {end_str}")
    else:
        # Проверяем, не активен ли trial
        if trial_end and trial_end > format_datetime():
            trial_end_str = format_datetime(trial_end)
            await message.answer(f"У вас действует триал до {trial_end_str}")
        else:
            await message.answer("Активной подписки нет.")

async def cmd_subscribe(message: types.Message):
    """
    Пользователь хочет оплатить подписку.
    Генерируем для него уникальный TRC20-адрес + QR, сохраняем в БД.
    """
    telegram_id = message.from_user.id
    user = get_user_by_telegram_id(telegram_id)

    if not user:
        await message.answer("Сначала введите /start.")
        return

    # Генерируем новый адрес
    new_address = generate_new_tron_address()
    # Сохраняем в БД
    update_deposit_address(user['id'], new_address)
    # Генерируем QR (опционально)
    qr_path = create_qr_code(new_address)

    text = (
        "Чтобы оформить подписку, отправьте 100 USDT (TRC20) на адрес:\n"
        f"{new_address}\n"
        "Данный адрес активен 24 часа."
    )

    if qr_path:
        await message.answer_photo(
            photo=open(qr_path, 'rb'),
            caption=text
        )
    else:
        await message.answer(text)
