from aiogram import Router, types
import logging
import config
import supabase_client
from datetime import datetime, timedelta
import os

from tron_service import create_qr_code, generate_new_tron_address

subscription_router = Router()
log = logging.getLogger(__name__)

# Две кнопки "Статус подписки" и "Оформить подписку"
main_menu = types.ReplyKeyboardMarkup(
    keyboard=[
        [
            types.KeyboardButton(text="Статус подписки"),
            types.KeyboardButton(text="Оформить подписку"),
        ]
    ],
    resize_keyboard=True
)

@subscription_router.message(lambda msg: msg.text == "Оформить подписку")
async def cmd_subscribe(message: types.Message):
    """
    Пользователь нажимает «Оформить подписку».
    1) Проверяем, не выдавали ли мы адрес <24 ч назад
    2) Если выдавали → сообщаем, сколько осталось
    3) Если нет → генерируем новый HD-адрес (по user['id']), сохраняем, отправляем QR
    """
    telegram_id = message.from_user.id
    log.info(f"User {telegram_id} pressed 'Оформить подписку'")

    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if not user:
        await message.answer(
            "Вы не зарегистрированы. Введите /start для регистрации.",
            reply_markup=main_menu
        )
        return

    deposit_address = user.get("deposit_address")
    deposit_created_at = user.get("deposit_created_at")  # datetime or None

    # Проверка 24 часов
    if deposit_address and deposit_created_at:
        now = datetime.now()
        diff = now - deposit_created_at
        if diff.total_seconds() < 24 * 3600:
            hours_left = 24 - diff.total_seconds() // 3600
            await message.answer(
                f"Адрес уже выдан менее 24 ч назад.\n"
                f"Осталось примерно {hours_left} часов, прежде чем сможете запросить новый.\n"
                f"Ваш текущий адрес:\n{deposit_address}",
                reply_markup=main_menu
            )
            return
        else:
            # Сбрасываем старый адрес
            supabase_client.reset_deposit_address(user['id'])
            deposit_address = None

    # Генерируем новый HD-адрес
    user_id = user["id"]
    tron_data = generate_new_tron_address(index=user_id)
    address = tron_data["address"]
    # private_key_hex = tron_data["private_key"] # мы не храним

    if not address:
        await message.answer(
            "Ошибка: не удалось сгенерировать Tron-адрес. Свяжитесь с администратором.",
            reply_markup=main_menu
        )
        return

    # Сохраняем deposit_address
    supabase_client.update_deposit_info(user_id, address)
    # Обновляем время
    supabase_client.update_deposit_created_at(user_id, datetime.now())

    # Генерируем QR
    qr_path = create_qr_code(address)

    # Берём сумму из .env (config.SUBSCRIPTION_PRICE_USDT)
    usdt_amount = config.SUBSCRIPTION_PRICE_USDT

    text = (
        f"Для оформления подписки на 30 дней оплатите {usdt_amount} USDT (TRC20) на адрес:\n"
        f"`{address}`\n\n"
        "Этот адрес действителен 24 часа. После оплаты бот автоматически подтвердит вашу подписку."
    )

    if qr_path and os.path.exists(qr_path):
        try:
            await message.answer_photo(
                photo=types.FSInputFile(qr_path),
                caption=text,
                parse_mode="Markdown",
                reply_markup=main_menu
            )
        except Exception as e:
            log.error(f"Error sending QR photo: {e}")
            await message.answer(
                f"{text}\n(Ошибка отправки QR. Вот адрес: `{address}`)",
                parse_mode="Markdown",
                reply_markup=main_menu
            )
    else:
        await message.answer(
            f"{text}\n(Не удалось сгенерировать QR)",
            parse_mode="Markdown",
            reply_markup=main_menu
        )