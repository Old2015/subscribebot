from aiogram import Router, types
import logging
import config
import supabase_client
from datetime import datetime, timedelta
import os

from tron_service import create_qr_code, generate_new_tron_address

subscription_router = Router()
log = logging.getLogger(__name__)

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
    Пользователь нажал «Оформить подписку».
    1) Проверяем, не прошло ли 24 часа с предыдущего адреса
    2) Если прошло - генерируем новый адрес (HD), qr, сохраняем
    """
    telegram_id = message.from_user.id
    log.info(f"User {telegram_id} pressed 'Оформить подписку'")

    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if not user:
        await message.answer(
            "Сначала воспользуйтесь /start для регистрации.",
            reply_markup=main_menu
        )
        return

    deposit_address = user.get("deposit_address")
    deposit_created_at = user.get("deposit_created_at")  # datetime or None

    # 1) Если уже есть адрес, и <24ч
    if deposit_address and deposit_created_at:
        now = datetime.now()
        created_dt = deposit_created_at
        diff = now - created_dt

        if diff.total_seconds() < 24 * 3600:
            hours_left = 24 - diff.total_seconds() // 3600
            await message.answer(
                f"У вас уже есть адрес, выданный менее 24 ч назад. "
                f"Осталось примерно {hours_left} часов, прежде чем сможете запросить новый. "
                f"\nАдрес:\n{deposit_address}",
                reply_markup=main_menu
            )
            return
        else:
            # Сбрасываем старый адрес (или можно хранить историю, если хотите)
            supabase_client.reset_deposit_address(user['id'])
            deposit_address = None

    # 2) Генерируем новый HD-адрес
    # Предположим, используем user['id'] как index (SERIAL int)
    # Или user['telegram_id'], но лучше int PK
    user_id = user["id"]  # int
    tron_data = generate_new_tron_address(index=user_id)
    address = tron_data["address"]
    private_key_hex = tron_data["private_key"]

    if not address:
        await message.answer(
            "Ошибка: не удалось сгенерировать адрес Tron. Свяжитесь с администратором.",
            reply_markup=main_menu
        )
        return

    # 3) Сохраняем в БД
    supabase_client.update_deposit_info(
        user_id=user_id,
        address=address,
        pk=private_key_hex  # если хотите
    )

    # обновляем время
    supabase_client.update_deposit_created_at(
        user_id=user_id,
        created_at=datetime.now()
    )

    # 4) Генерируем QR и отправляем
    qr_path = create_qr_code(address)

    text = (
        "Для оформления подписки на 30 дней оплатите 100 USDT (TRC20) на адрес:\n"
        f"`{address}`\n"
        "В течение 24 часов этот адрес активен. После оплаты бот подтвердит подписку.\n"
        "QR-код ниже:"
    )

    if qr_path and os.path.exists(qr_path):
        try:
            await message.answer_photo(
                types.FSInputFile(qr_path),
                caption=text,
                parse_mode="Markdown",
                reply_markup=main_menu
            )
        except Exception as e:
            log.error(f"Error sending QR photo: {e}")
            await message.answer(
                f"{text}\n(Ошибка отправки QR, вот адрес: `{address}`)",
                parse_mode="Markdown",
                reply_markup=main_menu
            )
    else:
        await message.answer(
            f"{text}\n(Не удалось сгенерировать QR)",
            parse_mode="Markdown",
            reply_markup=main_menu
        )