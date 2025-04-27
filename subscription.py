from aiogram import Router, types
import logging
import config
import supabase_client
from datetime import datetime
import os

# Импортируем, если нужно, логику из start.py
# (Теперь "Начать заново" не вызывает cmd_start, 
#  а реализуем отдельную логику здесь)
# from start import cmd_start

from tron_service import create_qr_code, generate_new_tron_address

subscription_router = Router()
log = logging.getLogger(__name__)

# Три кнопки (Reply-клавиатура)
main_menu = types.ReplyKeyboardMarkup(
    keyboard=[
        [
            types.KeyboardButton(text="Статус подписки"),
            types.KeyboardButton(text="Оформить подписку"),
        ],
        [
            types.KeyboardButton(text="Начать заново")
        ]
    ],
    resize_keyboard=True
)

@subscription_router.message(lambda msg: msg.text == "Начать заново")
async def cmd_restart(message: types.Message):
    """
    Пользователь нажал «Начать заново».
    1) unban в группе (на всякий случай)
    2) Проверяем trial_end, subscription_end
    3) Если есть право на доступ (trial или подписка активны), создаём одноразовую ссылку member_limit=1
    4) Отправляем пользователю
    """
    telegram_id = message.from_user.id
    log.info(f"User {telegram_id} pressed 'Начать заново'")

    # 1) unban (на случай, если был удалён)
    try:
        await config.bot.unban_chat_member(
            chat_id=config.PRIVATE_GROUP_ID,
            user_id=telegram_id
        )
        log.info(f"User {telegram_id} unbanned successfully")
    except Exception as e:
        log.warning(f"Failed to unban user {telegram_id}. Possibly not banned. Err: {e}")

    # 2) Проверяем, есть ли у пользователя trial/subscription (ещё действующие)
    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if not user:
        await message.answer(
            "Вы не зарегистрированы. Нажмите /start или «Оформить подписку».",
            reply_markup=main_menu
        )
        return

    now = datetime.now()
    trial_end = user.get("trial_end")
    sub_start = user.get("subscription_start")     # если используете
    sub_end = user.get("subscription_end")

    # Флаг: есть ли право на доступ
    has_access = False

    # Проверим триал
    if trial_end and trial_end > now:
        has_access = True

    # Проверим подписку
    if sub_end and sub_end > now:
        # если есть sub_start, смотрим начала ли подписка (sub_start <= now)
        if sub_start:
            if sub_start <= now:
                has_access = True
            else:
                # Подписка ещё не началась, 
                # но, возможно, хотим уже пускать? 
                # Решите сами, хотим ли давать ссылку?
                # has_access = False
                pass
        else:
            # Нет sub_start => подписка активна
            has_access = True

    if not has_access:
        # Нет действующего триала, нет активной подписки
        # => не даём ссылку
        await message.answer(
            "У вас сейчас нет доступа (триал истёк, подписка не оформлена).",
            reply_markup=main_menu
        )
        return

    # 3) Раз есть доступ, генерируем одноразовую ссылку
    try:
        invite_link = await config.bot.create_chat_invite_link(
            chat_id=config.PRIVATE_GROUP_ID,
            name="Single-Use Link",
            member_limit=1,  # одноразовая
            expire_date=None
        )
        text = (
            "Ваша новая одноразовая ссылка для входа в группу:\n"
            f"{invite_link.invite_link}\n\n"
            "Ссылка утратит силу, как только кто-то ею воспользуется (или по истечении срока)."
        )
        await message.answer(text, reply_markup=main_menu)
    except Exception as e:
        log.error(f"Failed to create single-use invite link for user {telegram_id}: {e}")
        await message.answer(
            "Не удалось создать ссылку для входа. Свяжитесь с администратором.",
            reply_markup=main_menu
        )

@subscription_router.message(lambda msg: msg.text == "Статус подписки")
async def cmd_status(message: types.Message):
    # ... (как прежде) выводим trial_end / subscription_start / subscription_end
    # 
    # Пример упрощённого кода:
    log.info(f"User {message.from_user.id} pressed 'Статус подписки'")
    user = supabase_client.get_user_by_telegram_id(message.from_user.id)
    if not user:
        await message.answer("Вы не зарегистрированы. Нажмите «Начать заново».", reply_markup=main_menu)
        return

    now = datetime.now()
    trial_end = user.get("trial_end")
    sub_start = user.get("subscription_start")
    sub_end = user.get("subscription_end")

    lines = []

    # trial
    if trial_end:
        if trial_end > now:
            dleft = (trial_end - now).days
            lines.append(f"Триал до {trial_end.strftime('%d.%m.%Y')} (~{dleft} дн.)")
        else:
            lines.append("Триал истёк.")
    else:
        lines.append("Триал не оформлен.")

    # subscription
    if sub_end:
        if sub_start and sub_start > now:
            # подписка будущая
            days_wait = (sub_start - now).days
            lines.append(f"Подписка начнётся {sub_start.strftime('%d.%m.%Y')} (через ~{days_wait} дн.)")
        elif sub_start and sub_start <= now < sub_end:
            dleft = (sub_end - now).days
            lines.append(f"Подписка активна до {sub_end.strftime('%d.%m.%Y')} (~{dleft} дн.)")
        elif sub_end < now:
            lines.append("Подписка истекла.")
        else:
            # sub_start нет, а sub_end > now => активна 
            if sub_end > now:
                dleft = (sub_end - now).days
                lines.append(f"Подписка до {sub_end.strftime('%d.%m.%Y')} (~{dleft} дн.)")
            else:
                lines.append("Подписка истекла.")
    else:
        lines.append("Подписка не оформлена.")

    final_text = "\n".join(lines)
    await message.answer(final_text, reply_markup=main_menu)

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