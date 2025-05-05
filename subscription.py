import time
from datetime import datetime, timedelta, timezone
import logging
import os

from aiogram import Router, types
import config
import supabase_client
from tron_service import create_qr_code, generate_ephemeral_address

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
    1) unban (на случай, если был удалён)
    2) Проверяем, есть ли trial_end > now или subscription_end > now
    3) Если есть — генерируем одноразовую ссылку (24 ч, member_limit=1)
    """
    telegram_id = message.from_user.id
    log.info(f"User {telegram_id} pressed 'Начать заново'")

    # unban
    try:
        await config.bot.unban_chat_member(
            chat_id=config.PRIVATE_GROUP_ID,
            user_id=telegram_id,
            only_if_banned=False
        )
        log.info(f"User {telegram_id} unbanned successfully")
    except Exception as e:
        log.warning(f"Failed to unban user {telegram_id}. Possibly not banned? {e}")

    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if not user:
        await message.answer(
            "Вы не зарегистрированы. Нажмите /start ",
            reply_markup=main_menu
        )
        return

    now = datetime.now()
    trial_end = user.get("trial_end")
    sub_start = user.get("subscription_start")
    sub_end = user.get("subscription_end")

    has_access = False

    # Проверим trial
    if trial_end and trial_end > now:
        has_access = True

    # Проверим подписку
    if sub_end and sub_end > now:
        if sub_start:
            if sub_start <= now:
                has_access = True
        else:
            has_access = True

    if not has_access:
        await message.answer(
            "У вас сейчас нет доступа (Период бесплатного доступа истёк или подписка не оформлена).",
            reply_markup=main_menu
        )
        return

    # Генерируем одноразовую ссылку, срок 24 ч
    expire_timestamp = int(time.time()) + 24 * 3600
    try:
        invite_link = await config.bot.create_chat_invite_link(
            chat_id=config.PRIVATE_GROUP_ID,
            name="Single-Use Link",
            member_limit=1,
            expire_date=expire_timestamp
        )
        text = (
            "Ваша новая одноразовая ссылка для входа в группу (действует 24 ч, один вход):\n"
            f"{invite_link.invite_link}\n\n"
            "Если понадобится ещё одна ссылка, нажмите «Начать заново»."
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
    """
    Показываем текущее состояние доступа в одном стиле с платёжным уведомлением:
      ─ базовый диапазон доступа
      ─ (опционально) блок «В том числе …» про тестовый период и оплаченные дни
    """
    log.info("User %s pressed 'Статус подписки'", message.from_user.id)

    user = supabase_client.get_user_by_telegram_id(message.from_user.id)
    if not user:
        await message.answer(
            "Вы не зарегистрированы. Нажмите «Начать заново».",
            reply_markup=main_menu,
        )
        return

    # --- даты из БД --------------------------------------------------------
    trial_end = user.get("trial_end")              # datetime | None
    sub_start = user.get("subscription_start")
    sub_end   = user.get("subscription_end")

    # приводим naive → UTC-aware, чтобы корректно сравнивать
    def as_utc(dt):
        if dt is None:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    trial_end = as_utc(trial_end)
    sub_start = as_utc(sub_start)
    sub_end   = as_utc(sub_end)

    # --- расчёт базового диапазона доступа --------------------------------
    now_utc   = datetime.now(timezone.utc)
    local_tz  = datetime.now().astimezone().tzinfo

    # если подписка активна — конец = sub_end; иначе если триал активен — trial_end
    if sub_end and sub_end > now_utc:
        access_end = sub_end
    elif trial_end and trial_end > now_utc:
        access_end = trial_end
    else:
        await message.answer(
            "У вас нет активного доступа.\nОформить подписку → «Оформить подписку».",
            reply_markup=main_menu,
        )
        return

    today_str = datetime.now(local_tz).strftime("%d.%m.%Y")
    end_str   = access_end.astimezone(local_tz).strftime("%d.%m.%Y")

    lines = [
        "ℹ️ *Статус доступа к TradingGroup*",
        f"Доступ к TradingGroup разрешён\nс {today_str} по {end_str}.",
    ]

    # --- доп. блок, если триал ещё не завершился --------------------------
    if trial_end and trial_end > now_utc:
        trial_end_str = trial_end.astimezone(local_tz).strftime("%d.%m.%Y")
        trial_days    = (trial_end.date() - now_utc.date()).days

        paid_start = max(trial_end, now_utc)        # начало оплаченной части
        paid_start_str = paid_start.astimezone(local_tz).strftime("%d.%m.%Y")
        paid_days      = (sub_end.date() - paid_start.date()).days if sub_end else 0
        paid_end_str   = sub_end.astimezone(local_tz).strftime("%d.%m.%Y") if sub_end else end_str

        lines.append(
            "\nВ том числе:"
            f"\n• с {today_str} по {trial_end_str} — {trial_days} дн. тестового периода."
            f"\n• с {paid_start_str} по {paid_end_str} — {paid_days} дн. оплаченной подписки."
        )

    await message.answer("\n".join(lines), parse_mode="Markdown", reply_markup=main_menu)



@subscription_router.message(lambda msg: msg.text == "Оформить подписку")
async def cmd_subscribe(message: types.Message):
    """
    1) Проверяем, выдавали ли адрес <24 ч назад
    2) Если можно — генерируем HD-адрес, сохраняем
    3) Отправляем 4 сообщения:
       (1) Фото (QR) + "Для оформления подписки..."
       (2) Адрес отдельно
       (3) "Этот адрес действует 24 часа..."
       (4) "Внимание: только сеть TRC20!"
    """
    telegram_id = message.from_user.id
    log.info(f"User {telegram_id} pressed 'Оформить подписку'")

    user = supabase_client.get_user_by_telegram_id(message.from_user.id)
    if not user:
        await message.answer(
            "Вы не зарегистрированы. Введите /start для регистрации.",
            reply_markup=main_menu
        )
        return

    deposit_address     = user.get("deposit_address")
    deposit_created_at  = user.get("deposit_created_at")        # может быть aware или naive

    if deposit_address and deposit_created_at:
        # --- выравниваем тайм-зоны -------------------------------------------
        created_utc = (
            deposit_created_at
            if deposit_created_at.tzinfo
            else deposit_created_at.replace(tzinfo=timezone.utc)
        )
        now_utc = datetime.now(timezone.utc)

        # --- сколько времени прошло / осталось ------------------------------
        diff_seconds      = (now_utc - created_utc).total_seconds()
        if diff_seconds < 24 * 3600:
            remaining_sec = 24 * 3600 - diff_seconds
            hours_left    = int(remaining_sec // 3600)   # или math.ceil(… / 3600)

            await message.answer(
                "Адрес для оплаты был выдан менее 24ч назад.\n"
                f"Осталось примерно {hours_left}ч, прежде чем вы сможете запросить новый.\n"
                f"Ваш текущий адрес для оплаты:\n{deposit_address}",
                reply_markup=main_menu,
            )
            return

    # 24 ч прошли — адрес обнуляем
        supabase_client.reset_deposit_address_and_privkey(user["id"])

    # Генерация нового адреса (если используете счётчик):
    # new_index = supabase_client.increment_deposit_index(user["id"])
    # tron_data = generate_ephemeral_address(index=new_index)
    # Или без счётчика:
    tron_data = generate_ephemeral_address(user['id'])   # БЕЗ параметра index
    address = tron_data["address"]
    if not address:
        await message.answer(
            "Ошибка: не удалось сгенерировать Tron-адрес. Свяжитесь с админом.",
            reply_markup=main_menu
        )
        return

   

    # Генерируем QR
    qr_path = create_qr_code(address)
    usdt_amount = config.SUBSCRIPTION_PRICE_USDT

    # Подготавливаем 4 части сообщения
    msg_intro = (
        f"Для оформления подписки на 30 дней оплатите {usdt_amount} USDT (TRC20) на адрес:"
    )
    msg_address = f"`{address}`"  # удобно копировать
    msg_after = (
        "Этот адрес действует 24 часа. После оплаты бот автоматически подтвердит вашу подписку."
    )
    msg_network = (
        "Внимание: оплата принимается **только** в сети TRC20.\n"
        "Если отправите в другой сети, средства не будут зачислены!"
    )

    if qr_path and os.path.exists(qr_path):
        # 1) QR + intro
        try:
            await message.answer_photo(
                photo=types.FSInputFile(qr_path),
                caption=msg_intro,
                parse_mode="Markdown",
                reply_markup=main_menu
            )
            # 2) Адрес отдельно
            await message.answer(msg_address, parse_mode="Markdown")
            # 3) Условия
            await message.answer(msg_after)
            # 4) Предупреждение сети
            await message.answer(msg_network, parse_mode="Markdown")

        except Exception as e:
            log.error(f"Error sending QR photo: {e}")
            # Если фото не отправилось, всё равно отправим разбивку без фото
            await message.answer(msg_intro, reply_markup=main_menu)
            await message.answer(msg_address, parse_mode="Markdown")
            await message.answer(msg_after)
            await message.answer(msg_network, parse_mode="Markdown")
    else:
        # Без QR
        await message.answer(msg_intro, reply_markup=main_menu)
        await message.answer(msg_address, parse_mode="Markdown")
        await message.answer("(Не удалось сгенерировать QR)\n" + msg_after)
        await message.answer(msg_network, parse_mode="Markdown")