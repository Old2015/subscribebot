import time                                          # временные операции
from datetime import datetime, timedelta, timezone, date  # работа с датами
import logging                                       # логирование
import os

from aiogram import Router, types                    # объекты aiogram
import config                                        # конфиг
import supabase_client                               # работа с БД
from tron_service import create_qr_code, generate_ephemeral_address
from tron_service import create_join_request_link



subscription_router = Router()                   # роутер раздела подписки
log = logging.getLogger(__name__)                # логгер модуля

# Anti-spam: не чаще одного раза в 30 сек
RESTART_COOLDOWN = 30                        # секунды между попытками "Начать заново"
_last_restart: dict[int, float] = {}         # tg_id → timestamp


# Три кнопки (Reply-клавиатура)
main_menu = types.ReplyKeyboardMarkup(
    keyboard=[
        [
            types.KeyboardButton(text="Subscription status"),
            types.KeyboardButton(text="Purchase subscription"),
        ],
        [
            types.KeyboardButton(text="Start over")
        ]
    ],
    resize_keyboard=True
)

@subscription_router.message(lambda msg: msg.text == "Start over")
async def cmd_restart(message: types.Message):
    """
    Пользователь нажал «Начать заново».
    1) unban (на случай, если был удалён)
    2) Проверяем, есть ли trial_end > now или subscription_end > now
    3) Если есть — генерируем одноразовую ссылку (24 ч, member_limit=1)
    """
    # обработка нажатия кнопки "Начать заново"
    telegram_id = message.from_user.id          # ← добавили
    log.info("User %s pressed 'Start over'", telegram_id)

    now_ts = time.time()
    if now_ts - _last_restart.get(telegram_id, 0) < RESTART_COOLDOWN:
        await message.answer(
            "Waiting 30 seconds. "
            "Please wait a moment 🙂",
            reply_markup=main_menu
        )
        return
    _last_restart[telegram_id] = now_ts



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
            "You are not registered. Tap /start ",
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
            "You currently have no access (your free trial has expired or no subscription is active). You can purchase a new subscription. For technical questions, please contact the administrator @gwen12309",
            reply_markup=main_menu
        )
        return

 # --- выдаём / переиспользуем join-request ссылку ----------------------
    try:
        # 1) снимаем бан (на всякий случай)
        await config.bot.unban_chat_member(
            chat_id=config.PRIVATE_GROUP_ID,
            user_id=telegram_id,
            only_if_banned=True
        )


        # 2) если в БД уже есть не-протухшая – переиспользуем
 

        old_link, old_exp = supabase_client.get_invite(user["id"])

        def _as_utc(dt):
            if dt is None:
                return None
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

        old_exp = _as_utc(old_exp)             # выравниваем tz

        if old_link and old_exp and old_exp > datetime.now(timezone.utc):
            join_link = old_link
        else:
            join_link = await create_join_request_link(
                bot=config.make_bot(),
                chat_id=config.PRIVATE_GROUP_ID,
                title="Restart join-request",
            )
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
            supabase_client.upsert_invite(user["id"], join_link, expires_at)


        # 4) отдаём кнопку
        btn = types.InlineKeyboardButton(text="Join the group", url=join_link)
        kb  = types.InlineKeyboardMarkup(inline_keyboard=[[btn]])
        await message.answer(
            "Tap the button below and confirm your request—the bot will approve it automatically.",
            reply_markup=kb
        )


    except Exception as e:
        log.error("restart join-link error for %s: %s", telegram_id, e)
        await message.answer(
            "🚫 Unable to generate a link. Please try again later or contact the administrator @gwen12309.",
            reply_markup=main_menu
        )

# ─────────────────────────────────────────────────────────────────────────────
# «СТАТУС ПОДПИСКИ»
# ─────────────────────────────────────────────────────────────────────────────
@subscription_router.message(lambda msg: msg.text == "Subscription status")
async def cmd_status(message: types.Message):
    """
    Показываем текущее состояние доступа. Логика:
      • Общий диапазон = min( trial_start | sub_start ) … max( trial_end | sub_end )
      • Бесплатные дни = trial_start … trial_end            (если есть и не закончились)
      • Платные дни     = max(sub_start, trial_end+1) … sub_end
    """
    log.info("User %s pressed 'Subscription status'", message.from_user.id)

    user = supabase_client.get_user_by_telegram_id(message.from_user.id)
    if not user:
        await message.answer(
            "You are not registered. Tap «Start over» .",
            reply_markup=main_menu,
        )
        return

    # ------------------------------ начало изменённого фрагмента -----------------

    # ---------- [1] подготовка дат ----------
    def as_utc(dt):
        if dt is None:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    trial_start = as_utc(user.get("trial_start"))
    trial_end   = as_utc(user.get("trial_end"))
    sub_start   = as_utc(user.get("subscription_start"))
    sub_end     = as_utc(user.get("subscription_end"))


    now_utc  = datetime.now(timezone.utc)
    local_tz = datetime.now().astimezone().tzinfo

    # ── сразу после now_utc / local_tz
    def days_inclusive(d1: date, d2: date) -> int:
        """Разница дат с учётом обеих границ (19-21 = 3)."""
        return (d2 - d1).days + 1

    # ---------- [2] базовый интервал доступа ----------
    if sub_end and sub_end > now_utc:
        # если у пользователя был тест – считаем, что доступ начался ещё с него
        if trial_start:
            access_start = trial_start
        else:
            access_start = sub_start or now_utc
        access_end = sub_end
    elif trial_end and trial_end > now_utc:
        access_start = trial_start or now_utc
        access_end   = trial_end
    else:
        await message.answer(
            "You currently have no active access.\n"
            "To join the group, tap → «Purchase subscription»."
            "For technical questions, please contact @gwen12309",
            reply_markup=main_menu,
        )
        return

    access_start_str = access_start.astimezone(local_tz).strftime("%d.%m.%Y")
    access_end_str   = access_end.astimezone(local_tz).strftime("%d.%m.%Y")

    lines = [
        "ℹ️ *HiddenEdge Trader’s Group access status*",
        f"Access is granted from  {access_start_str} to {access_end_str}."
    ]

    details_exist = False            # нужно ли выводить раздел “В том числе:”

    # -------------------------------------------------------------------------
    # 1) БЕСПЛАТНЫЙ ТЕСТ: если триал активен
    # -------------------------------------------------------------------------
    trial_start_eff = trial_start or access_start

    if trial_end and trial_end > now_utc:
        trial_start_l = trial_start_eff.astimezone(local_tz)
        trial_end_l   = trial_end.astimezone(local_tz)
        trial_days = days_inclusive(trial_start_eff.date(), trial_end.date())
        lines.append("\nIncluding:")
        details_exist = True
        lines.append(
          f"• from {trial_start_l:%d.%m.%Y} to {trial_end_l:%d.%m.%Y} — {trial_days}-day free trial"
        )

    # -------------------------------------------------------------------------
    # 2) ОПЛАЧЕННАЯ ПОДПИСКА
    # -------------------------------------------------------------------------
    if sub_end and sub_end > now_utc:
        # если тест ещё идёт → платная часть начинается на 1 день позже trial_end
        if trial_end and trial_end > now_utc:
            paid_start = trial_end + timedelta(days=1)
        else:
            paid_start = sub_start or now_utc          # fallback

        paid_start_str = paid_start.astimezone(local_tz).strftime("%d.%m.%Y")
        paid_days = days_inclusive(paid_start.date(), sub_end.date())


        if not details_exist:
            lines.append("\nIncluding:")
        lines.append(
            f"• from {paid_start_str} to {access_end_str} — {paid_days} day paid subscription"
        )
# ------------------------------ конец изменённого фрагмента ------------------
    await message.answer(
        "\n".join(lines),
        parse_mode="Markdown",
        reply_markup=main_menu,
    )



@subscription_router.message(lambda msg: msg.text == "Purchase subscription")
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
    log.info(f"User {telegram_id} pressed 'Purchase subscription'")

    user = supabase_client.get_user_by_telegram_id(message.from_user.id)
    if not user:
        await message.answer(
            "You are not registered. Tap /start .",
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
                "A payment address was issued less than 24 hours ago.\n"
                f"Approximately {hours_left}h remain before you can request a new one.\n"
                f"Your current payment address:\n{deposit_address}",
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
            "Error: failed to generate a Tron address. Please contact the administrator @gwen12309",
            reply_markup=main_menu
        )
        return

   

    # Генерируем QR
    qr_path = create_qr_code(address)
    usdt_amount = config.SUBSCRIPTION_PRICE_USDT

    # Подготавливаем 4 части сообщения
    msg_intro = (
        f"To purchase a 30-day subscription, please send {usdt_amount} USDT (TRC20) to the address below:"
    )
    msg_address = f"`{address}`"  # easy to copy
    msg_after = (
        "This address is valid for 24 hours. After payment, the bot will automatically confirm your subscription and activate (or extend) your group access within 20 minutes."
    )
    msg_network = (
        "Attention: payments are accepted **only** on the TRC20 network.\n"
        "If you send funds via another network, they will not be credited! For technical questions, contact the administrator @gwen12309."
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
        await message.answer("(Failed to generate a QR code)\n" + msg_after)
        await message.answer(msg_network, parse_mode="Markdown")

