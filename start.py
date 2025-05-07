import time
from datetime import datetime, timedelta, timezone
from aiogram import Router, types
from aiogram.filters import Command
import logging
import config
import supabase_client

# Импортируем main_menu из subscription.py, 
# где находятся 3 кнопки: "Статус подписки", "Оформить подписку", "Начать заново".
from subscription import main_menu
from tron_service import create_join_request_link


start_router = Router()
log = logging.getLogger(__name__)

@start_router.message(Command("start"))
async def cmd_start(message: types.Message):
    """
    Пользователь вводит /start.
    Логика:
    1) Если новый пользователь:
       - unban (на всякий случай)
       - trial_end = 
          - если now < GLOBAL_END_DATE => GLOBAL_END_DATE (т.е. 01.06.2025)
          - иначе => now + FREE_TRIAL_DAYS
       - создаём запись (trial_end)
       - генерируем одноразовую ссылку (24h, 1 вход)
       - пишем: "Добро пожаловать... до dd.mm.yyyy (xx дней)"
         ссылка...
         "Если нужна новая ссылка, жмите «Начать заново»."
       - показываем main_menu
    2) Если пользователь есть:
       - Если trial_end > now => "У вас бесплатный доступ до dd.mm.yyyy, (xx дней).
         Для новой ссылки => «Начать заново»."
       - Если подписка active => ...
       - И тоже main_menu
    """
    telegram_id = message.from_user.id
    username = message.from_user.username or "NoUsername"
    now = datetime.now()

    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if not user:
        # ============== НОВЫЙ ПОЛЬЗОВАТЕЛЬ ==============

        # 1) unban
        try:
            await config.bot.unban_chat_member(
                chat_id=config.PRIVATE_GROUP_ID,
                user_id=telegram_id,
                only_if_banned=False
            )
            log.info(f"User {telegram_id} unbanned successfully (new).")
        except Exception as e:
            log.warning(f"Failed to unban new user {telegram_id}: {e}")

        # 2) Определяем trial_end
        if config.GLOBAL_END_DATE:
            # Если now.date() < GLOBAL_END_DATE => trial_end = GLOBAL_END_DATE (полночь)
            if now.date() < config.GLOBAL_END_DATE:
                # Допустим, trial_end = <дата> 00:00
                trial_end_datetime = datetime(
                    config.GLOBAL_END_DATE.year,
                    config.GLOBAL_END_DATE.month,
                    config.GLOBAL_END_DATE.day,
                    0, 0, 0
                )
            else:
                # уже >= 2025-06-01 => обычный FREE_TRIAL_DAYS
                trial_end_datetime = now + timedelta(days=config.FREE_TRIAL_DAYS)
        else:
            # если GLOBAL_END_DATE не указана, просто + FREE_TRIAL_DAYS
            trial_end_datetime = now + timedelta(days=config.FREE_TRIAL_DAYS)

        # 3) Создаём запись вручную (custom trial)
        #    Предположим, у вас есть функция create_user_with_custom_trial(...)
        #    Если нет, напишем / либо используем create_user_with_trial(), 
        #    но тогда придётся обновить trial_end вручную:

        supabase_client.create_user_custom_trial(
            telegram_id=telegram_id,
            username=username,
            trial_end=trial_end_datetime
        )
        # Либо:
        # new_user = supabase_client.create_user_with_trial(telegram_id, username, config.FREE_TRIAL_DAYS)
        #  а потом update trial_end = trial_end_datetime. 
        #  Как удобнее.

        # Рассчитаем, сколько дней (примерно):
        days_left = (trial_end_datetime - now).days
        trial_end_str = trial_end_datetime.strftime("%d.%m.%Y")

        # 4) Генерируем одноразовую ссылку
        expire_timestamp = int(time.time()) + 24*3600
        link_str = ""
        try:
            join_link = await create_join_request_link(
                bot=config.bot,
                chat_id=config.PRIVATE_GROUP_ID,
                title="New-user join-request"
            )

            # TTL 24 ч (храним, чтобы «Начать заново» мог переиспользовать)
            expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
            supabase_client.upsert_invite(user["id"], join_link, expires_at)

            link_str = (
                "Нажмите ссылку ниже, отправьте запрос — бот одобрит автоматически "
                "(ссылка действует 24 ч, один вход):\n"
                f"{join_link}\n\n"
                "Если понадобится новая ссылка, нажмите «Начать заново».\n"
                "Возникли проблемы — пишите @gwen12309."
            )
        except Exception as e:
            log.error("Failed to create join-request for new user %s: %s", telegram_id, e)
            link_str = (
                "Не удалось автоматически создать ссылку. "
                "Свяжитесь с админом @gwen12309 или попробуйте «Начать заново» позже."
            )
            

        text = (
            f"Добро пожаловать! Вы получили доступ в TradingGroup и Вам оформлен тестовый доступ на {days_left} дн., "
            f"до {trial_end_str}.\n Внимательно изучите документацию в закрепе группы.\n\n"
            f"{link_str}"
        )
        await message.answer(text, reply_markup=main_menu)

    else:
        # ============== СУЩЕСТВУЮЩИЙ ПОЛЬЗОВАТЕЛЬ ==============
        trial_end = user.get("trial_end")
        sub_start = user.get("subscription_start")
        sub_end = user.get("subscription_end")

        now = datetime.now()
        # trial check
        if trial_end and trial_end > now:
            dleft = (trial_end - now).days
            trial_end_str = trial_end.strftime("%d.%m.%Y")
            await message.answer(
                f"У вас есть бесплатный доступ до {trial_end_str} ({dleft} дн).\n\n"
                "Чтобы сформировать новую ссылку, нажмите «Начать заново».",
                reply_markup=main_menu
            )
        elif sub_end and sub_end > now:
            # подписка
            if sub_start and sub_start > now:
                dwait = (sub_start - now).days
                await message.answer(
                    f"Подписка начнётся через {dwait} дн., "
                    f"с {sub_start.strftime('%d.%m.%Y')}.\n\n"
                    "Для новой ссылки: «Начать заново».",
                    reply_markup=main_menu
                )
            elif sub_start is None or sub_start <= now < sub_end:
                dleft = (sub_end - now).days
                await message.answer(
                    f"Подписка активна до {sub_end.strftime('%d.%m.%Y')} ({dleft} дн.).\n\n"
                    "Чтобы получить новую ссылку, «Начать заново».",
                    reply_markup=main_menu
                )
            else:
                await message.answer(
                    "Странное состояние подписки. Попробуйте «Начать заново» или свяжитесь с админом.",
                    reply_markup=main_menu
                )
        else:
            await message.answer(
                "Ваш тестовый период и/или подписка истекли. "
                "Нажмите «Оформить подписку» для продления.",
                reply_markup=main_menu
            )