from aiogram import Router, types
from aiogram.filters import Command
import logging
import supabase_client
import config
from datetime import datetime
from typing import Optional

start_router = Router()
log = logging.getLogger(__name__)

# Reply-клавиатура: две кнопки "Статус подписки", "Оформить подписку"
main_menu = types.ReplyKeyboardMarkup(
    keyboard=[
        [
            types.KeyboardButton(text="Статус подписки"),
            types.KeyboardButton(text="Оформить подписку"),
        ]
    ],
    resize_keyboard=True
)

@start_router.message(Command("start"))
async def cmd_start(message: types.Message):
    """
    Логика:
    1) Проверяем, есть ли пользователь в БД.
    2) Если нет -> create_user_with_trial(...). Подключаем в группу.
       - Отправляем приветственное сообщение с инфо о тестовом доступе на 3 дня.
    3) Если есть -> проверяем trial_end.
       - Если trial_end > now -> говорим, сколько осталось.
       - Иначе -> trial закончился, удаляем из группы, просим подписку.
    """
    telegram_id = message.from_user.id
    username = message.from_user.username or "NoUsername"

    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if not user:
        # Пользователя нет, создаём
        new_user = supabase_client.create_user_with_trial(
            telegram_id=telegram_id,
            username=username,
            trial_days=config.FREE_TRIAL_DAYS  # в .env => 3, например
        )
        log.info(f"Created new user with trial: {new_user}")

        # Подключаем (unban) в приватную группу
        try:
            await config.bot.unban_chat_member(
                chat_id=config.PRIVATE_GROUP_ID,
                user_id=telegram_id
            )
            # Отправляем приветственное сообщение с информацией
            welcome_text = (
                "Добро пожаловать в приватную торговую группу!\n"
                "В режиме реального времени публикуется каждая сделка "
                "профессионального трейдера Анонимуса: лимитные и маркет-ордера, "
                "TP/SL, частичное и полное закрытие позиций.\n\n"
                "Вам предоставлен и активирован тестовый доступ в торговую группу **3 дня**.\n\n"
                "По истечению тестового периода вы можете оформить подписку, "
                "стоимость **100 USDT** в месяц."
            )

            await message.answer(
                text=welcome_text,
                reply_markup=main_menu,
                parse_mode="Markdown"
            )
        except Exception as e:
            log.error(f"Error adding user {telegram_id} to group: {e}")
            await message.answer(
                "Вы добавлены в базу и получили триал, но не удалось добавить вас в группу.",
                reply_markup=main_menu
            )
    else:
        # Пользователь есть, смотрим trial_end
        trial_end: Optional[datetime] = user.get("trial_end")
        if trial_end is None:
            # Нет trial_end => либо триал уже истёк, либо не выдавался
            log.info(f"User {telegram_id} found, but no trial_end in DB.")
            await _remove_from_group_if_in(
                telegram_id,
                "Ваш тестовый период закончен. Оформите подписку."
            )
            await message.answer("Ваш триал не активен. Нужно оформить подписку.", reply_markup=main_menu)
            return

        now = datetime.now()
        if trial_end > now:
            # Триал активен, считаем сколько осталось
            days_left = (trial_end - now).days
            log.info(f"User {telegram_id} trial is still active, {days_left} days left.")
            await message.answer(
                f"У вас ещё активен триал на {days_left} дней.",
                reply_markup=main_menu
            )
        else:
            # trial_end < now => истёк
            log.info(f"User {telegram_id} trial expired.")
            await _remove_from_group_if_in(
                telegram_id,
                "Триал закончился! Для доступа оформите подписку."
            )
            await message.answer("Ваш триал закончился, нужно оформить подписку.", reply_markup=main_menu)


async def _remove_from_group_if_in(user_id: int, reason_text: str = ""):
    """
    Удаляем (ban) пользователя из приватной группы, 
    при желании отправляем ему личное сообщение.
    """
    try:
        await config.bot.ban_chat_member(
            chat_id=config.PRIVATE_GROUP_ID,
            user_id=user_id
        )
        if reason_text:
            await config.bot.send_message(
                chat_id=user_id,
                text=reason_text
            )
    except Exception as e:
        log.error(f"Error removing user {user_id} from group: {e}")