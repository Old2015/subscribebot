from aiogram import Router, types
from aiogram.filters import Command
import logging
import supabase_client
import config
from datetime import datetime, timedelta
from typing import Optional

start_router = Router()
log = logging.getLogger(__name__)

# Клавиатура (пример, 3 кнопки)
main_menu = types.ReplyKeyboardMarkup(
    keyboard=[
        [
            types.KeyboardButton(text="Статус подписки"),
            types.KeyboardButton(text="Оформить подписку"),
        ],
        [
            types.KeyboardButton(text="Старт")
        ]
    ],
    resize_keyboard=True
)

@start_router.message(Command("start"))
async def cmd_start(message: types.Message):
    telegram_id = message.from_user.id
    username = message.from_user.username or "NoUsername"

    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if not user:
        # Новый пользователь
        now = datetime.now()
        # Проверяем глобальную дату
        if config.GLOBAL_END_DATE:
            # Если (сегодня) < GLOBAL_END_DATE
            if now.date() < config.GLOBAL_END_DATE:
                # trial_end = 1 июня 2025 00:00
                trial_end_datetime = datetime(config.GLOBAL_END_DATE.year,
                                              config.GLOBAL_END_DATE.month,
                                              config.GLOBAL_END_DATE.day, 0, 0)
            else:
                # Иначе обычный trial N дней
                trial_end_datetime = now + timedelta(days=config.FREE_TRIAL_DAYS)
        else:
            # Если вообще не задано, всё по FREE_TRIAL_DAYS
            trial_end_datetime = now + timedelta(days=config.FREE_TRIAL_DAYS)

        # Создаём пользователя
        new_user = supabase_client.create_user_with_custom_trial(
            telegram_id=telegram_id,
            username=username,
            trial_end=trial_end_datetime
        )
        log.info(f"Created new user with trial_end={trial_end_datetime}")

        # Генерируем invite link / unban
        try:
            invite_link = await config.bot.create_chat_invite_link(
                chat_id=config.PRIVATE_GROUP_ID,
                name="Trial Access"
            )
            text = (
                "Добро пожаловать!\n"
                f"Тестовый период действует до {trial_end_datetime.strftime('%d.%m.%Y')}.\n"
                "Если оплатите подписку до этой даты, старт подписки будет с этой же даты.\n"
                "Ссылка для входа в группу:\n"
                f"{invite_link.invite_link}"
            )
            await message.answer(text, reply_markup=main_menu)
        except Exception as e:
            log.error(f"Failed to create invite link: {e}")
            await message.answer(
                "Вы добавлены в базу, но не получилось создать ссылку.\n"
                "Свяжитесь с админом.",
                reply_markup=main_menu
            )

    else:
        # Уже есть пользователь
        trial_end: Optional[datetime] = user.get("trial_end")
        if not trial_end:
            # trial_end = NULL => trial нет
            # удаляем из группы?
            await _remove_from_group_if_in(telegram_id, "У вас нет активного триала.")
            await message.answer("Ваш триал не активен, оформите подписку.", reply_markup=main_menu)
            return

        now = datetime.now()
        if trial_end > now:
            # Trial is active
            days_left = (trial_end - now).days
            await message.answer(
                f"Триал ещё активен, осталось {days_left} дней.\n"
                "Чтобы зайти в группу, используйте /start ещё раз для ссылки (при необходимости).",
                reply_markup=main_menu
            )
        else:
            # trial_end < now => триал истёк
            await _remove_from_group_if_in(
                telegram_id,
                "Ваш тестовый период закончился, оформите подписку."
            )
            await message.answer("Триал закончился, оформите подписку.", reply_markup=main_menu)

async def _remove_from_group_if_in(user_id: int, reason: str):
    try:
        await config.bot.ban_chat_member(
            chat_id=config.PRIVATE_GROUP_ID,
            user_id=user_id
        )
        await config.bot.send_message(
            chat_id=user_id,
            text=reason
        )
    except Exception as e:
        log.error(f"Error removing user {user_id} from group: {e}")