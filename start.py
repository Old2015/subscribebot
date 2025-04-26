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
    telegram_id = message.from_user.id
    username = message.from_user.username or "NoUsername"

    user = supabase_client.get_user_by_telegram_id(telegram_id)
    if not user:
        # Если пользователя нет в БД -> создаём
        new_user = supabase_client.create_user_with_trial(
            telegram_id=telegram_id,
            username=username,
            trial_days=config.FREE_TRIAL_DAYS
        )
        log.info(f"Created new user with trial: {new_user}")

        # Сначала unban – чтобы, если он был забанен ранее, мог заново войти
        try:
            await config.bot.unban_chat_member(
                chat_id=config.PRIVATE_GROUP_ID,
                user_id=telegram_id
            )
        except Exception as e:
            log.error(f"Error unbanning user {telegram_id}: {e}")

        # Генерируем пригласительную ссылку
        try:
            invite_link = await config.bot.create_chat_invite_link(
                chat_id=config.PRIVATE_GROUP_ID,
                name="Trial Access",
                expire_date=None,
                member_limit=None
            )

            welcome_text = (
                "Добро пожаловать в приватную торговую группу!\n"
                "В режиме реального времени публикуется каждая сделка "
                "профессионального трейдера Анонимуса: лимитные и маркет-ордера, "
                "TP/SL, частичное и полное закрытие позиций.\n\n"
                f"Вам предоставлен и активирован тестовый доступ в торговую группу {config.FREE_TRIAL_DAYS} дня(ей).\n\n"
                "По истечению тестового периода вы можете оформить подписку, "
                "стоимость 100 USDT в месяц.\n\n"
                f"Чтобы войти в группу, перейдите по ссылке:\n{invite_link.invite_link}"
            )

            await message.answer(
                text=welcome_text,
                reply_markup=main_menu
            )

            # Уведомление админам
            now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            admin_text = (
                f"[{now_str}] Новый пользователь!\n"
                f"Username: {username}\n"
                f"TelegramID: {telegram_id}\n"
                f"Оформлен тестовый доступ на {config.FREE_TRIAL_DAYS} дн."
            )
            await config.bot.send_message(
                chat_id=config.ADMIN_CHAT_ID,
                text=admin_text
            )
        except Exception as e:
            log.error(f"Error creating invite link or notifying user {telegram_id}: {e}")
            await message.answer(
                "Вы добавлены в базу (trial), но не удалось создать пригласительную ссылку.\n"
                "Свяжитесь с администратором.",
                reply_markup=main_menu
            )

    else:
        # Если пользователь уже есть -> проверяем trial_end
        trial_end: Optional[datetime] = user.get("trial_end")
        if not trial_end:
            # Нет trial_end => триал не выдавался или истёк
            log.info(f"User {telegram_id} found, trial_end is None.")
            await _remove_from_group_if_in(
                telegram_id,
                "Ваш тестовый период закончен. Оформите подписку."
            )
            await message.answer("У вас нет активного триала. Оформите подписку.", reply_markup=main_menu)
            return

        now = datetime.now()
        if trial_end > now:
            # Триал активен
            days_left = (trial_end - now).days
            log.info(f"User {telegram_id} trial is active: {days_left} days left.")

            # unban, чтобы гарантированно мог зайти
            try:
                await config.bot.unban_chat_member(
                    chat_id=config.PRIVATE_GROUP_ID,
                    user_id=telegram_id
                )
            except Exception as e:
                log.error(f"Error unbanning user {telegram_id}: {e}")

            # Генерируем новую ссылку (при желании)
            try:
                invite_link = await config.bot.create_chat_invite_link(
                    chat_id=config.PRIVATE_GROUP_ID,
                    name="Trial Re-Access",
                )
                text = (
                    f"У вас ещё активен триал, осталось ~{days_left} дн.\n"
                    f"Если не в группе, перейдите по ссылке:\n{invite_link.invite_link}"
                )
                await message.answer(text, reply_markup=main_menu)
            except Exception as e:
                await message.answer(
                    f"Триал активен (осталось ~{days_left} дн). "
                    "Но не получилось создать ссылку, свяжитесь с админом.",
                    reply_markup=main_menu
                )
                log.error(f"Error creating new link for existing user {telegram_id}: {e}")

        else:
            # trial_end < now => истёк
            log.info(f"User {telegram_id} trial expired.")
            await _remove_from_group_if_in(
                telegram_id,
                "Триал закончился! Для доступа оформите подписку."
            )
            await message.answer(
                "Ваш триал закончился, нужно оформить подписку.",
                reply_markup=main_menu
            )


async def _remove_from_group_if_in(user_id: int, reason_text: str = ""):
    """
    Удаляем пользователя из приватной группы (ban),
    отправляем ему reason_text (при желании).
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