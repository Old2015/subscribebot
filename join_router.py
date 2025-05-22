# join_router.py
from datetime import datetime, timezone      # время для проверки TTL
from subscription import main_menu           # клавиатура с меню

from aiogram import Router, Bot, types         # работа с событиями чата
import config, supabase_client, logging        # общие модули

log = logging.getLogger(__name__)        # логгер модуля
join_router = Router()                   # отдельный роутер для join-request


@join_router.chat_join_request()              # фильтр по chat_id делаем руками
async def handle_join_request(event: types.ChatJoinRequest, bot: Bot):
    """
    Одобряем join-request, если в БД есть действующая ссылка для пользователя.
    """
    # Срабатывает при запросе пользователя присоединиться к группе
    chat_id = event.chat.id
    user_id = event.from_user.id
    log.info("CJRequest from %s in chat %s", user_id, chat_id)

    # 1) только наша группа
    if chat_id != config.PRIVATE_GROUP_ID:
        return

    # 2) пользователь существует?
    db_user = supabase_client.get_user_by_telegram_id(user_id)
    if not db_user:
        log.warning("join-request: unknown user %s", user_id)
        await bot.decline_chat_join_request(chat_id, user_id)
        return

    # 3) есть ли запись invite_links?
    link, exp = supabase_client.get_invite(db_user["id"])
    if not link:
        log.info("join-request: no link stored, but approve %s", user_id)


    # (по желанию можно проверить срок действия exp)

    # 4) approve
    try:
        await bot.approve_chat_join_request(chat_id, user_id)
        log.info("join-request approved for %s", user_id)
    except Exception as e:
        log.error("approve failed for %s: %s", user_id, e)
        return

    # 5) личное сообщение (не обязательно)
    try:
        await bot.send_message(
            chat_id=user_id,
            text="✅ Заявка одобрена! Добро пожаловать в TradingGroup.",
            reply_markup=main_menu              # ← показываем меню
        )
    except Exception as e:
        log.warning("Не смог отправить приветственное сообщение пользователю %s: %s",
                    user_id, e)

