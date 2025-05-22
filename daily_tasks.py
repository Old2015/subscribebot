# daily_tasks.py
import asyncio                              # util для асинхронных пауз
import logging                              # логирование
from datetime import datetime, timezone    # работа с датами/временем
from aiogram import Bot                    # тип бота
import config                              # настройки
import supabase_client                     # функции работы с БД

log = logging.getLogger(__name__)

RATE_LIMIT  = 0.06             # задержка между сообщениями, чтобы не ловить flood
NOTIFY_DAYS = (3, 1)           # дни до окончания, когда шлём напоминание

def as_utc(dt):
    """Возвращает datetime в UTC (если tzinfo отсутствует)."""
    return dt if (dt and dt.tzinfo) else (dt and dt.replace(tzinfo=timezone.utc))

async def run_daily_tasks(bot: Bot):
    """
    • Напоминаем о скором окончании доступа (7/3/1 день).
    • Если триал/подписка уже закончились — уведомляем и кикаем пользователя.
    """
    # Основная ежедневная процедура
    log.info("Running daily tasks…")
    stats = {"trial_warn": 0, "sub_warn": 0, "kicked": 0}

    users = supabase_client.get_all_users()          # SELECT * FROM users
    now   = datetime.now(timezone.utc)

    for user in users:                     # обходим всех пользователей
        tg_id       = user["telegram_id"]
        trial_end   = as_utc(user.get("trial_end"))
        sub_start   = as_utc(user.get("subscription_start"))
        sub_end     = as_utc(user.get("subscription_end"))

        has_active_sub  = sub_end and sub_end > now  # текущая подписка активна
        sub_future_only = sub_start and sub_start > now  # подписка ещё не началась
        trial_active    = trial_end and trial_end > now   # триал действует

        # 1. Напоминания о скором окончании --------------------------------
        #    Отправляем уведомления за 3 и 1 день до конца доступа
        if trial_active:
            days_left = (trial_end.date() - now.date()).days
            if days_left in NOTIFY_DAYS:
                try:
                    await bot.send_message(
                        tg_id,
                        f"Тестовый доступ заканчивается через {days_left} дн. "
                        f"({trial_end.strftime('%d.%m.%Y')}).",
                    )
                    stats["trial_warn"] += 1
                except Exception as e:
                    log.error("Trial notice failed for %s: %s", tg_id, e)
                await asyncio.sleep(RATE_LIMIT)

        if has_active_sub:
            days_left = (sub_end.date() - now.date()).days
            if days_left in NOTIFY_DAYS:
                try:
                    await bot.send_message(
                        tg_id,
                        f"Подписка заканчивается через {days_left} дн. "
                        f"({sub_end.strftime('%d.%m.%Y')}).",
                    )
                    stats["sub_warn"] += 1
                except Exception as e:
                    log.error("Sub notice failed for %s: %s", tg_id, e)
                await asyncio.sleep(RATE_LIMIT)

        # 2. Доступ истёк → уведомляем и кикаем ----------------------------
        #    Нет ни подписки, ни триала — удаляем пользователя из группы
        if (not has_active_sub) and (not trial_active) and (not sub_future_only):
            # a) Уведомление
            try:
                await bot.send_message(
                    tg_id,
                    "Ваш доступ к TradingGroup завершён. "
                    "Чтобы восстановить доступ, оформите подписку.",
                    disable_notification=True,
                )
            except Exception as e:
                log.warning("Cannot send expire notice to %s: %s", tg_id, e)

            await asyncio.sleep(RATE_LIMIT)

            # b) Кикаем без последующего unban
            try:
                await bot.ban_chat_member(
                    chat_id=config.PRIVATE_GROUP_ID,
                    user_id=tg_id,
                    revoke_messages=True,
                )
                stats["kicked"] += 1
            except Exception as e:
                log.error("Kick failed for %s: %s", tg_id, e)

            await asyncio.sleep(RATE_LIMIT)

    log.info(
        "Daily tasks finished: trial_warn=%d, sub_warn=%d, kicked=%d",
        stats["trial_warn"], stats["sub_warn"], stats["kicked"],
    )  # выводим статистику в лог

