# admin_report.py


import logging                                    # логирование
from datetime import datetime, timezone           # работа со временем
from aiogram import Bot                           # тип бота
from tron_service import derive_master, get_usdt_balance, get_total_balance_v2
from html import escape as html_escape
import config                                     # настройки проекта
import supabase_client                            # работа с БД

log = logging.getLogger(__name__)

_SQL = {  # набор SQL-запросов для статистики
    "users_total":
        "SELECT COUNT(*) FROM users;",
    "payments_total":
        "SELECT COUNT(*), COALESCE(SUM(amount_usdt),0) FROM payments;",
    "users_month":
        "SELECT COUNT(*) FROM users "
        "WHERE created_at >= date_trunc('month', NOW());",
    "payments_month":
        "SELECT COUNT(*), COALESCE(SUM(amount_usdt),0) FROM payments "
        "WHERE paid_at >= date_trunc('month', NOW());",
    "users_day":
        "SELECT COUNT(*) FROM users "
        "WHERE created_at >= date_trunc('day', NOW()) - interval '1 day' "
        "AND created_at <  date_trunc('day', NOW());",
    "payments_day":
        "SELECT COUNT(*), COALESCE(SUM(amount_usdt),0) FROM payments "
        "WHERE paid_at >= NOW() - interval '1 day';",
    "trial_active":
        "SELECT COUNT(*) FROM users WHERE trial_end > NOW();",
    "sub_active":
        "SELECT COUNT(*) FROM users WHERE subscription_end > NOW();",
    "users_active":
        "SELECT COUNT(DISTINCT telegram_id) FROM users "
        "WHERE trial_end > NOW() OR subscription_end > NOW();",
}

def _fetch_one(query):
    """Выполняет запрос и возвращает одну строку."""
    with supabase_client._get_connection() as conn, conn.cursor() as cur:
        cur.execute(query)
        return cur.fetchone()

async def send_admin_report(bot: Bot) -> None:
    """Формирует текстовый отчёт и отправляет администратору."""
    kicked_users = supabase_client.get_expired_users_last_day()
    try:
        metrics = {k: _fetch_one(q) for k, q in _SQL.items()}
    except Exception as e:
        log.error("Admin report SQL failed: %s", e)
        return

    users_tot = metrics["users_total"][0]
    pays_tot, usdt_tot = metrics["payments_total"]
    users_mon = metrics["users_month"][0]
    pays_mon, usdt_mon = metrics["payments_month"]
    users_day = metrics["users_day"][0]
    pays_day, usdt_day = metrics["payments_day"]
    trial_cnt = metrics["trial_active"][0]
    sub_cnt   = metrics["sub_active"][0]
    active_cnt = metrics["users_active"][0]

    new_users = supabase_client.get_new_users_last_day()

    today = datetime.now(timezone.utc).astimezone().strftime("%d.%m.%Y")

    
    # ───── 2. данные мастер‑кошелька ──────────────────────────
    master_addr, _ = derive_master()                       # ← РАЗВОРАЧИВАЕМ кортеж
    usdt_master    = get_usdt_balance(master_addr)         # str → float
    _, total_sun   = get_total_balance_v2(master_addr)     # ← берём total_sun
    trx_master     = total_sun / 1_000_000                 # Sun → TRX


    new_users_lines = "".join(
        f"• • {uid} - {html_escape(uname or 'NoUsername')}\n"
        for uid, uname in new_users
    )
    kicked_lines = "".join(
        f"• • {uid} - {html_escape(uname or 'NoUsername')}\n"
        for uid, uname in kicked_users
    )

    text = (
        f"<b>Ежедневный отчёт — {today}</b>\n\n"
        f"• Баланс мастер‑кошелька: {usdt_master:.2f} USDT | {trx_master:.2f} TRX\n\n"
        f"• Всего пользователей в базе: <b>{users_tot}</b>\n"
        f"• Всего платежей в базе: <b>{pays_tot}</b> на сумму <b>{usdt_tot:.2f} USDT</b>\n\n"
        f"• Новых пользователей за текущий месяц: <b>{users_mon}</b>\n"
        f"• Платежей за текущий месяц: <b>{pays_mon}</b> на сумму <b>{usdt_mon:.2f} USDT</b>\n"
        f"• Платежей за сутки: <b>{pays_day}</b> на сумму <b>{usdt_day:.2f} USDT</b>\n\n"
        f"• Новых пользователей за сутки: <b>{users_day}</b>\n"
        f"{new_users_lines if new_users_lines else ''}"
        f"• Удалено пользователей за сутки: <b>{len(kicked_users)}</b>\n"
        f"{kicked_lines if kicked_lines else ''}\n"
        f"• Всего активных пользователей в базе: <b>{active_cnt}</b>\n"
        f"• •  в т.ч. по тестам: <b>{trial_cnt}</b>\n"
        f"• •  в т.ч. по подпискам: <b>{sub_cnt}</b>"
    )

    try:
        await bot.send_message(config.ADMIN_CHAT_ID, text, parse_mode="HTML")  # отправляем отчёт
        log.info("Admin report sent ✔")
    except Exception as e:
        log.error("Failed to send admin report: %s", e)

