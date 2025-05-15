# admin_report.py


import logging
from datetime import datetime, timezone
from aiogram import Bot
from tron_service import derive_master, get_usdt_balance, get_total_balance_v2
import config
import supabase_client

log = logging.getLogger(__name__)

_SQL = {
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
        "WHERE created_at >= NOW() - interval '1 day';",
    "payments_day":
        "SELECT COUNT(*), COALESCE(SUM(amount_usdt),0) FROM payments "
        "WHERE paid_at >= NOW() - interval '1 day';",
    "trial_active":
        "SELECT COUNT(*) FROM users WHERE trial_end > NOW();",
    "sub_active":
        "SELECT COUNT(*) FROM users WHERE subscription_end > NOW();",
}

def _fetch_one(query):
    with supabase_client._get_connection() as conn, conn.cursor() as cur:
        cur.execute(query)
        return cur.fetchone()

async def send_admin_report(bot: Bot):
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

    today = datetime.now(timezone.utc).astimezone().strftime("%d.%m.%Y")

    
    # ───── 2. данные мастер‑кошелька ──────────────────────────
    master_addr, _ = derive_master()                       # ← РАЗВОРАЧИВАЕМ кортеж
    usdt_master    = get_usdt_balance(master_addr)         # str → float
    _, total_sun   = get_total_balance_v2(master_addr)     # ← берём total_sun
    trx_master     = total_sun / 1_000_000                 # Sun → TRX


    text = (
        f"*Ежедневный отчёт — {today}*\n\n"
        f"• Баланс мастер‑кошелька: {usdt_master:.2f} USDT | {trx_master:.2f} TRX\n\n"
        f"• Всего пользователей в базе: **{users_tot}**\n"
        f"• Всего платежей в базе: **{pays_tot}** на сумму **{usdt_tot:.2f} USDT**\n\n"
        f"• Новых пользователей за текущий месяц: **{users_mon}**\n"
        f"• Платежей за текущий месяц: **{pays_mon}** на сумму **{usdt_mon:.2f} USDT**\n\n"
        f"• Новых пользователей за сутки: **{users_day}**\n"
        f"• Платежей за сутки: **{pays_day}** на сумму **{usdt_day:.2f} USDT**\n\n"
        f"• Активных тестовых доступов: **{trial_cnt}**\n"
        f"• Активных подписок: **{sub_cnt}**"
    )

    try:
        await bot.send_message(config.ADMIN_CHAT_ID, text, parse_mode="Markdown")
        log.info("Admin report sent ✔")
    except Exception as e:
        log.error("Failed to send admin report: %s", e)