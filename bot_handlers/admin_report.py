# bot_handlers/admin_report.py
from aiogram import Bot
from services.supabase_client import get_admin_report_data
from config import ADMIN_CHAT_ID

async def send_daily_report(bot: Bot):
    """
    Формируем текстовый отчёт по состоянию на сейчас, отправляем в админ-группу.
    """
    report_data = get_admin_report_data()
    # Пример структуры report_data:
    # {
    #   "active_subscribers": 10,
    #   "total_users": 30,
    #   "month_sum": 500,
    #   "year_sum": 2000,
    #   "all_time_sum": 5000,
    #   "subscribed_24h": 2,
    #   "unsubscribed_24h": 1,
    #   "sum_24h": 200
    # }
    text = (
        "Ежедневный отчет:\n"
        f"Активных подписчиков: {report_data['active_subscribers']}\n"
        f"Всего пользователей: {report_data['total_users']}\n"
        f"Сумма (месяц): {report_data['month_sum']} USDT\n"
        f"Сумма (год): {report_data['year_sum']} USDT\n"
        f"Сумма (вся): {report_data['all_time_sum']} USDT\n"
        f"Новых за сутки: {report_data['subscribed_24h']}\n"
        f"Потеряли подписку за сутки: {report_data['unsubscribed_24h']}\n"
        f"Сумма за сутки: {report_data['sum_24h']} USDT\n"
    )
    await bot.send_message(ADMIN_CHAT_ID, text)
