import config
import supabase_client
from aiogram import Bot

async def send_daily_report(bot: Bot):
    data = supabase_client.get_admin_report_data()
    text = (
        "Ежедневный отчет:\n"
        f"Активных подписчиков: {data['active_subscribers']}\n"
        f"Всего пользователей: {data['total_users']}\n"
        f"Сумма за месяц: {data['month_sum']} USDT\n"
        f"Сумма за год: {data['year_sum']} USDT\n"
        f"Сумма за всю историю: {data['all_time_sum']} USDT\n"
        f"Подписок за сутки: {data['subscribed_24h']}\n"
        f"Потеряли подписку за сутки: {data['unsubscribed_24h']}\n"
        f"Сумма за сутки: {data['sum_24h']} USDT\n"
    )
    await bot.send_message(config.ADMIN_CHAT_ID, text)
