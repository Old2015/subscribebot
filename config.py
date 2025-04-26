# config.py
import os
from dotenv import load_dotenv
from aiogram import Bot

load_dotenv()

# Telegram
BOT_TOKEN = os.getenv("BOT_TOKEN", "TEST")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
PRIVATE_GROUP_ID = os.getenv("PRIVATE_GROUP_ID")

# Supabase / Postgres
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

# Tron / TRC20
TRON_MASTER_SEED = os.getenv("TRON_MASTER_SEED")
TRC20_USDT_CONTRACT = os.getenv("TRC20_USDT_CONTRACT")

# Подписка
SUBSCRIPTION_PRICE_USDT = float(os.getenv("SUBSCRIPTION_PRICE_USDT", "100"))
DAYS_FOR_100_USDT = int(os.getenv("DAYS_FOR_100_USDT", "30"))

# FREE trial days
FREE_TRIAL_DAYS = int(os.getenv("FREE_TRIAL_DAYS", "2"))  # по умолчанию 2 суток

# Интервалы и расписания
CHECK_INTERVAL_MIN = int(os.getenv("CHECK_INTERVAL_MIN", "10"))
DAILY_ANALYSIS_TIME = os.getenv("DAILY_ANALYSIS_TIME", "09:00")

# Aiogram Bot instance (singleton)
bot = Bot(token=BOT_TOKEN)
