import os
from dotenv import load_dotenv
from aiogram import Bot

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN", "TEST")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
PRIVATE_GROUP_ID = os.getenv("PRIVATE_GROUP_ID")

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

TRON_MASTER_SEED = os.getenv("TRON_MASTER_SEED")
TRC20_USDT_CONTRACT = os.getenv("TRC20_USDT_CONTRACT")

SUBSCRIPTION_PRICE_USDT = float(os.getenv("SUBSCRIPTION_PRICE_USDT", "100"))
FREE_TRIAL_DAYS = int(os.getenv("FREE_TRIAL_DAYS", "2"))

# Новая переменная
FREE_TRIAL_GLOBAL_END = os.getenv("FREE_TRIAL_GLOBAL_END", "")
# Превратим в datetime.date, если строка не пуста
from datetime import datetime
GLOBAL_END_DATE = None
if FREE_TRIAL_GLOBAL_END:
    # Парсим yyyy-mm-dd
    GLOBAL_END_DATE = datetime.strptime(FREE_TRIAL_GLOBAL_END, "%Y-%m-%d").date()

CHECK_INTERVAL_MIN = int(os.getenv("CHECK_INTERVAL_MIN", "10"))
DAILY_ANALYSIS_TIME = os.getenv("DAILY_ANALYSIS_TIME", "09:00")

bot = Bot(token=BOT_TOKEN)