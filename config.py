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
TRON_API_KEY = os.getenv("TRON_API_KEY")

SUBSCRIPTION_PRICE_USDT = float(os.getenv("SUBSCRIPTION_PRICE_USDT", "100"))
DAYS_FOR_USDT = int(os.getenv("DAYS_FOR_USDT", "30"))

# ─── TRON / комиссии ───────────────────────────────────────────
# “дорогой” лимит – первый перевод на адрес, где ещё нет USDT  
TRC20_USDT_FEE_LIMIT_FIRST  = 40_000_000      # 40 TRX в Sun  
# “обычный” лимит – повторные переводы  
TRC20_USDT_FEE_LIMIT        = 25_000_000      # 25 TRX в Sun  

# сколько секунд ждём, пока 30 TRX «дойдут» до депозита  
WAIT_DEPOSIT_CONFIRM_SEC    = 25              # ≈ 1 блок

# после скольких подряд ошибок перевода уведомлять админа  
MAX_USDT_ERRORS             = 3



# Новая переменная
FREE_TRIAL_GLOBAL_END = os.getenv("FREE_TRIAL_GLOBAL_END", "")
GLOBAL_END_DATE = None
if FREE_TRIAL_GLOBAL_END:
    from datetime import datetime
    GLOBAL_END_DATE = datetime.strptime(FREE_TRIAL_GLOBAL_END, "%Y-%m-%d").date()

FREE_TRIAL_DAYS = int(os.getenv("FREE_TRIAL_DAYS", "10"))

CHECK_INTERVAL_MIN = int(os.getenv("CHECK_INTERVAL_MIN", "10"))
DAILY_ANALYSIS_TIME = os.getenv("DAILY_ANALYSIS_TIME", "09:00")

bot = Bot(token=BOT_TOKEN)