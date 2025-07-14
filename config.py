import os                                           # доступ к переменным окружения
from dotenv import load_dotenv                      # загрузка .env файла
from aiogram import Bot                             # класс Bot
import aiohttp, ssl
from aiogram.client.session.aiohttp import AiohttpSession   # ← новый импорт
from aiogram.client.default import DefaultBotProperties
from typing import Optional
import certifi                                      # сертификаты Mozilla


load_dotenv()  # загружаем переменные окружения из .env

BOT_TOKEN = os.getenv("BOT_TOKEN", "TEST")
ADMIN_CHAT_ID     = int(os.getenv("ADMIN_CHAT_ID",   "0") or 0)
PRIVATE_GROUP_ID  = int(os.getenv("PRIVATE_GROUP_ID","0") or 0)

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

FREE_TRIAL_DAYS = int(os.getenv("FREE_TRIAL_DAYS", "7"))

CHECK_INTERVAL_MIN = int(os.getenv("CHECK_INTERVAL_MIN", "20"))
DAILY_ANALYSIS_TIME = os.getenv("DAILY_ANALYSIS_TIME", "00:01")
LOG_ON_THE_START = os.getenv("LOG_ON_THE_START", "false").lower() == "true"


# ─── доверяем сертификатам Mozilla заранее ──────────────────────
#  ♦  Python (особенно macOS-сборка) может «не видеть» системные CA.
#  ♦  Достаём свежий pem из certifi и объявляем его дефолтным.
os.environ.setdefault("SSL_CERT_FILE", certifi.where())
# ----------------------------------------------------------------

_bot_singleton: Optional[Bot] = None         # кеш-одиночка


def make_bot() -> Bot:
    """
    Возвращает singleton-экземпляр Bot с *обычной* aiohttp-сессией,
    но уже знающей о корневых CA (см. строку с SSL_CERT_FILE выше).
    """
    global _bot_singleton                    # pylint: disable=global-statement
    if _bot_singleton:
        return _bot_singleton

    _bot_singleton = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode="HTML"),   # ≤ aiogram-3.20
        # session=None → aiogram сам создаст AiohttpSession c правильным SSL
    )
    return _bot_singleton

