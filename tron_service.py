import logging
import math
import time
from datetime import datetime
import tempfile
import qrcode

# Важно: Импорт Tron, HttpProvider из tronpy
from tronpy import Tron
from tronpy.providers import HTTPProvider

# Импорты из вашего проекта
import config
import supabase_client
from aiogram import Bot
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip44DepthError

log = logging.getLogger(__name__)

# Инициализируем TronPy-клиент через provider=HTTPProvider(...)
# Для mainnet используем https://api.trongrid.io
client = Tron(provider=HTTPProvider("https://api.trongrid.io"))

def check_trc20_balance_or_transaction(address: str) -> float:
    """
    Проверяем, сколько USDT (TRC20) лежит на указанном address (баланс).
    Возвращаем float (количество USDT).

    Используем TronPy:
      - Получаем контракт USDT: client.get_contract(config.TRC20_USDT_CONTRACT)
      - Вызываем balanceOf(address)
      - Делим на 1e6 (6 decimals)
    """
    if not address:
        return 0.0

    try:
        contract = client.get_contract(config.TRC20_USDT_CONTRACT)
        raw_balance = contract.functions.balanceOf(address)
        balance_usdt = raw_balance / 10**6
        return float(balance_usdt)
    except Exception as e:
        log.error(f"Error checking TRC20 balance for {address}: {e}")
        return 0.0

async def poll_trc20_transactions(bot: Bot):
    """
    Вызывается каждые CHECK_INTERVAL_MIN (в main.py).

    Логика:
      1) Берём пользователей c ненулевым deposit_address
      2) Если прошло >24ч от deposit_created_at -> сбрасываем адрес, уведомляем
      3) Иначе смотрим check_trc20_balance_or_transaction(...)
         - если >0 -> значит оплатили
           => создаём payment, считаем дни (ceil), продлеваем подписку, сбрасываем адрес, уведомляем
    """
    log.info("Start polling TRC20 transactions...")

    pending = supabase_client.get_pending_deposits()
    now = datetime.now()

    for row in pending:
        user_id = row["id"]
        telegram_id = row["telegram_id"]
        address = row["deposit_address"]
        created_at = row["deposit_created_at"]

        if not address:
            continue

        # Проверка времени
        hours_passed = (now - created_at).total_seconds() / 3600
        if hours_passed > 24:
            # Срок счёта истёк
            supabase_client.reset_deposit_address(user_id)
            try:
                await bot.send_message(
                    chat_id=telegram_id,
                    text="24 часа истекли, а средства на указанный адрес не поступили.\n"
                         "Счёт неактуален. При необходимости сформируйте новый."
                )
            except Exception as e:
                log.warning(f"Failed to send invoice-expired msg to {telegram_id}: {e}")
            continue

        # Иначе проверяем баланс
        paid_amount = check_trc20_balance_or_transaction(address)
        if paid_amount > 0:
            log.info(f"User {user_id} paid {paid_amount:.2f} USDT on {address}")

            # Создаём запись в payments (days_added=0 пока что)
            supabase_client.create_payment(
                user_id=user_id,
                txhash="unknown_txhash",
                amount_usdt=paid_amount,
                days_added=0
            )

            # Сколько дней положено? 
            # 100 USDT => config.DAYS_FOR_100_USDT (напр. 30)
            ratio = config.DAYS_FOR_100_USDT / config.SUBSCRIPTION_PRICE_USDT
            days_float = paid_amount * ratio
            days_rounded = math.ceil(days_float)

            # Обновим days_added в payments
            supabase_client.update_payment_days(user_id, paid_amount, days_rounded)
            # Продлим подписку
            supabase_client.apply_subscription_extension(user_id, days_rounded)
            # Сбросим адрес
            supabase_client.reset_deposit_address(user_id)

            # Уведомим пользователя
            sub_text = supabase_client.get_user_sub_info(user_id)
            msg_text = (
                f"Оплата {paid_amount:.2f} USDT получена!\n"
                f"Ваша подписка продлена на {days_rounded} дней.\n"
                f"{sub_text}"
            )
            try:
                await bot.send_message(telegram_id, text=msg_text)
            except Exception as e:
                log.warning(f"Failed to notify user {telegram_id} about payment: {e}")

    log.info("Finished polling TRC20 transactions.")

def create_qr_code(data: str) -> str:
    """
    Генерирует PNG-файл с QR-кодом. Возвращает путь к файлу.
    """
    try:
        img = qrcode.make(data)
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        img.save(tmp.name)
        return tmp.name
    except Exception as e:
        log.error(f"Error creating QR code: {e}")
        return ""

def generate_new_tron_address(index: int) -> dict:
    """
    Используем master seed (TRON_MASTER_SEED) из .env и BIP44 для Tron:
      - coin_type=195
      - путь: m/44'/195'/0'/0/index
    Возвращаем {"address": "T...", "private_key": "hex"}
    """
    try:
        seed_bytes = Bip39SeedGenerator(config.TRON_MASTER_SEED).Generate()
        bip44_m = Bip44.FromSeed(seed_bytes, Bip44Coins.TRON)
        bip44_addr = bip44_m.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(index)

        priv_key_obj = bip44_addr.PrivateKey()
        pub_key_obj = bip44_addr.PublicKey()

        private_key_hex = priv_key_obj.Raw().ToHex()
        tron_address = pub_key_obj.ToAddress()  # 'T...' 

        return {
            "address": tron_address,
            "private_key": private_key_hex
        }

    except Bip44DepthError as e:
        log.error(f"Index out of depth for BIP44: {e}")
        return {"address": "", "private_key": ""}
    except Exception as e:
        log.error(f"Error generating Tron address from seed: {e}")
        return {"address": "", "private_key": ""}