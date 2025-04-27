import logging
import tempfile
import qrcode
from datetime import datetime
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip44DepthError
from config import TRON_MASTER_SEED

log = logging.getLogger(__name__)


# Инициализация TronPy (mainnet по умолчанию).
# При желании можно указать: Tron(full_node='https://api.trongrid.io')
client = Tron(full_node='https://api.trongrid.io')

def check_trc20_balance_or_transaction(address: str) -> float:
    """
    Реально проверяем, сколько USDT (TRC20) лежит на указанном address.
    Возвращаем float (количество USDT).

    Используем TronPy для вызова контракта USDT (config.TRC20_USDT_CONTRACT).
    Предполагаем, что "address" – это Base58check формат (T...).
    """
    if not address:
        return 0.0

    # Получаем контракт USDT
    try:
        contract = client.get_contract(config.TRC20_USDT_CONTRACT)
    except Exception as e:
        log.error(f"Failed to get USDT contract: {e}")
        return 0.0

    try:
        raw_balance = contract.functions.balanceOf(address)
        # USDT обычно имеет 6 decimals => делим на 10^6
        balance_usdt = raw_balance / 10**6
        return float(balance_usdt)
    except Exception as e:
        log.error(f"Error calling balanceOf for {address}: {e}")
        return 0.0

async def poll_trc20_transactions(bot: Bot):
    """
    Вызывается каждые CHECK_INTERVAL_MIN (в main.py).
    1) Получаем пользователей, у кого есть deposit_address (не пуст).
    2) Если >24ч от deposit_created_at => сбрасываем, уведомляем
    3) Иначе check_trc20_balance_or_transaction(address)
       - если > 0 => оформляем подписку, сбрасываем address, уведомляем
    """
    log.info("Start polling TRC20 transactions...")

    pending = supabase_client.get_pending_deposits()  # Все пользователи с ненулевым deposit_address
    now = datetime.now()

    for row in pending:
        user_id = row["id"]
        telegram_id = row["telegram_id"]
        address = row["deposit_address"]
        created_at = row["deposit_created_at"]

        if not address:
            continue

        # Сколько часов прошло?
        hours_passed = (now - created_at).total_seconds() / 3600
        if hours_passed > 24:
            # Срок устарел
            supabase_client.reset_deposit_address(user_id)
            try:
                await bot.send_message(
                    chat_id=telegram_id,
                    text=("24 часа истекли, а средства не поступили на адрес.\n"
                          "Счёт аннулирован. Сформируйте новый, если нужно.")
                )
            except Exception as e:
                log.warning(f"Failed to send 'invoice expired' msg to {telegram_id}: {e}")
            continue

        # Проверяем баланс
        paid_amount = check_trc20_balance_or_transaction(address)
        if paid_amount > 0:
            # Оплата поступила
            log.info(f"User {user_id} paid {paid_amount:.2f} USDT on {address}")
            # Создаём запись в payments
            supabase_client.create_payment(
                user_id=user_id,
                txhash="unknown_txhash",  # при желании можно получить реальный txhash
                amount_usdt=paid_amount,
                days_added=0  # пока 0, обновим позже
            )

            # Считаем количество дней.
            # Логика: "100 USDT => config.DAYS_FOR_100_USDT" (например, 30)
            ratio = config.DAYS_FOR_100_USDT / 100.0
            days_float = paid_amount * ratio
            # Округляем В БОЛЬШУЮ сторону
            days_rounded = math.ceil(days_float)

            # Обновляем days_added
            supabase_client.update_payment_days(user_id, paid_amount, days_rounded)
            # Применяем продление подписки
            supabase_client.apply_subscription_extension(user_id, days_rounded)
            # Сбрасываем адрес
            supabase_client.reset_deposit_address(user_id)

            # Уведомим пользователя
            sub_text = supabase_client.get_user_sub_info(user_id)
            msg_text = (
                f"Оплата {paid_amount:.2f} USDT получена!\n"
                f"Ваша подписка продлена на {days_rounded} дней.\n"
                f"{sub_text}"
            )
            try:
                await bot.send_message(
                    chat_id=telegram_id,
                    text=msg_text
                )
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

    Возвращаем dict: {"address": "Txxx...", "private_key": "hex"}
    """
    try:
        # 1) Генерируем seed из сид-фразы
        #   В библиотеках bip_utils актуальная сигнатура:
        #   seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
        seed_bytes = Bip39SeedGenerator(TRON_MASTER_SEED).Generate()

        # 2) Инициализируем BIP44 для Tron
        bip44_m = Bip44.FromSeed(seed_bytes, Bip44Coins.TRON)

        # 3) Деривация: m/44'/195'/0'/0/index
        bip44_addr = bip44_m.Purpose() \
                            .Coin() \
                            .Account(0) \
                            .Change(Bip44Changes.CHAIN_EXT) \
                            .AddressIndex(index)

        priv_key_obj = bip44_addr.PrivateKey()
        pub_key_obj = bip44_addr.PublicKey()

        private_key_hex = priv_key_obj.Raw().ToHex()
        tron_address = pub_key_obj.ToAddress()   # 'T...' Tron base58 address

        return {
            "address": tron_address,
            "private_key": private_key_hex
        }

    except Bip44DepthError as e:
        log.error(f"Index out of depth for BIP44: {e}")
        return {
            "address": "",
            "private_key": ""
        }
    except Exception as e:
        log.error(f"Error generating Tron address from seed: {e}")
        return {
            "address": "",
            "private_key": ""
        }