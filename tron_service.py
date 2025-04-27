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

    Если нужно отлавливать "свежие" транзакции, 
    можно смотреть логи Transfer(...) за последние N блоков,
    однако для упрощения - читаем просто balanceOf(address).
    """
    if not address:
        return 0.0

    # Адрес см. TronPy. Убедитесь, что address "T..." верный
    usdt_contract = client.get_contract(config.TRC20_USDT_CONTRACT)
    # balanceOf возвращает int (в "микро-USDT", т.к. 6 decimals)
    raw_balance = usdt_contract.functions.balanceOf(address)
    # Переводим в обычные USDT
    balance_usdt = raw_balance / 10**6
    return float(balance_usdt)


async def poll_trc20_transactions(bot: Bot):
    """
    Вызывается каждые CHECK_INTERVAL_MIN (в main.py).
    1) Ищем пользователей, у кого есть deposit_address,
       и время выдачи <24 ч (т.е. не истекло) 
    2) Проверяем balanceOf(address). 
    3) Если >0 => оформляем подписку, создаём запись в payments, сбрасываем address.
    4) Если истекло 24 ч => сбрасываем address, уведомляем пользователя.
    """
    log.info("Start polling TRC20 transactions...")

    # Получаем всех пользователей c непустым deposit_address
    pending = supabase_client.get_pending_deposits()
    now = datetime.now()

    for row in pending:
        user_id = row["id"]
        telegram_id = row["telegram_id"]
        address = row["deposit_address"]
        created_at = row["deposit_created_at"]

        if not address:
            continue

        hours_passed = (now - created_at).total_seconds() / 3600
        if hours_passed > 24:
            # Срок счёта истёк
            supabase_client.reset_deposit_address(user_id)
            try:
                await bot.send_message(
                    chat_id=telegram_id,
                    text="24 часа истекли, средства на указанный адрес не поступили.\n"
                         "Счёт неактуален. При необходимости сформируйте новый."
                )
            except Exception as e:
                log.warning(f"Failed to send invoice expired msg to {telegram_id}: {e}")
            continue

        # Проверяем баланс
        paid_amount = check_trc20_balance_or_transaction(address)
        if paid_amount > 0:
            # Пользователь оплатил => фиксируем платёж, оформляем подписку
            log.info(f"User {user_id} paid {paid_amount} USDT on {address}!")
            # Сохраняем в payments
            supabase_client.create_payment(
                user_id=user_id,
                txhash="unknown_txhash",  # Здесь можно получить реальный txhash
                amount_usdt=paid_amount,
                days_added=0  # временно 0, но сейчас посчитаем
            )
            # Считаем, на сколько дней хватило:
            # SUBSCRIPTION_PRICE_USDT => DAYS_FOR_100_USDT (например, 30)
            # Если 150 USDT => 30 дней => 1 USDT => 0.2 дней
            # days_for_price = DAYS_FOR_100_USDT / 100 => 30/100=0.3
            # но у нас SUBSCRIPTION_PRICE_USDT (например, 150)
            #   => ratio = DAYS_FOR_100_USDT / (price_usdt / 100)
            # Упростим: ratio = (DAYS_FOR_100_USDT / 100) => per_usdt
            #   => days = paid_amount * per_usdt
            # Но точнее, user wants "всегда в сторону пользователя" => math.ceil.
            # Упростим формулу:
            #   1) base_price = config.SUBSCRIPTION_PRICE_USDT (например, 150)
            #   2) base_days = config.DAYS_FOR_100_USDT (например, 30) => "за 100 USDT"
            #
            # Надо аккуратно: "за 100 USDT" => 30 дней => 1 USDT => 0.3 дней
            # paid_amount => days = paid_amount * 0.3
            # Но base_price=150 => "150 USDT за 30 дней"? Или "100 USDT => 30 дней"? 
            # Смотрим .env: "DAYS_FOR_100_USDT=30" => "100 usdt => 30 дней".
            # => 1 USDT => 0.3 дней => paid_amount => paid_amount*0.3
            # => round up => math.ceil(...)
            ratio = config.DAYS_FOR_100_USDT / 100.0  # 30/100=0.3
            days_to_add = paid_amount * ratio
            # округляем вверх:
            days_to_add_ceil = math.ceil(days_to_add)

            # Обновим payment.days_added
            supabase_client.update_payment_days(user_id, paid_amount, days_to_add_ceil)

            # Продлим подписку
            supabase_client.apply_subscription_extension(user_id, days_to_add_ceil)

            # Сбросим адрес
            supabase_client.reset_deposit_address(user_id)

            # Уведомим пользователя
            sub_info_text = supabase_client.get_user_sub_info(user_id)
            msg_text = (
                f"Оплата {paid_amount:.2f} USDT получена!\n"
                f"Подписка продлена на {days_to_add_ceil} дней.\n"
                f"{sub_info_text}"
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