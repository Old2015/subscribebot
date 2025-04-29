import logging
import math
import time
import tempfile
import requests

from eth_utils import keccak  # для вычисления 4-байтового ID функции
from tronapi import Tron  # псевдокод, можно использовать любую библиотеку для подписания

from datetime import datetime

import config
import supabase_client
from aiogram import Bot

from tronpy import Tron
from tronpy.providers import HTTPProvider
from tronpy.contract import Contract

from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip44DepthError

log = logging.getLogger(__name__)

provider = HTTPProvider("https://api.trongrid.io", api_key=config.TRON_API_KEY)
client = Tron(provider=provider)

TRC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [
            {"name":"_to","type":"address"},
            {"name":"_value","type":"uint256"}
        ],
        "name":"transfer",
        "outputs":[
            {"name":"","type":"bool"}
        ],
        "payable":False,
        "stateMutability":"nonpayable",
        "type":"function"
    }
]

USDT_CONTRACT = config.TRC20_USDT_CONTRACT
TRONGRID_API = "https://api.trongrid.io"

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX    = {c: i for i, c in enumerate(B58_ALPHABET)}

def b58check_decode(addr: str) -> bytes:
    num = 0
    for ch in addr:
        num = num * 58 + B58_INDEX[ch]
    raw = num.to_bytes(25, byteorder="big")        # 1-байт prefix + 20-байт addr + 4-байт checksum
    data, checksum = raw[:-4], raw[-4:]
    from hashlib import sha256
    if checksum != sha256(sha256(data).digest()).digest()[:4]:
        raise ValueError("bad base58 checksum")
    return data          # вернёт b'\x41…' (21 байт)



def derive_master_key_and_address():
    """
    Извлекаем master seed из config.TRON_MASTER_SEED, делаем BIP44: m/44'/195'/0'/0/0.
    Возвращаем (master_address, master_privkey).
    """
    mnemonic = config.TRON_MASTER_SEED
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_m = Bip44.FromSeed(seed_bytes, Bip44Coins.TRON)
    bip44_addr = bip44_m.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

    priv_key_obj = bip44_addr.PrivateKey()
    pub_key_obj  = bip44_addr.PublicKey()

    master_privkey = priv_key_obj.Raw().ToHex()  # hex
    master_address = pub_key_obj.ToAddress()     # 'T...'

    return master_address, master_privkey

def get_usdt_balance(address: str) -> float:
    try:
        # Формируем параметр: 32-байтовый адрес в hex
        # Убираем префикс 41, дополняем слева нулями до 64 символов hex
        addr_bytes = b58check_decode(address)   # 21 байт
        addr_hex = addr_bytes.hex()
        if addr_hex.startswith("41"):
            addr_hex = addr_hex[2:]  # убрать '41'
        param = addr_hex.rjust(64, '0')  # дополняем до 32 байт (64 hex символа)
        # Готовим запрос к TronGrid
        payload = {
            "owner_address": address,
            "contract_address": USDT_CONTRACT,
            "function_selector": "balanceOf(address)",
            "parameter": param,
            "fee_limit": 1_000_000,
            "call_value": 0,
            "visible": True
        }
        headers = {"TRON-PRO-API-KEY": config.TRON_API_KEY}  # если необходим API-KEY
        resp = requests.post(f"{TRONGRID_API}/wallet/triggerconstantcontract",
                             json=payload, headers=headers)
        data = resp.json()
        # TronGrid вернёт результат в поле constant_result (список hex-значений) [oai_citation:1‡quicknode.com](https://www.quicknode.com/docs/tron/wallet-triggersmartcontract#:~:text=constant_result)
        result_hex = data.get("constant_result", [None])[0]
        if result_hex:
            balance_int = int(result_hex, 16)
            return balance_int / 1_000_000  # преобразуем в USDT (6 знаков после запятой)
    except Exception as e:
        log.warning(f"get_usdt_balance({address}) failed: {e}")
    return 0.0

def generate_ephemeral_address() -> dict:
    """
    Генерируем случайный ephemeral address (TronPy).
    Возвращаем { "address": T..., "private_key": hex }.
    """
    data = client.generate_address()
    return {
        "address": data["base58check_address"],
        "private_key": data["private_key"]
    }

def rent_energy(master_privkey: str, ephemeral_address: str, energy_amount: int) -> bool:
    # 1. Определяем адрес контракта Energy Rental (Hex-формат):
    energy_rental_contract = "TU2MJ5Veik1LRAgjeSzEdvmDYx7mefJZvd"
    # Можно использовать Base58 адрес с флагом visible=true

    # 2. Готовим данные вызова функции rentResource(receiver, amount, resourceType=1) 
    #   - receiver: ephemeral_address
    #   - amount: TRX для депозита (Sun)
    #   - resourceType: 1 (энергия)
    function_selector = "rentResource(address,uint256,uint256)"
    resource_type = 1  # 1 = Energy, согласно контракту [oai_citation:1‡docs.justlend.org](https://docs.justlend.org/developers/energy-rental#:~:text=greater%20than%201%20TRX%3B)
    # Преобразуем адрес получателя в 32-байтовый ABI-параметр (с учетом Tron-формата):
    receiver_hex = Tron.address_to_hex(ephemeral_address)  # 0x41... формат (21 байт с префиксом 0x41)
    receiver_param = receiver_hex[2:]  # убираем '0x' для вставки в данные
    receiver_param = receiver_param.ljust(64, '0')  # паддинг справа до 32 байт
    # Вычисляем необходимый депозит TRX для указанного количества энергии:
    trx_amount = calculate_trx_for_energy(energy_amount)  # функция расчёта по актуальному курсу EnergyStakePerTrx
    if trx_amount < 1_000000:  # минимальный депозит 1 TRX (в Sun) [oai_citation:2‡docs.justlend.org](https://docs.justlend.org/developers/energy-rental#:~:text=,be%20greater%20than%201%20TRX)
        trx_amount = 1_000000
    amount_param = format(trx_amount, '064x')  # 32-байтное hex-значение суммы в Sun
    resource_param = format(resource_type, '064x')  # 32-байтное hex-значение (1)
    # Полная строка параметров для ABI (без ID функции):
    parameters = receiver_param + amount_param + resource_param

    # 3. Формируем транзакцию вызова смарт-контракта через TronGrid
    tx_data = {
        "contract_address": energy_rental_contract,
        "owner_address": Tron.address_to_hex(master_address),  # master_address в hex (0x41...)
        "function_selector": function_selector,
        "parameter": parameters,
        "fee_limit": 100_000000,        # fee_limit в Sun (например, 100 TRX лимит на сжигание)
        "call_value": trx_amount,       # отправляемая сумма TRX (депозит), в Sun
        "visible": True                 # указывает, что адреса заданы в Base58 (если мы подаем base58 адреса)
    }
    resp = requests.post("https://api.trongrid.io/wallet/triggersmartcontract", json=tx_data)
    tx = resp.json().get("transaction")  # TransactionExtention.transaction (unsigned)

    if not tx:
        return False  # не удалось сформировать транзакцию
    # 4. Подписываем транзакцию локально приватным ключом master_privkey
    tx_signed = Tron.sign(tx, master_privkey)  # ECDSA secp256k1 подпись SHA256(raw_data)
    # 5. Отправляем подписанную транзакцию в сеть Tron
    resp_broadcast = requests.post("https://api.trongrid.io/wallet/broadcasttransaction", json=tx_signed)
    result = resp_broadcast.json().get("result")
    if not result:
        # если транзакция отклонена, логируем причину (resp_broadcast.json().get("message"))
        return False

    # 6. (Опционально) Сохраняем идентификатор аренды для последующего возврата депозита.
    # В контракте JustLend идентификатором аренды служит комбинация (payer=master, receiver=ephemeral, resourceType=1).
    return True

def sign_and_broadcast_usdt_transfer(ephem_privkey: str, from_addr: str, to_addr: str, amount: float) -> bool:
    # 1. Параметры транзакции transfer(address to, uint256 value)
    usdt_contract = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # USDT (TRC20) контракт на Tron
    function_selector = "transfer(address,uint256)"
    # USDT имеет 6 знаков после запятой, конвертируем сумму в целое количество минимальных единиц (SUN, т.к. 1 USDT = 1e6)
    value = int(amount * 1_000000)
    # Кодируем адрес получателя и сумму по ABI:
    to_hex = Tron.address_to_hex(to_addr)[2:].rjust(64, '0')
    value_hex = format(value, '064x')
    parameters = to_hex + value_hex

    # 2. Создаём транзакцию вызова смарт-контракта USDT.transfer
    tx_data = {
        "contract_address": usdt_contract,
        "owner_address": from_addr,
        "function_selector": function_selector,
        "parameter": parameters,
        "fee_limit": 5_000000,    # лимит по fee, например 5 TRX
        "call_value": 0,         # для вызова TRC20 не отправляем TRX
        "visible": True
    }
    resp = requests.post("https://api.trongrid.io/wallet/triggersmartcontract", json=tx_data)
    tx = resp.json().get("transaction")
    if not tx:
        return False

    # 3. Подписываем транзакцию приватным ключом ephemeral-адреса (from_addr)
    tx_signed = Tron.sign(tx, ephem_privkey)
    # 4. Бродкастим транзакцию в сеть Tron
    resp_broadcast = requests.post("https://api.trongrid.io/wallet/broadcasttransaction", json=tx_signed)
    result = resp_broadcast.json().get("result")
    return bool(result)

async def print_master_balance_at_start(bot: Bot):
    """
    Вызывается при старте бота. 
    1) Высчитываем (master_address, master_privkey).
    2) Получаем баланс.
    3) Пишем в лог, шлём в ADMIN_CHAT_ID.
    """
    master_addr, master_priv = derive_master_key_and_address()
    bal = get_usdt_balance(master_addr)
    msg = (
        f"Bot started.\n"
        f"Master Address: {master_addr}\n"
        f"USDT Balance on Master: {bal:.2f}"
    )
    log.info(msg)
    if config.ADMIN_CHAT_ID:
        try:
            await bot.send_message(config.ADMIN_CHAT_ID, msg)
        except Exception as e:
            log.warning(f"Failed to notify admin about master balance: {e}")

def create_temp_deposit_address(user_id: int):
    """
    Функция, когда пользователь нажимает «Оформить подписку».
    Генерируем ephemeral addr, сохраняем (deposit_address, deposit_privkey).
    """
    ephem = generate_ephemeral_address()
    dep_addr = ephem["address"]
    dep_key  = ephem["private_key"]

    # Записываем в БД
    supabase_client.set_deposit_address_and_privkey(user_id, dep_addr, dep_key)

    # Печатаем
    log.info(f"Сформирован адрес на оплату {dep_addr} (priv={dep_key[:6]}...) для user_id={user_id}")
    return dep_addr

def create_qr_code(data: str) -> str:
    """
    Генерация QR-кода, возврат пути к файлу (PNG).
    """
    try:
        img = qrcode.make(data)
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        img.save(tmp.name)
        return tmp.name
    except Exception as e:
        log.error(f"Error creating QR code: {e}")
        return ""

async def poll_trc20_transactions(bot: Bot):
    """
    Аналогично вашей старой логике, но с переносом USDT:
      1) Если balance>0 => rent_energy(...) + sign_and_broadcast_usdt_transfer(...) => master_addr
      2) create_payment => remove deposit.
    """
    log.info("Start ephemeral poll...")

    master_addr, master_priv = derive_master_key_and_address()
    rows = supabase_client.get_pending_deposits_with_privkey()  
    # SELECT id, telegram_id, deposit_address, deposit_privkey, deposit_created_at FROM users WHERE deposit_address IS NOT NULL ...

    now = datetime.now()
    for row in rows:
        user_id     = row["id"]
        tg_id       = row["telegram_id"]
        dep_addr    = row["deposit_address"]
        dep_privkey = row["deposit_privkey"]
        created_at  = row["deposit_created_at"]

        if not dep_addr or not dep_privkey:
            continue

        hours_passed = (now - created_at).total_seconds() / 3600
        if hours_passed>24:
            supabase_client.reset_deposit_address_and_privkey(user_id)
            try:
                await bot.send_message(
                    chat_id=tg_id,
                    text=(
                        "24 часа истекли, а средства не поступили.\n"
                        "Счёт аннулирован. При необходимости сформируйте новый."
                    )
                )
            except Exception as e:
                log.warning(f"Failed to send expire msg to {tg_id}: {e}")
            continue

        bal = get_usdt_balance(dep_addr)
        if bal>0:
            log.info(f"Средства на адресе {dep_addr} обнаружены: {bal} USDT.")
            # rent energy
            ok_energy = rent_energy(master_priv, dep_addr, 65000)
            if not ok_energy:
                log.warning(f"rent_energy failed for {dep_addr}")
                continue
            log.info(f"Оплачена аренда энергии для {dep_addr} ~3-4 TRX")

            # sign & broadcast
            tx_ok = sign_and_broadcast_usdt_transfer(dep_privkey, dep_addr, master_addr, bal)
            if not tx_ok:
                log.warning(f"transfer USDT failed from {dep_addr}")
                continue
            log.info(f"Средства переведены на основной адрес {master_addr} = {bal} USDT.")

            # Запись о платеже
            supabase_client.create_payment(user_id, "unknown_txhash", bal, 0)

            # Продлеваем подписку
            ratio = config.DAYS_FOR_100_USDT/100.0
            days_float = bal*ratio
            days_rounded=math.ceil(days_float)
            supabase_client.update_payment_days(user_id, bal, days_rounded)
            supabase_client.apply_subscription_extension(user_id, days_rounded)

            # Сбрасываем
            supabase_client.reset_deposit_address_and_privkey(user_id)

            # Текущий баланс master
            master_bal = get_usdt_balance(master_addr)
            log.info(f"Текущий баланс основного адреса {master_addr} = {master_bal} USDT.")

            # Уведомляем
            sub_text = supabase_client.get_user_sub_info(user_id)
            msg = (
                f"Оплата {bal:.2f} USDT получена!\n"
                f"Подписка продлена на {days_rounded} дней.\n"
                f"{sub_text}\n"
                f"Текущий баланс MASTER: {master_bal:.2f} USDT"
            )
            try:
                await bot.send_message(tg_id, msg)
            except Exception as e:
                log.warning(f"Failed to notify user {tg_id} about payment: {e}")

    log.info("Finished ephemeral poll.")