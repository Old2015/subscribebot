import logging
import math
import time
import tempfile
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
    """
    Проверяем баланс USDT (TRC20) на адресе 'address'.
    Предполагаем, что TronPy 0.4.x (Contract(...).at(...)).
    """
    try:
        base_c = Contract(client=client, abi=TRC20_ABI, bytecode=b"")
        usdt = base_c.at(USDT_CONTRACT)
        raw = usdt.functions.balanceOf(address)
        return raw / 1_000_000
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
    """
    Псевдо-функция "оплаты" аренды Energy для ephemeral_address на 65k energy, 
    подписывая транзакцию master_privkey (или как-то иначе).
    Реальная реализация требует вызова JustLend или TronLend контракта.
    """
    log.info(f"Rent {energy_amount} energy for ephemeral addr {ephemeral_address}, paying from master. (stub)")
    # TODO: Реализовать либо TronPy-вызов, либо raw REST, 
    #       подписать master_privkey => broadcast
    return True

def sign_and_broadcast_usdt_transfer(ephem_privkey: str, from_addr: str, to_addr: str, amount: float) -> bool:
    """
    Псевдо-функция: создаём транзакцию USDT.transfer(to_addr, amount * 1e6),
    подписываем приватником ephemeral_addr, бродкастим.
    """
    # TODO: TronPy 0.4.x pseudo-code:
    """
    with Tron(provider=provider) as tron:
        txn = (
          tron.trx.build_contract_transaction(
            contract_address=USDT_CONTRACT,
            function_selector="transfer(address,uint256)",
            parameter=[to_addr, int(amount*1e6)],
            fee_limit=5_000_000
          )
          .with_owner(from_addr)
          .build()
          .sign(ephem_privkey)
          .broadcast()
        )
        result = txn.wait()
        if result["receipt"]["result"] == "SUCCESS":
            return True
    """
    log.info(f"sign_and_broadcast_usdt_transfer ephemeral {from_addr}->{to_addr}, amount={amount}")
    return True

async def print_master_balance_at_start(bot: Bot):
    """
    Вызовем при старте бота: вычисляем master address, печатаем (и шлём в ADMIN_CHAT_ID) баланс.
    """
    master_addr, master_priv = derive_master_key_and_address()
    bal = get_usdt_balance(master_addr)
    msg = f"Master Address: {master_addr}\nUSDT Balance: {bal}"
    log.info(msg)
    # Пошлём админу
    try:
        if config.ADMIN_CHAT_ID:
            await bot.send_message(config.ADMIN_CHAT_ID, f"[BOT START] {msg}")
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