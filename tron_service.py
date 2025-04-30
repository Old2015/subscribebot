#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tron_service.py — вся работа с TRON через TronGrid (без tronpy/TronWeb).
"""

import os, math, time, base64, logging, tempfile, requests, qrcode, base58, ecdsa, hashlib
from datetime import datetime
from typing import Tuple, Optional, Dict

import config, supabase_client
from aiogram import Bot
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes

log = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────
# 1.  Константы / конфиг
# ────────────────────────────────────────────────────────────────
TRONGRID_API = "https://api.trongrid.io"
HEADERS      = {"TRON-PRO-API-KEY": config.TRON_API_KEY} if config.TRON_API_KEY else {}

USDT_CONTRACT  = config.TRC20_USDT_CONTRACT or "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
ENERGY_MARKET  = "TU2MJ5Veik1LRAgjeSzEdvmDYx7mefJZvd"          # JustLend DAO
RESOURCE_ENERGY = 1                                            # 1 = Energy

# Цена энергии (units per 1 TRX). Желательно хранить в .env
ENERGY_PER_TRX = int(os.getenv("ENERGY_PER_TRX", "15000"))

# ────────────────────────────────────────────────────────────────
# 2.  Keccak-256 (без зависимости от openssl 3.0)
# ────────────────────────────────────────────────────────────────
try:
    import sha3                  # pysha3
    def keccak_256(data: bytes) -> bytes:
        k = sha3.keccak_256(); k.update(data); return k.digest()
except ImportError:
    from Crypto.Hash import keccak    # pycryptodome
    def keccak_256(data: bytes) -> bytes:
        return keccak.new(data=data, digest_bits=256).digest()

# ────────────────────────────────────────────────────────────────
# 3.  Base58 utils
# ────────────────────────────────────────────────────────────────
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_IDX = {c: i for i, c in enumerate(_B58)}

def b58decode_check(addr: str) -> bytes:
    num = 0
    for ch in addr: num = num*58 + _B58_IDX[ch]
    raw = num.to_bytes(25, "big")
    if hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        raise ValueError("Bad base58 checksum")
    return raw[:-4]      # 21 bytes (0x41 + 20)

def b58_to_hex(addr: str) -> str:
    return b58decode_check(addr).hex()           # 41…

def hex_to_b58(hex_addr: str) -> str:
    if hex_addr.startswith("0x"): hex_addr = hex_addr[2:]
    raw = bytes.fromhex(hex_addr)
    chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return base58.b58encode(raw + chk).decode()

def pub_to_b58(pub65: bytes) -> str:
    h = keccak_256(pub65[1:])
    addr = b"\x41" + h[-20:]
    chk  = hashlib.sha256(hashlib.sha256(addr).digest()).digest()[:4]
    return base58.b58encode(addr + chk).decode()

# ────────────────────────────────────────────────────────────────
# 4.  Подпись транзакции Tron
# ────────────────────────────────────────────────────────────────
def sign_tx(tx: Dict, priv_hex: str) -> Dict:
    """
    Подписывает Tron-транзакцию ECDSA-ключом и возвращает объект с полем signature[].
    Бросает ValueError, если приватный ключ не соответствует owner_address.
    """
    if priv_hex.startswith("0x"): priv_hex = priv_hex[2:]
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(priv_hex), curve=ecdsa.SECP256k1)
    pub_uncompressed = b"\x04" + sk.verifying_key.to_string()

    txid = bytes.fromhex(tx["txID"])           # sha256(raw_data)

    # 1. address владельца из raw_data
    owner_raw = tx["raw_data"]["contract"][0]["parameter"]["value"]["owner_address"]
    if owner_raw.startswith("0x"): owner_raw = owner_raw[2:]
    owner_b58 = hex_to_b58(owner_raw) if owner_raw.startswith("41") else owner_raw

    # 2. быстрый check
    if pub_to_b58(pub_uncompressed) != owner_b58:
        raise ValueError("Приватный ключ не соответствует owner_address")

    # 3. canonical r|s
    sig_rs = sk.sign_digest(txid, sigencode=ecdsa.util.sigencode_string_canonize)

    # 4. rec-id (последний бит Y-координаты pubkey)
    rec_id = pub_uncompressed[-1] & 1
    full_sig = (sig_rs + bytes([rec_id])).hex()

    signed = tx.copy()
    signed["signature"] = [full_sig]
    return signed

# ────────────────────────────────────────────────────────────────
# 5.  Master-адрес из сид-фразы
# ────────────────────────────────────────────────────────────────
def derive_master() -> Tuple[str, str]:
    """
    Возвращает (адрес T…, priv_hex) для пути m/44'/195'/0'/0/0
    """
    if hasattr(config, "TRON_MASTER_PRIVKEY") and config.TRON_MASTER_PRIVKEY:
        priv_hex = config.TRON_MASTER_PRIVKEY.lstrip("0x")
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(priv_hex), curve=ecdsa.SECP256k1)
        pub = b"\x04" + sk.verifying_key.to_string()
        return pub_to_b58(pub), priv_hex

    seed = Bip39SeedGenerator(config.TRON_MASTER_SEED).Generate()
    acc  = (Bip44.FromSeed(seed, Bip44Coins.TRON)
                  .Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0))
    return acc.PublicKey().ToAddress(), acc.PrivateKey().Raw().ToHex()

# ────────────────────────────────────────────────────────────────
# 6.  Баланс TRC-20 USDT
# ────────────────────────────────────────────────────────────────
def get_usdt_balance(addr_b58: str) -> float:
    addr_hex = b58_to_hex(addr_b58)[2:].rjust(64, "0")
    payload = {
        "owner_address": addr_b58,
        "contract_address": USDT_CONTRACT,
        "function_selector": "balanceOf(address)",
        "parameter": addr_hex,
        "visible": True
    }
    r = requests.post(f"{TRONGRID_API}/wallet/triggerconstantcontract",
                      json=payload, headers=HEADERS, timeout=10).json()
    if not r.get("result", {}).get("result", True):
        log.warning(f"constantcontract error: {base64.b64decode(r.get('message','')).decode(errors='ignore')}")
        return 0.0
    bal_hex = r.get("constant_result", ["0"])[0]
    return int(bal_hex, 16) / 1_000_000

def get_trx_balance(addr_b58: str) -> int:         # Sun
    r = requests.post(f"{TRONGRID_API}/wallet/getaccount",
                      json={"address": addr_b58, "visible": True},
                      headers=HEADERS, timeout=10).json()
    return r.get("balance", 0)

# ────────────────────────────────────────────────────────────────
# 7.  Генерация одноразового (ephemeral) адреса
# ────────────────────────────────────────────────────────────────
def generate_ephemeral_address(user_id: int) -> Dict[str, str]:
    """
    Создаёт новое Tron-keypair, записывает в БД (адрес+приватник+время).
    """
    priv = os.urandom(32)
    sk   = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    pub  = b"\x04" + sk.verifying_key.to_string()
    addr = pub_to_b58(pub)

    supabase_client.set_deposit_address_and_privkey(user_id, addr, priv.hex())
    log.info(f"Создан депозитный адрес {addr} (user={user_id})")
    return {"address": addr, "private_key": priv.hex()}

# ────────────────────────────────────────────────────────────────
# 8.  Аренда энергии
# ────────────────────────────────────────────────────────────────
def trx_for_energy(units: int) -> int:          # Sun
    trx = math.ceil(units / ENERGY_PER_TRX)
    return trx * 1_000_000

def rent_energy(master_priv: str, master_addr: str,
                receiver: str, units: int = 65_000) -> int:
    """
    Арендует энергию. Возвращает фактически внесённый депозит в Sun
    либо 0, если аренда не создана.
    """
    deposit = max(trx_for_energy(units), 1_000_000)      # min 1 TRX
    params  = (
        b58_to_hex(receiver)[2:].ljust(64, "0") +
        hex(deposit)[2:].rjust(64, "0") +
        hex(RESOURCE_ENERGY)[2:].rjust(64, "0")
    )
    txo = requests.post(f"{TRONGRID_API}/wallet/triggersmartcontract",
                        json={
                            "contract_address": ENERGY_MARKET,
                            "owner_address": master_addr,
                            "function_selector": "rentResource(address,uint256,uint256)",
                            "parameter": params,
                            "call_value": deposit,
                            "fee_limit": 100_000_000,
                            "visible": True
                        }, headers=HEADERS, timeout=10).json()
    tx = txo.get("transaction")
    if not tx:
        log.error(f"rent_energy error: {base64.b64decode(txo.get('message','')).decode(errors='ignore')}")
        return 0

    signed = sign_tx(tx, master_priv)
    br = requests.post(f"{TRONGRID_API}/wallet/broadcasttransaction",
                       json=signed, headers=HEADERS, timeout=10).json()
    if not br.get("result"):
        log.error(f"RentEnergy broadcast failed: {br}")
        return 0

    log.info(f"RentEnergy tx {br['txid']} ; залог {deposit/1e6:.2f} TRX")
    return deposit             # вернём для последующего возврата

# ────────────────────────────────────────────────────────────────
# 9.  Возврат залога
# ────────────────────────────────────────────────────────────────
def fetch_pledge(payer: str, receiver: str) -> int:
    fn = "rentInfo(address,address,uint256)"
    param = (
        b58_to_hex(payer)[2:].rjust(64, "0") +
        b58_to_hex(receiver)[2:].rjust(64, "0") +
        hex(RESOURCE_ENERGY)[2:].rjust(64, "0")
    )
    r = requests.post(f"{TRONGRID_API}/wallet/triggerconstantcontract",
                      json={
                          "owner_address": payer,
                          "contract_address": ENERGY_MARKET,
                          "function_selector": fn,
                          "parameter": param,
                          "visible": True
                      }, headers=HEADERS, timeout=10).json()
    hex_val = r.get("constant_result", ["0"])[0]
    return int(hex_val, 16)          # pledgeAmount in Sun

def return_resource(master_priv: str, master_addr: str,
                    receiver: str, amount_sun: int) -> bool:
    if amount_sun == 0:
        log.info(f"Pledge for {receiver} already 0")
        return True
    param = (
        b58_to_hex(receiver)[2:].ljust(64, "0") +
        hex(amount_sun)[2:].rjust(64, "0") +
        hex(RESOURCE_ENERGY)[2:].rjust(64, "0")
    )
    txo = requests.post(f"{TRONGRID_API}/wallet/triggersmartcontract",
                        json={
                            "contract_address": ENERGY_MARKET,
                            "owner_address": master_addr,
                            "function_selector": "returnResource(address,uint256,uint256)",
                            "parameter": param,
                            "fee_limit": 10_000_000,
                            "visible": True
                        }, headers=HEADERS, timeout=10).json()
    tx = txo.get("transaction")
    if not tx:
        log.error(f"returnResource create error: "
                  f"{base64.b64decode(txo.get('message','')).decode(errors='ignore')}")
        return False
    signed = sign_tx(tx, master_priv)
    br = requests.post(f"{TRONGRID_API}/wallet/broadcasttransaction",
                       json=signed, headers=HEADERS, timeout=10).json()
    if not br.get("result"):
        log.error(f"returnResource broadcast failed: {br}")
        return False
    log.info(f"returnResource tx {br['txid']} ; ожидается возврат {amount_sun/1e6:.2f} TRX")
    return True

# ────────────────────────────────────────────────────────────────
# 10.  TRC-20 USDT transfer
# ────────────────────────────────────────────────────────────────
def usdt_transfer(from_priv: str, from_addr: str, to_addr: str,
                  amount: float) -> Optional[str]:
    value = int(round(amount * 1_000_000))
    param = (
        b58_to_hex(to_addr)[2:].rjust(64, "0") +
        hex(value)[2:].rjust(64, "0")
    )
    txo = requests.post(f"{TRONGRID_API}/wallet/triggersmartcontract",
                        json={
                            "contract_address": USDT_CONTRACT,
                            "owner_address": from_addr,
                            "function_selector": "transfer(address,uint256)",
                            "parameter": param,
                            "fee_limit": 5_000_000,
                            "visible": True
                        }, headers=HEADERS, timeout=10).json()
    tx = txo.get("transaction")
    if not tx:
        log.error(f"USDT transfer create error: "
                  f"{base64.b64decode(txo.get('message','')).decode(errors='ignore')}")
        return None
    signed = sign_tx(tx, from_priv)
    br = requests.post(f"{TRONGRID_API}/wallet/broadcasttransaction",
                       json=signed, headers=HEADERS, timeout=10).json()
    if not br.get("result"):
        log.error(f"USDT transfer broadcast failed: {br}")
        return None
    log.info(f"USDT transfer tx {br['txid']}")
    return br["txid"]

# ────────────────────────────────────────────────────────────────
# 11.  Вспомогательные high-level функции для бота
# ────────────────────────────────────────────────────────────────
def fund_address(master_priv: str, master_addr: str,
                 dest_addr: str, sun: int = 110_000) -> bool:
    """
    Переводит небольшую сумму TRX (по умолчанию 0.11) на dest_addr для активации.
    """
    create = requests.post(f"{TRONGRID_API}/wallet/createtransaction",
                           json={
                               "owner_address": master_addr,
                               "to_address": dest_addr,
                               "amount": sun,
                               "visible": True
                           }, headers=HEADERS, timeout=10).json()
    if not create.get("txID"):
        log.error(f"Funding create failed: {create}")
        return False
    signed = sign_tx(create, master_priv)
    br = requests.post(f"{TRONGRID_API}/wallet/broadcasttransaction",
                       json=signed, headers=HEADERS, timeout=10).json()
    if not br.get("result"):
        log.error(f"Funding broadcast failed: {br}")
        return False
    log.info(f"Funding tx {br['txid']} ; +{sun/1e6:.2f} TRX -> {dest_addr}")
    return True


# ────────────────────────────────────────────────────────────────
# 11-bis.  Сообщаем баланс мастера при старте бота
# ────────────────────────────────────────────────────────────────
async def print_master_balance_at_start(bot: Bot):
    master_addr, _ = derive_master()
    usdt = get_usdt_balance(master_addr)
    trx  = get_trx_balance(master_addr) / 1_000_000
    msg  = (
        f"Bot started ✅\n"
        f"Master address: {master_addr}\n"
        f"Balance: {usdt:.2f} USDT  |  {trx:.2f} TRX"
    )
    log.info(msg)
    if getattr(config, "ADMIN_CHAT_ID", None):
        try:
            await bot.send_message(config.ADMIN_CHAT_ID, msg)
        except Exception as e:
            log.warning(f"Cannot notify admin: {e}")
            

def create_qr_code(data: str) -> str:
    img = qrcode.make(data)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    img.save(tmp.name)
    return tmp.name

# ────────────────────────────────────────────────────────────────
# 12.  Основной цикл опроса депозитов
# ────────────────────────────────────────────────────────────────
async def poll_trc20_transactions(bot: Bot):
    log.info("Start poll…")
    master_addr, master_priv = derive_master()
    rows = supabase_client.get_pending_deposits_with_privkey()
    now  = datetime.now()

    for row in rows:
        user_id     = row["id"]
        tg_id       = row["telegram_id"]
        dep_addr    = row["deposit_address"]
        dep_priv    = row["deposit_privkey"]
        created_at  = row["deposit_created_at"]

        if not dep_addr or not dep_priv:
            continue
        if (now - created_at).total_seconds() > 24*3600:
            supabase_client.reset_deposit_address_and_privkey(user_id)
            await bot.send_message(tg_id, "Счёт истёк (24 ч). Сформируйте новый.")
            continue

        usdt = get_usdt_balance(dep_addr)
        if usdt <= 0:
            continue

        log.info(f"{usdt:.2f} USDT на {dep_addr}")

        # 1. Если деп-адрес ещё не активирован - отправляем 0.11 TRX
        if get_trx_balance(dep_addr) == 0:
            if not fund_address(master_priv, master_addr, dep_addr):
                log.error("Не удалось отправить 0.11 TRX для активации")
                continue
            time.sleep(3)      # подождать включение

        # 2. Арендуем энергию
        deposit_sun = rent_energy(master_priv, master_addr, dep_addr)
        if deposit_sun == 0:
            continue

        # 3. Переводим USDT
        txid = usdt_transfer(dep_priv, dep_addr, master_addr, usdt)
        if not txid:
            continue

        # 4. Возвращаем залог
        pledge = fetch_pledge(master_addr, dep_addr)
        if pledge:
            return_resource(master_priv, master_addr, dep_addr, pledge)

        # 5. Обновляем БД
        supabase_client.create_payment(user_id, txid, usdt, 0)
        days = math.ceil(usdt * config.DAYS_FOR_100_USDT / 100)
        supabase_client.update_payment_days(user_id, usdt, days)
        supabase_client.apply_subscription_extension(user_id, days)
        supabase_client.reset_deposit_address_and_privkey(user_id)

        # 6. Уведомляем
        master_usdt = get_usdt_balance(master_addr)
        await bot.send_message(
            tg_id,
            f"✅ Получено {usdt:.2f} USDT\nПодписка продлена на {days} дней.\n"
            f"Баланс мастер-кошелька: {master_usdt:.2f} USDT"
        )

    log.info("Poll done.")