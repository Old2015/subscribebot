#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tron_service.py – работа с TRON без tronpy.
"""

import os
import math
import time
import json
import base58
import ecdsa
import qrcode
import hashlib
import logging
import requests
import tempfile
from datetime import datetime

import config
import supabase_client
from aiogram import Bot

from bip_utils import (
    Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
)

log = logging.getLogger(__name__)

TRONGRID_API   = "https://api.trongrid.io"
TRON_API_KEY   = config.TRON_API_KEY
USDT_CONTRACT  = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
ENERGY_MARKET  = "TU2MJ5Veik1LRAgjeSzEdvmDYx7mefJZvd"       # JustLend DAO
RESOURCE_ENERGY= 1

HEADERS = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}

# ───────────────────── Base58 helpers ──────────────────────────
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX    = {c: i for i, c in enumerate(B58_ALPHABET)}

def b58check_decode(addr: str) -> bytes:
    """T...  →  0x41 + 20-byte + 4-checksum"""
    num = 0
    for ch in addr:
        num = num * 58 + B58_INDEX[ch]
    raw = num.to_bytes(25, "big")
    data, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] != checksum:
        raise ValueError("Bad Base58 checksum")
    return data                      # 21 bytes

def addr_b58_to_hex(addr_b58: str) -> str:
    return b58check_decode(addr_b58).hex()          # 41… hex

# ───────────────────── ECDSA подпись ───────────────────────────
def _pub_to_addr(pub_bytes: bytes) -> str:
    keccak = hashlib.new("keccak256", pub_bytes[1:]).digest()
    addr   = b"\x41" + keccak[-20:]
    chk    = hashlib.sha256(hashlib.sha256(addr).digest()).digest()[:4]
    return base58.b58encode(addr + chk).decode()


def _hex_to_b58(hex_addr: str) -> str:
    """41… hex → Base58Check (T…)"""
    addr_bytes = bytes.fromhex(hex_addr)
    checksum   = hashlib.sha256(hashlib.sha256(addr_bytes).digest()).digest()[:4]
    return base58.b58encode(addr_bytes + checksum).decode()

def _pub_to_b58(pub65: bytes) -> str:
    """нежатый pubkey (0x04‖X‖Y) → Tron Base58 адрес"""
    keccak = hashlib.new("keccak256", pub65[1:]).digest()
    addr   = b"\x41" + keccak[-20:]
    checksum = hashlib.sha256(hashlib.sha256(addr).digest()).digest()[:4]
    return base58.b58encode(addr + checksum).decode()

def sign_tx(tx: dict, priv_hex: str) -> dict:
    """Подписывает trx, подбирая правильный recovery-byte (0/1)."""
    txid = bytes.fromhex(tx["txID"])

    # ----- owner_address из raw_data -----------------------------------------
    owner_raw = tx["raw_data"]["contract"][0]["parameter"]["value"]["owner_address"]
    owner_b58 = _hex_to_b58(owner_raw) if owner_raw.startswith("41") else owner_raw

    # ----- быстрый check: совпадает ли приватный ключ с owner_address --------
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(priv_hex),
                                      curve=ecdsa.SECP256k1)
    pk = sk.verifying_key
    addr_from_priv = _pub_to_b58(b"\x04" + pk.to_string())
    if addr_from_priv != owner_b58:
        raise ValueError("Приватный ключ не соответствует owner_address транзакции")

    # ----- подпись r‖s --------------------------------------------------------
    sig_rs = sk.sign_digest(txid, sigencode=ecdsa.util.sigencode_string_canonize)

    # ----- ищем валидный rec_id (0/1) ----------------------------------------
    for rec_id in (0, 1):
        try:
            vk = ecdsa.VerifyingKey.from_public_key_recovery(
                sig_rs, txid,
                curve=ecdsa.SECP256k1,
                sigdecode=ecdsa.util.sigdecode_string
            )[rec_id]
            if _pub_to_b58(b"\x04" + vk.to_string()) == owner_b58:
                full_sig = (sig_rs + bytes([rec_id])).hex()
                signed   = tx.copy()
                signed["signature"] = [full_sig]
                return signed
        except Exception:
            pass

    raise ValueError("Could not produce valid signature (rec_id 0/1)")


# ───────────────────── BIP-44 master из сид-фразы ──────────────
def derive_master_key_and_address():
    """
    BIP-44 путь m/44'/195'/0'/0/0   →   (T… , priv_hex)
    """
    mnemonic   = config.TRON_MASTER_SEED
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    bip44_m    = Bip44.FromSeed(seed_bytes, Bip44Coins.TRON)
    acct       = bip44_m.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    priv_hex   = acct.PrivateKey().Raw().ToHex()
    pub_addr   = acct.PublicKey().ToAddress()        # Base58 T…
    return pub_addr, priv_hex

# ───────────────────── TRC-20 баланс USDT ──────────────────────
def get_usdt_balance(address_b58: str) -> float:
    try:
        addr_hex = addr_b58_to_hex(address_b58)[2:].rjust(64, "0")
        payload  = {
            "owner_address":    address_b58,
            "contract_address": USDT_CONTRACT,
            "function_selector":"balanceOf(address)",
            "parameter":        addr_hex,
            "visible":          True
        }
        r = requests.post(f"{TRONGRID_API}/wallet/triggerconstantcontract",
                          json=payload, headers=HEADERS, timeout=10)
        result_hex = r.json().get("constant_result", [None])[0]
        if result_hex:
            return int(result_hex, 16) / 1_000_000
    except Exception as e:
        log.warning(f"get_usdt_balance({address_b58}) failed: {e}")
    return 0.0

# ───────────────────── Генерация одноразового адреса ───────────
def generate_tron_keypair() -> dict:
    priv = os.urandom(32)
    sk   = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    pub  = sk.verifying_key.to_string("uncompressed")[1:]
    keccak = hashlib.new("keccak256", pub).digest()
    addr_bytes = b"\x41" + keccak[-20:]
    checksum   = hashlib.sha256(hashlib.sha256(addr_bytes).digest()).digest()[:4]
    b58_addr   = base58.b58encode(addr_bytes + checksum).decode()
    return {"address": b58_addr, "private_key": priv.hex()}

def generate_ephemeral_address() -> dict:
    return generate_tron_keypair()

# ───────────────────── Оценка TRX для N энергии ────────────────
def calculate_trx_for_energy(energy_units: int) -> int:
    """
    Очень грубая оценка: 1 TRX (~1e6 Sun) ≈ 15 k Energy весной-2025.
    Для 65 000 Energy → ~ 5 TRX.
    Настройте под точный коэффициент сети!
    """
    trx = math.ceil(energy_units / 15000)
    return trx * 1_000_000

# ───────────────────── Аренда энергии (JustLend) ───────────────
def rent_energy(master_privkey: str, master_addr: str,
                receiver_b58: str, energy_amount: int = 65000) -> bool:
    trx_deposit = calculate_trx_for_energy(energy_amount)
    if trx_deposit < 1_000_000:                 # минимум 1 TRX
        trx_deposit = 1_000_000

    function_selector = "rentResource(address,uint256,uint256)"
    receiver_param = addr_b58_to_hex(receiver_b58)[2:].ljust(64, "0")
    amount_param   = hex(trx_deposit)[2:].rjust(64, "0")
    res_param      = hex(RESOURCE_ENERGY)[2:].rjust(64, "0")
    params         = receiver_param + amount_param + res_param

    trigger = {
        "contract_address": ENERGY_MARKET,
        "owner_address":    master_addr,
        "function_selector":function_selector,
        "parameter":        params,
        "fee_limit":        100_000_000,          # 100 TRX
        "call_value":       trx_deposit,
        "visible":          True
    }
    tx_obj = requests.post(f"{TRONGRID_API}/wallet/triggersmartcontract",
                           json=trigger, headers=HEADERS, timeout=10).json()
    tx = tx_obj.get("transaction")
    if not tx:
        log.error(f"rent_energy create failed: {tx_obj}")
        return False

    tx_signed  = sign_tx(tx, master_privkey)
    br = requests.post(f"{TRONGRID_API}/wallet/broadcasttransaction",
                       json=tx_signed, headers=HEADERS).json()
    if not br.get("result"):
        log.error(f"RentEnergy broadcast failed: {br}")
        return False

    txid = br["txid"]
    log.info(f"RentEnergy tx {txid}; депозит {trx_deposit/1e6:.2f} TRX отправлен")

    # ждём включения и берём фактическую комиссию
    time.sleep(6)
    info = requests.get(f"{TRONGRID_API}/wallet/gettransactioninfobyid",
                        params={"value": txid}).json()
    fee_sun = info.get("fee", 0)
    log.info(f"Комиссия RentEnergy: {fee_sun/1e6:.6f} TRX "
             f"(energy {info.get('energy_usage_total')})")
    return True


def return_resource(master_privkey: str,
                    master_addr: str,
                    receiver_b58: str,
                    deposit_sun: int,
                    resource_type: int = 1) -> bool:
    """
    Завершает аренду энергии (или bandwidth) и возвращает депозит TRX.
    * master_privkey  – приватный ключ плательщика залога
    * master_addr     – T-адрес плательщика (owner_address)
    * receiver_b58    – адрес, которому делегировали ресурс
    * deposit_sun     – сумма TRX к возврату, в SUN (1 TRX = 1_000_000 SUN)
    * resource_type   – 1 = Energy, 0 = Bandwidth
    """
    fn_selector = "returnResource(address,uint256,uint256)"

    recv_param = addr_b58_to_hex(receiver_b58)[2:].ljust(64, "0")
    amt_param  = hex(deposit_sun)[2:].rjust(64, "0")
    res_param  = hex(resource_type)[2:].rjust(64, "0")
    params     = recv_param + amt_param + res_param

    trigger = {
        "contract_address": ENERGY_MARKET,   # TU2MJ… JustLend DAO
        "owner_address":    master_addr,
        "function_selector":fn_selector,
        "parameter":        params,
        "fee_limit":        10_000_000,       # 10 TRX лимит комиссии
        "call_value":       0,
        "visible":          True
    }

    create = requests.post(f"{TRONGRID_API}/wallet/triggersmartcontract",
                           json=trigger, headers=HEADERS, timeout=10).json()
    tx = create.get("transaction")
    if not tx:
        log.error(f"returnResource create failed: {create}")
        return False

    tx_signed = sign_tx(tx, master_privkey)
    broadcast = requests.post(f"{TRONGRID_API}/wallet/broadcasttransaction",
                              json=tx_signed, headers=HEADERS, timeout=10).json()
    if not broadcast.get("result"):
        log.error(f"returnResource broadcast failed: {broadcast}")
        return False

    txid = broadcast["txid"]
    log.info(f"returnResource tx {txid} → запрос возврата {deposit_sun/1e6:.2f} TRX")

    # — подождём включения и напишем фактическую комиссию —
    time.sleep(6)
    info = requests.get(f"{TRONGRID_API}/wallet/gettransactioninfobyid",
                        params={"value": txid}, headers=HEADERS, timeout=10).json()
    fee_sun = info.get("fee", 0)
    log.info(f"Комиссия returnResource: {fee_sun/1e6:.6f} TRX "
             f"(energy_used {info.get('energy_usage_total')})")

    # в смарт-контракте депозит перечисляется мастеру тем же tx
    return True


# ───────────────────── USDT transfer + optional returnRent ─────
def sign_and_broadcast_usdt_transfer(ephem_privkey: str, from_b58: str,
                                     to_b58: str, amount: float) -> bool:
    value_int   = int(round(amount * 1_000_000))
    to_param    = addr_b58_to_hex(to_b58)[2:].rjust(64, "0")
    val_param   = hex(value_int)[2:].rjust(64, "0")
    params      = to_param + val_param

    trigger = {
        "contract_address": USDT_CONTRACT,
        "owner_address":    from_b58,
        "function_selector":"transfer(address,uint256)",
        "parameter":        params,
        "fee_limit":        5_000_000,
        "visible":          True
    }
    tx_obj = requests.post(f"{TRONGRID_API}/wallet/triggersmartcontract",
                           json=trigger, headers=HEADERS, timeout=10).json()
    tx = tx_obj.get("transaction")
    if not tx:
        log.error(f"create transfer failed: {tx_obj}")
        return False

    tx_signed = sign_tx(tx, ephem_privkey)
    br = requests.post(f"{TRONGRID_API}/wallet/broadcasttransaction",
                       json=tx_signed, headers=HEADERS, timeout=10).json()
    if br.get("result"):
        log.info(f"USDT transfer broadcast: {br.get('txid')}")
        return True

    log.error(f"broadcast transfer failed: {br}")
    return False

# ───────────────────── QR-код (без изменений) ──────────────────
def create_qr_code(data: str) -> str:
    try:
        img = qrcode.make(data)
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        img.save(tmp.name)
        return tmp.name
    except Exception as e:
        log.error(f"QR code error: {e}")
        return ""

# ───────────────────── High-level API для бота ────────────────
def create_temp_deposit_address(user_id: int):
    kp = generate_ephemeral_address()
    supabase_client.set_deposit_address_and_privkey(user_id, kp["address"], kp["private_key"])
    log.info(f"Сформирован депозит {kp['address']} (user {user_id})")
    return kp["address"]

async def print_master_balance_at_start(bot: Bot):
    master_addr, _ = derive_master_key_and_address()
    bal = get_usdt_balance(master_addr)
    msg = f"Bot started.\nMaster: {master_addr}\nUSDT Balance: {bal:.2f}"
    log.info(msg)
    if config.ADMIN_CHAT_ID:
        try:
            await bot.send_message(config.ADMIN_CHAT_ID, msg)
        except Exception as e:
            log.warning(f"notify admin failed: {e}")

# ───────────────────── Постоянный опрос депозитов ─────────────
async def poll_trc20_transactions(bot: Bot):
    log.info("Start poll…")
    master_addr, master_priv = derive_master_key_and_address()

    rows = supabase_client.get_pending_deposits_with_privkey()
    now  = datetime.now()

    for row in rows:
        user_id, tg_id   = row["id"], row["telegram_id"]
        dep_addr, dep_pk = row["deposit_address"], row["deposit_privkey"]
        created_at       = row["deposit_created_at"]

        if not dep_addr or not dep_pk:
            continue
        if (now - created_at).total_seconds() > 24*3600:
            supabase_client.reset_deposit_address_and_privkey(user_id)
            try:
                await bot.send_message(tg_id, "Счёт истёк (24 ч). Создайте новый.")
            except Exception:
                pass
            continue

        bal = get_usdt_balance(dep_addr)
        if bal <= 0:
            continue

        log.info(f"{bal} USDT на {dep_addr}")

        # ---- 1. арендуем энергию ------------------------------------------------
        if not rent_energy(master_priv, master_addr, dep_addr, 65000):
            continue

        # ---- 2. перевели USDT ----------------------------------------------------
        if not sign_and_broadcast_usdt_transfer(dep_pk, dep_addr, master_addr, bal):
            continue

        # ---- 3. возвращаем депозит TRX ------------------------------------------
        deposit_sun = calculate_trx_for_energy(65000)      # тот же объём, что арендовали
        return_resource(master_priv, master_addr, dep_addr, deposit_sun)

        # ---- 4. БД и продление подписки -----------------------------------------
        supabase_client.create_payment(user_id, "tx", bal, 0)
        days = math.ceil(bal * config.DAYS_FOR_100_USDT / 100)
        supabase_client.update_payment_days(user_id, bal, days)
        supabase_client.apply_subscription_extension(user_id, days)
        supabase_client.reset_deposit_address_and_privkey(user_id)

        master_bal = get_usdt_balance(master_addr)
        msg = (f"Получено {bal:.2f} USDT.\nПодписка +{days} дн.\n"
               f"Master balance: {master_bal:.2f} USDT")
        try:
            await bot.send_message(tg_id, msg)
        except Exception:
            pass

    log.info("Poll done.")