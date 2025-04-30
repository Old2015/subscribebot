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

MIN_ACTIVATION_SUN = 1_000_000           # 1 TRX – минимум для создания аккаунта
FUND_EXTRA_SUN     = 100_000             # небольшой запас на fee (0.1 TRX)

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

# ─── helper ─────────────────────────────────────────────────────
def _looks_like_hex(s: str) -> bool:
    """True, если строка полностью из 0-hex-символов и длиной 40-42 байта."""
    try:
        int(s, 16)
        return 40 <= len(s) <= 44        # 20-21 байт (+ optional '41')
    except ValueError:
        return False
    


# ────────────────────────────────────────────────────────────────
# 4.  Подпись транзакции Tron
# ────────────────────────────────────────────────────────────────
def sign_tx(tx: Dict, priv_hex: str) -> Dict:
    """
    Подписывает Tron-транзакцию приватным ключом.
    • проверяет, что ключ действительно принадлежит owner_address;
    • перебирает rec_id 0/1, пока адрес не совпадёт.
    """
    priv_hex = priv_hex.lstrip("0x")
    sk  = ecdsa.SigningKey.from_string(bytes.fromhex(priv_hex), curve=ecdsa.SECP256k1)
    pk  = sk.verifying_key
    pub = b"\x04" + pk.to_string()              # 65-байтный uncompressed

    txid = bytes.fromhex(tx["txID"])

    # owner_address из raw_data
    owner_raw = tx["raw_data"]["contract"][0]["parameter"]["value"]["owner_address"]
    owner_raw = owner_raw.lstrip("0x")
    if _looks_like_hex(owner_raw):
        owner_b58 = hex_to_b58(owner_raw[-42:])      # берём последние 42, на случай 'a614…'
    else:
        owner_b58 = owner_raw

    # быстрый check, что ключ тот самый
    if pub_to_b58(pub) != owner_b58:
        raise ValueError("Приватный ключ не соответствует owner_address")

    # canonical r|s
    sig_rs = sk.sign_digest(txid, sigencode=ecdsa.util.sigencode_string_canonize)

    # ищем валидный rec_id
    for rec_id in (0, 1):
        try:
            vk = ecdsa.VerifyingKey.from_public_key_recovery(
                    sig_rs, txid,
                    curve=ecdsa.SECP256k1,
                    sigdecode=ecdsa.util.sigdecode_string)[rec_id]
            if pub_to_b58(b"\x04" + vk.to_string()) == owner_b58:
                signed = tx.copy()
                signed["signature"] = [(sig_rs + bytes([rec_id])).hex()]
                return signed
        except Exception:
            pass

    raise ValueError("Cannot build valid signature for owner_address")

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

# ────────────────────────────────────────────────────────────────
# 6-bis.  Баланс TRX (Sun)
# ────────────────────────────────────────────────────────────────
def get_trx_balance(addr_b58: str, *, total: bool = False) -> int:
    """
    Возвращает баланс TRX в SUN (1 TRX = 1e6 SUN).

    total = False  – свободный (spendable) баланс.
    total = True   – raw balance из TronGrid (spend + frozen + pledge).
    """
    try:
        acc = requests.post(
            f"{TRONGRID_API}/wallet/getaccount",
            json={"address": addr_b58, "visible": True},
            headers=HEADERS, timeout=10
        ).json()

        balance_spend = acc.get("balance", 0)
        if total:
            frozen = acc.get("frozen_balance_for_energy", 0) + acc.get("frozen_balance", 0)
            pledge = acc.get("account_resource", {}).get("pledge_balance_for_energy", 0)
            return balance_spend + frozen + pledge

        return balance_spend
    except Exception as e:
        log.warning(f"get_trx_balance({addr_b58}) failed: {e}")
        return 0

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

    needed = trx_for_energy(units)
    bal    = get_trx_balance(master_addr)
    if bal < needed:
        max_units = max(int(bal / 1_000_000 * ENERGY_PER_TRX) - 1000, 0)
        if max_units < 15_000:
            log.warning("rent_energy skipped: not enough TRX")
            return 0
        units  = max_units
        needed = trx_for_energy(units)
        log.info(f"rent_energy ↓ {units} units (deposit {needed/1e6:.2f} TRX)")


    deposit = max(trx_for_energy(units), 1_000_000)      # ≥1 TRX
    params  = (
        b58_to_hex(receiver)[2:].ljust(64, "0") +
        hex(deposit)[2:].rjust(64, "0") +
        hex(RESOURCE_ENERGY)[2:].rjust(64, "0")
    )

    txo = requests.post(f"{TRONGRID_API}/wallet/triggersmartcontract",
                        json={
                            "contract_address": ENERGY_MARKET,
                            "owner_address":    b58_to_hex(master_addr),  # ← hex!
                            "function_selector":"rentResource(address,uint256,uint256)",
                            "parameter":        params,
                            "call_value":       deposit,
                            "fee_limit":        100_000_000,
                            "visible":          False                    # ← hex-режим
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
    """
    Возвращает сумму залога (Sun) по связке payer→receiver.
    Если залога нет или ответ контракта пустой, вернёт 0.
    """
    fn = "rentInfo(address,address,uint256)"
    param = (
        b58_to_hex(payer)[2:].rjust(64, "0") +
        b58_to_hex(receiver)[2:].rjust(64, "0") +
        hex(RESOURCE_ENERGY)[2:].rjust(64, "0")
    )

    r = requests.post(
        f"{TRONGRID_API}/wallet/triggerconstantcontract",
        json={
            "owner_address":    payer,
            "contract_address": ENERGY_MARKET,
            "function_selector": fn,
            "parameter":         param,
            "visible":           True
        },
        headers=HEADERS, timeout=10
    ).json()

    # 1) TronGrid может вернуть {"code":"OTHER_ERROR", ...}
    if not r.get("result", {}).get("result", True):
        msg = base64.b64decode(r.get("message", "")).decode(errors="ignore")
        log.warning(f"fetch_pledge error {receiver}: {msg}")
        return 0

    hex_val = (r.get("constant_result") or [""])[0]
    try:
        return int(hex_val or "0", 16)
    except ValueError:
        return 0          # неожиданный формат ответа

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
def fund_address(master_priv: str, master_addr: str, dest_addr: str) -> bool:
    """Переводит 1.1 TRX (1 TRX — активация, 0.1 TRX — запас)."""
    amount = MIN_ACTIVATION_SUN + FUND_EXTRA_SUN        # 1 100 000 Sun

    if get_trx_balance(master_addr) < amount + 500_000:
        log.error("Мало TRX на мастер-кошельке для активации депозита")
        return False

    create = requests.post(
        f"{TRONGRID_API}/wallet/createtransaction",
        json={
            "owner_address": b58_to_hex(master_addr),  # hex-формат
            "to_address":    b58_to_hex(dest_addr),
            "amount":        amount,
            "visible":       False                    # hex-режим
        },
        headers=HEADERS, timeout=10
    ).json()

    if "txID" not in create:
        log.error(f"Funding create failed: {create}")
        return False

    signed = sign_tx(create, master_priv)
    br = requests.post(f"{TRONGRID_API}/wallet/broadcasttransaction",
                       json=signed, headers=HEADERS, timeout=10).json()
    if not br.get("result"):
        log.error(f"Funding broadcast failed: {br}")
        return False

    log.info(f"Funding tx {br['txid']} | +{amount/1e6:.2f} TRX → {dest_addr}")
    return True

# ────────────────────────────────────────────────────────────────
# x.  Суммарный pledge мастера (на все адреса)
# ────────────────────────────────────────────────────────────────
def total_master_pledge(master_b58: str) -> Dict[str, int]:
    """
    Возвращает словарь {receiver_b58: pledgeSun} для всех депозит-адресов в БД.
    """
    pledges: Dict[str, int] = {}
    for rec in supabase_client.get_all_deposit_addresses():
        try:
            pledge = fetch_pledge(master_b58, rec)
            if pledge:
                pledges[rec] = pledge
        except Exception:
            continue
    total = sum(pledges.values())
    log.info(f"Total pledge locked: {total/1e6:.2f} TRX")
    return pledges

# ────────────────────────────────────────────────────────────────
# 11-bis.  Сообщаем баланс мастера при старте бота
# ────────────────────────────────────────────────────────────────
async def print_master_balance_at_start(bot: Bot):
    # ← здесь получаем пару
    master_addr, priv = derive_master()

    usdt  = get_usdt_balance(master_addr)
    spend = get_trx_balance(master_addr) / 1e6
    total = get_trx_balance(master_addr, total=True) / 1e6

    log.info(
        f"Bot started ✅\n"
        f"Master address: {master_addr}\n"
        f"Balance: {usdt:.2f} USDT | {spend:.2f} TRX spend / {total:.2f} TRX total"
    )

    if getattr(config, "ADMIN_CHAT_ID", None):
        try:
            await bot.send_message(
                config.ADMIN_CHAT_ID,
                f"🏁 *Бот запущен*\n"
                f"`{master_addr}`\n"
                f"*USDT*: {usdt:.2f}\n"
                f"*TRX*:  {spend:.2f} из {total:.2f}",
                parse_mode="Markdown"
            )
        except Exception as e:
            log.warning(f"Cannot notify admin: {e}")

    # ── возвращаем старые залоги, если есть ────────────────────
    pledges = total_master_pledge(master_addr)
    returned = 0
    for recv, sun in pledges.items():
        if return_resource(priv, master_addr, recv, sun):
            returned += sun
    if returned:
        log.info(f"🔄  Returned old pledges: {returned/1e6:.2f} TRX")

                

def create_qr_code(data: str) -> str:
    img = qrcode.make(data)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    img.save(tmp.name)
    return tmp.name

# ────────────────────────────────────────────────────────────────
# 12.  Основной цикл опроса депозитов
# ────────────────────────────────────────────────────────────────
async def poll_trc20_transactions(bot: Bot) -> None:
    """
    1. Раз в минуту читает все активные депозит-адреса из БД.
    2. Первым делом пытается вернуть *старые* залоги TRX, если такие остались.
    3. Для каждого депозита:
       • если баланса USDT ещё нет   → пропуск;
       • если на мастере < 6 TRX     → пробуем перевести USDT *без* аренды энергии;
       • иначе                       → обычный путь: активация ↓ аренда ↓ перевод ↓ возврат залога.
    4. После успешного платежа – обновление БД, продление подписки, уведомление.
    """
    log.info("Start poll…")
    master_addr, master_priv = derive_master()

    # ── ❶  Пытаемся вернуть ВСЕ старые залоги ───────────────────
    for dep_b58, pledge_sun in total_master_pledge(master_addr).items():
        if pledge_sun:
            log.info(f"⚠️  Старый залог {pledge_sun/1e6:.2f} TRX на {dep_b58} — пытаюсь вернуть")
            return_resource(master_priv, master_addr, dep_b58, pledge_sun)

    # ── ❷  Обрабатываем актуальные депозиты пользователей ───────
    now  = datetime.now()
    rows = supabase_client.get_pending_deposits_with_privkey()

    for row in rows:
        user_id     = row["id"]
        tg_id       = row["telegram_id"]
        dep_addr    = row["deposit_address"]
        dep_priv    = row["deposit_privkey"]
        created_at  = row["deposit_created_at"]

        # пропуск невалидных строк
        if not dep_addr or not dep_priv:
            continue

        # истёкло 24 ч — аннулируем счёт
        if (now - created_at).total_seconds() > 24*3600:
            supabase_client.reset_deposit_address_and_privkey(user_id)
            try:
                await bot.send_message(tg_id, "Счёт истёк (24 ч). Сформируйте новый.")
            except Exception:
                pass
            continue

        # баланс USDT на депозит-адресе
        usdt = get_usdt_balance(dep_addr)
        if usdt <= 0:
            continue     # средств ещё нет

        log.info(f"🔎 Найдено {usdt:.2f} USDT на {dep_addr}")

        # ── ❷-a  если TRX на мастере < 6 — пробуем «без аренды» ──
        master_trx_spend = get_trx_balance(master_addr) / 1e6
        if master_trx_spend < 6:
            log.warning(f"💧 Мало TRX на мастере ({master_trx_spend:.2f}). "
                        f"Пробую перевод без аренды.")
            txid = usdt_transfer(dep_priv, dep_addr, master_addr, usdt)
            if not txid:
                log.error("USDT transfer без аренды не прошёл")
                continue

            # success —— оформляем платёж, продлеваем подписку, очищаем адрес
            _after_success_payment(user_id, tg_id, dep_addr, usdt, txid,
                                   master_addr)
            continue   # к следующему депозиту

        # ── ❷-b  стандартный путь с арен­дой энергии ─────────────

        # 1. при необходимости активируем адрес (0.11 TRX)
        if get_trx_balance(dep_addr) == 0:
            if not fund_address(master_priv, master_addr, dep_addr, 110_000):
                log.error("❌ Не удалось активировать депозит-адрес (0.11 TRX)")
                continue
            time.sleep(3)      # ждём включения блока

        # 2. арендуем энергию
        pledge_before = rent_energy(master_priv, master_addr, dep_addr)
        if pledge_before == 0:
            log.error("❌ rent_energy не создана — пропуск")
            continue

        # 3. переводим USDT
        txid = usdt_transfer(dep_priv, dep_addr, master_addr, usdt)
        if not txid:
            log.error("❌ USDT transfer не прошёл")
            continue

        # 4. возвращаем залог (можно вернуть ТУ ЖЕ сумму pledge_before)
        return_resource(master_priv, master_addr, dep_addr, pledge_before)

        # 5. после успеха — БД / подписка / уведомление
        _after_success_payment(user_id, tg_id, dep_addr, usdt, txid, master_addr)

    log.info("Poll done.")


# ────────────────────────────────────────────────────────────────
# Служебная обёртка для корректного оформления платежа в БД + чат
# ────────────────────────────────────────────────────────────────
def _after_success_payment(
    user_id: int,
    telegram_id: int,
    dep_addr: str,
    amount_usdt: float,
    txid: str,
    master_addr: str
) -> None:
    """
    1. create_payment    → записываем транзакцию
    2. subscription +days
    3. reset deposit_address / privkey
    4. выводим лог и шлем пользователю уведомление
    """
    # (1) платеж
    supabase_client.create_payment(user_id, txid, amount_usdt, 0)

    # (2) подписка
    days = math.ceil(amount_usdt * config.DAYS_FOR_100_USDT / 100)
    supabase_client.update_payment_days(user_id, amount_usdt, days)
    supabase_client.apply_subscription_extension(user_id, days)

    # (3) очищаем адрес
    supabase_client.reset_deposit_address_and_privkey(user_id)

    # (4) лог + уведомление
    master_usdt = get_usdt_balance(master_addr)
    log.info(
        f"✅ {amount_usdt:.2f} USDT с {dep_addr} → мастер.\n"
        f"Подписка +{days} дн. | Master USDT: {master_usdt:.2f}"
    )
    try:
        asyncio.create_task(
            bot.send_message(
                telegram_id,
                f"✅ Получено {amount_usdt:.2f} USDT.\n"
                f"Ваша подписка продлена на {days} дн.\n"
                f"Текущий баланс бота: {master_usdt:.2f} USDT."
            )
        )
    except Exception as e:
        log.warning(f"Cannot notify user {telegram_id}: {e}")