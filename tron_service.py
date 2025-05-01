#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tron_service.py — вся работа с TRON через TronGrid (без tronpy/TronWeb).
"""

import os, math, time, base64, logging, tempfile, requests, qrcode, base58, ecdsa, hashlib, asyncio
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
    Подписывает Tron-транзакцию.
    • Проверяет, что priv→addr совпадают.
    • Подпись canonical r|s.
    • rec_id подбирается через recovery *с тем же* SHA-256, что и txID.
    """
    priv_hex = priv_hex.lstrip("0x")
    if len(priv_hex) < 64:                       # safety — дополняем слева до 64 hex
        priv_hex = priv_hex.rjust(64, "0")

    sk  = ecdsa.SigningKey.from_string(bytes.fromhex(priv_hex),
                                       curve=ecdsa.SECP256k1)
    pub = b"\x04" + sk.verifying_key.to_string()          # 65-byte uncompressed
    txid = bytes.fromhex(tx["txID"])

    # ── owner_address из raw_data
    owner_raw = tx["raw_data"]["contract"][0]["parameter"]["value"]["owner_address"]
    owner_raw = owner_raw.lstrip("0x")
    owner_b58 = hex_to_b58(owner_raw[-42:]) if _looks_like_hex(owner_raw) else owner_raw

    # быстрая проверка «приватник → адрес»
    if pub_to_b58(pub) != owner_b58:
        raise ValueError("Приватный ключ не соответствует owner_address")

    # ── canonical r|s
    sig_rs = sk.sign_digest(txid, sigencode=ecdsa.util.sigencode_string_canonize)

    # ── восстановление pubkey → выбор rec_id (важно: тот же SHA-256!)
    try:
        cands = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
            signature = sig_rs,
            digest    = txid,                      # уже готовый sha256(tx.raw)
            curve     = ecdsa.SECP256k1,
            sigdecode = ecdsa.util.sigdecode_string,
            hashfunc  = hashlib.sha256             # ← ключевое отличие
        )
    except Exception as e:                         # крайне редко, но перехватим
        raise ValueError(f"recovery failed: {e}")

    for rec_id, vk in enumerate(cands):
        if pub_to_b58(b"\x04" + vk.to_string()) == owner_b58:
            signed              = tx.copy()
            signed["signature"] = [(sig_rs + bytes([rec_id])).hex()]
            return signed

    raise ValueError("Cannot build valid signature for owner_address")


def sign_and_broadcast(raw_tx: dict, priv_hex: str) -> Optional[dict]:
    """
    1. Подписывает Tron-транзакцию 'raw_tx' приватным ключом 'priv_hex'.
    2. Шлёт в /wallet/broadcasttransaction.
    3. Возвращает словарь signed_tx, где будет поле "txid", 
       либо None при ошибке.
    """
    # Подписываем (используем уже имеющуюся у вас sign_tx)
    signed = sign_tx(raw_tx, priv_hex)
    if not signed.get("signature"):
        log.error("sign_and_broadcast: no signature in signed tx")
        return None
    
    # Отправляем
    br = requests.post(
        f"{TRONGRID_API}/wallet/broadcasttransaction",
        json=signed,
        headers=HEADERS,
        timeout=10
    ).json()

    if not br.get("result"):
        # Ошибка при broadcast — логируем и возвращаем None
        log.error(f"broadcasttransaction failed: {br}")
        return None

    # Обычно в ответе br['txid'] — кладём это же поле в signed
    txid = br.get("txid")
    if not txid:
        log.error(f"broadcasttransaction: no txid in response: {br}")
        return None
    signed["txid"] = txid

    # Возвращаем уже дополненный signed, 
    # чтобы в вызывающей функции удобно взять signed["txid"]
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

# ────────────────────────────────────────────────────────────────
# 6-bis.  Баланс TRX (Sun)
# ────────────────────────────────────────────────────────────────
def get_trx_balance_v2(addr_b58: str) -> dict:
    """
    Возвращает структуру с балансами по схеме Freeze V2,
    БЕЗ вызова /wallet/getaccountresourcev2 (т.к. он 405 на tron api).
    
    Пример возвращаемого словаря:
    {
      "balance": 51088950,   # свободный баланс (Sun)
      "frozen_balance_for_energy_v2": 10000000,
      "frozen_balance_for_bandwidth_v2": 0,
      "delegated_frozen_balance_for_energy_v2": 0,
      "delegated_frozen_balance_for_bandwidth_v2": 0
    }
    """

    result = {
        "balance": 0,
        "frozen_balance_for_energy_v2": 0,
        "frozen_balance_for_bandwidth_v2": 0,
        "delegated_frozen_balance_for_energy_v2": 0,    # Пока ставим 0
        "delegated_frozen_balance_for_bandwidth_v2": 0  # Пока ставим 0
    }

    try:
        resp = requests.post(
            f"{TRONGRID_API}/wallet/getaccount",
            json={"address": addr_b58, "visible": True},
            headers=HEADERS,
            timeout=10
        )
        acc = resp.json()
        # Свободный баланс
        result["balance"] = acc.get("balance", 0)

        # Ищем frozenV2 (массив)
        frozen_v2_list = acc.get("frozenV2", [])
        # Пример: [
        #   {"amount":10000000},
        #   {"type":"ENERGY"},
        #   {"type":"TRON_POWER"}
        # ]

        # Логика: обычно там 1 объект с "amount" и 1-2 объекта с "type"
        # Но может быть несколько freeze-блоков. Собираем сумму amounts.
        # А если тип "ENERGY" => считаем это frozen_balance_for_energy_v2.
        # Если тип "BANDWIDTH" => frozen_balance_for_bandwidth_v2.

        # Чтобы обработать универсально, пройдёмся по списку в паре.
        # Tron отдает [{"amount": N}, {"type":"ENERGY"}, {"type":"TRON_POWER"}].
        # "TRON_POWER" - это внутренняя метка. Главное - ENERGY или BANDWIDTH.
        # Если freeze на BW, обычно {"type":"BANDWIDTH"}.

        frozen_amount = 0
        freeze_type = None

        # Сканируем items посекционно
        # (т.к. Tron обычно идёт: {"amount": ...}, {"type":"ENERGY"}, {"type":"TRON_POWER"})
        i = 0
        length = len(frozen_v2_list)
        while i < length:
            item = frozen_v2_list[i]
            if "amount" in item:
                # Запоминаем временно
                frozen_amount = item["amount"]
                # Смотрим следующий элемент, если есть
                if i+1 < length:
                    t_item = frozen_v2_list[i+1]
                    if "type" in t_item:
                        freeze_type = t_item["type"]  # ENERGY / BANDWIDTH / TRON_POWER
                        i += 2
                    else:
                        i += 1
                else:
                    i += 1
            elif "type" in item:
                freeze_type = item["type"]
                i += 1
            else:
                i += 1

            # Теперь, если freeze_type = "ENERGY", frozen_amount -> frozen_balance_for_energy_v2
            # Если "BANDWIDTH" -> frozen_balance_for_bandwidth_v2
            # Если "TRON_POWER", это просто маркер, ignore

            if freeze_type == "ENERGY":
                result["frozen_balance_for_energy_v2"] += frozen_amount
            elif freeze_type == "BANDWIDTH":
                result["frozen_balance_for_bandwidth_v2"] += frozen_amount
            # TRON_POWER можно игнорировать, либо логировать
            # сбрасываем temp
            frozen_amount = 0
            freeze_type = None

        # delegated_frozen_... могли бы тоже искать, но TronGrid обычно 
        # отдаёт delegated freeze иначе. Если нужно — доработать.

    except Exception as e:
        log.warning(f"get_trx_balance_v2({addr_b58}) failed: {e}")

    return result



def get_total_balance_v2(addr_b58: str) -> (int, int):
    """
    Возвращает (spend_sun, total_sun) для Freeze V2:
      spend_sun = свободный баланс (Sun)
      total_sun = spend_sun + замороженные в ENERGY/BANDWIDTH (V2)
    """
    acc_res2 = get_trx_balance_v2(addr_b58)
    spend_sun = acc_res2["balance"]

    v2_energy = acc_res2["frozen_balance_for_energy_v2"]
    v2_bw     = acc_res2["frozen_balance_for_bandwidth_v2"]

    total_sun = spend_sun + v2_energy + v2_bw
    return spend_sun, total_sun 

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
# 8.  Замораживаем ТРХ для перевода средств
# ────────────────────────────────────────────────────────────────
def trx_for_energy(units: int) -> int:          # Sun - нам нужна эта функция ???
    trx = math.ceil(units / ENERGY_PER_TRX)
    return trx * 1_000_000

def freeze_balance_v2(owner_address: str,
                      owner_priv: str,
                      receiver_address: str,
                      amount_sun: int,
                      resource="ENERGY") -> str:
    """
    Замораживает 'amount_sun' на 3 дня, используя V2 (freeze v2).
    Делегирует resource (ENERGY/BANDWIDTH) на 'receiver_address'.
    Возвращает txid или "".
    """
    freeze_body = {
        "owner_address": owner_address,
        "frozen_balance": amount_sun,
        "frozen_duration": 3,
        "resource_type": resource.upper(),    # "ENERGY" или "BANDWIDTH"
        "receiver_address": receiver_address,
        "visible": True
    }

    create_resp = requests.post(
        f"{TRONGRID_API}/wallet/freezebalancev2",
        json=freeze_body,
        headers=HEADERS,
        timeout=10
    )
    if create_resp.status_code != 200:
        log.error(f"freeze_balance_v2 create failed: {create_resp.text}")
        return ""
    
    raw_tx = create_resp.json()
    if "Error" in raw_tx:
        log.error(f"freeze_balance_v2 error in raw_tx: {raw_tx['Error']}")
        return ""

    # Подписываем и бродкастим (аналогично старому freeze_balance)
    signed_tx = sign_and_broadcast(raw_tx, owner_priv)
    if not signed_tx:
        return ""

    txid = signed_tx.get("txid", "")
    if not txid:
        log.error(f"freeze_balance_v2 no txid: {signed_tx}")
        return ""

    log.info(f"[freezeV2] {txid} => {amount_sun/1e6:.2f} TRX (resource={resource}, receiver={receiver_address})")
    return txid


# ────────────────────────────────────────────────────────────────
# 9.  Размораживаем средства ТРХ
# ────────────────────────────────────────────────────────────────
def unfreeze_balance_v2(owner_address: str,
                        owner_priv: str,
                        receiver_address: str,
                        resource="ENERGY") -> str:
    """
    Размораживает все TRX (в V2) по указанному resource, делегированные на receiver_address.
    Возвращает txid или "".
    """
    unfreeze_body = {
        "owner_address": owner_address,
        "resource_type": resource.upper(), 
        "receiver_address": receiver_address,
        "visible": True
    }

    create_resp = requests.post(
        f"{TRONGRID_API}/wallet/unfreezebalancev2",
        json=unfreeze_body,
        headers=HEADERS,
        timeout=10
    )
    if create_resp.status_code != 200:
        log.error(f"unfreeze_balance_v2 create failed: {create_resp.text}")
        return ""
    raw_tx = create_resp.json()
    if "Error" in raw_tx:
        log.error(f"unfreeze_balance_v2 error in raw_tx: {raw_tx['Error']}")
        return ""

    signed_tx = sign_and_broadcast(raw_tx, owner_priv)
    if not signed_tx:
        return ""

    txid = signed_tx.get("txid", "")
    if not txid:
        log.error(f"unfreeze_balance_v2 no txid: {signed_tx}")
        return ""

    log.info(f"[unfreezeV2] success: {txid} (resource={resource}, receiver={receiver_address})")
    return txid

# ────────────────────────────────────────────────────────────────
# 10.  TRC-20 USDT transfer
# ────────────────────────────────────────────────────────────────


def usdt_transfer(from_priv: str,
                  from_addr: str,
                  to_addr:   str,
                  amount:    float,
                  fee_limit: int = 8_000_000) -> Optional[str]:
    """
    Переводит `amount` USDT с `from_addr` на `to_addr`.
    • fee_limit — лимит TRX на комиссию (Sun). По-умолчанию 8 TRX.
    Возвращает txid либо None, если broadcast не прошёл.
    """
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
                            "fee_limit": 8_000_000,
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

    txid = br["txid"]                      # ← ➊ получили hash
    log.info(f"➜ USDT tx {txid}; energy OK, bandwidth OK")  # ← ➋ теперь можно писать
    return txid                            # ← ➌ и вернуть вызывающему

# ────────────────────────────────────────────────────────────────
# 10.а  Учёт в таблице freeze_records
# ────────────────────────────────────────────────────────────────

def record_freeze_in_db(
    deposit_address: str,
    freeze_amount_sun: int,
    freeze_tx: str,
    resource: str = "ENERGY"
):
    rec_id = supabase_client.insert_freeze_record(deposit_address, freeze_amount_sun, freeze_tx, resource)
    log.info(f"[DB] freeze_records: inserted freeze_tx={freeze_tx} deposit={deposit_address} id={rec_id}")

def record_unfreeze_in_db(freeze_id: int, unfreeze_tx: str):
    """
    Помечаем запись в freeze_records как 'unfrozen', указываем время (NOW()) и tx (unfreeze_tx).
    """
    sql = """
        UPDATE freeze_records
           SET unfrozen     = true,
               unfreeze_tx  = %s,
               unfrozen_at  = now()
         WHERE id           = %s
         RETURNING id
    """
    with _get_connection() as conn, conn.cursor() as cur:
        cur.execute(sql, (unfreeze_tx, freeze_id))
        row = cur.fetchone()
        conn.commit()

        if row:
            return row[0]
        return None

# ────────────────────────────────────────────────────────────────
# 11.  Вспомогательные high-level функции для бота
# ────────────────────────────────────────────────────────────────
def fund_address(master_priv: str, master_addr: str, dest_addr: str) -> bool:
    """Переводит 1.1 TRX (1 TRX — активация, 0.1 TRX — запас)."""
    amount = MIN_ACTIVATION_SUN + FUND_EXTRA_SUN        # 1 100 000 Sun

    info_master = get_trx_balance_v2(master_addr)
    spend_sun   = info_master["balance"]  # свободный баланс

    if spend_sun < amount + 500_000:
        log.error("Мало TRX на мастер-кошельке для активации депозита")
        return False

    create = requests.post(f"{TRONGRID_API}/wallet/createtransaction",
                           json={
                               "owner_address": master_addr,   # base58
                               "to_address":    dest_addr,     # base58
                               "amount":        amount,
                               "visible":       True
                           }, headers=HEADERS, timeout=10).json()

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
    master_addr, priv = derive_master()

    # 1) Смотрим USDT
    usdt = get_usdt_balance(master_addr)

    # 2) Смотрим TRX (freeze v2)
    spend_sun, total_sun = get_total_balance_v2(master_addr)
    frozen_sun = max(0, total_sun - spend_sun)


    log.info(
        f"Bot started ✅\n"
        f"Master address: {master_addr}\n"
        f"Balance: {usdt:.2f} USDT | {frozen_sun/1e6:.2f} TRX freeze / {total_sun/1e6:.2f} TRX total"
    )

    if getattr(config, "ADMIN_CHAT_ID", None):
        try:
            await bot.send_message(
                config.ADMIN_CHAT_ID,
                f"🏁 *Бот запущен*\n"
                f"`{master_addr}`\n"
                f"*USDT*: {usdt:.2f}\n"
                f"*TRX*:  {total_sun/1e6:.2f} (в том числе заморожено {frozen_sun/1e6:.2f})",
                parse_mode="Markdown"
            )
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
async def poll_trc20_transactions(bot: Bot) -> None:
    """
    1. Раз в N минут читает все активные депозит-адреса из БД.
    2. Если на депозите найден баланс USDT:
       - Если на мастере < 6 TRX => делаем перевод USDT напрямую (fallback).
       - Иначе стандартная схема:
         (a) Активируем депозит (~1.1 TRX), если нужно.
         (b) Замораживаем 5 TRX (freezeBalance MASTER -> депозит), записываем в freeze_records.
         (c) Ждём пару секунд.
         (d) safe_usdt_transfer(...) → перевод USDT.
       - После успешного платежа -> оформляем платёж, продлеваем подписку, очищаем адрес.
    3. Если USDT = 0 -> пропуск.
    4. Если депозиту > 24 ч, аннулируем счёт.
    """

    log.info("Start poll…")
    master_addr, master_priv = derive_master()

    now = datetime.now()
    rows = supabase_client.get_pending_deposits_with_privkey()
    
    for row in rows:
        user_id     = row["id"]
        tg_id       = row["telegram_id"]
        dep_addr    = row["deposit_address"]
        dep_priv    = row["deposit_privkey"]
        created_at  = row["deposit_created_at"]

        # Проверяем, соответствует ли приватник адресу
        try:
            addr_from_priv = pub_to_b58(
                b'\x04' + ecdsa.SigningKey.from_string(bytes.fromhex(dep_priv),
                                                       curve=ecdsa.SECP256k1)
                              .verifying_key
                              .to_string()
            )
        except Exception:
            log.error(f"⚠️  dep_priv испорчен ({dep_priv[:8]}…) – пропуск")
            continue

        if addr_from_priv != dep_addr:
            log.error(f"⚠️  Приватный ключ не подходит к {dep_addr} – аннулирую")
            supabase_client.reset_deposit_address_and_privkey(user_id)
            continue

        if not dep_addr or not dep_priv:
            continue

        # Если счёт старше 24 ч, аннулируем
        if (now - created_at).total_seconds() > 24*3600:
            supabase_client.reset_deposit_address_and_privkey(user_id)
            try:
                await bot.send_message(tg_id, "Счёт истёк (24 ч). Сформируйте новый.")
            except Exception:
                pass
            continue

        # Проверяем баланс USDT
        usdt = get_usdt_balance(dep_addr)
        if usdt <= 0:
            # Нет поступлений
            continue

        log.info(f"🔎 Найдено {usdt:.2f} USDT на {dep_addr}")

        # Fallback, если мало TRX на мастере — переводим без freeze (прямой расход TRX на комиссию)
        master_info = get_trx_balance_v2(master_addr)
        master_trx_spend = master_info["balance"] / 1e6  # свободный
        # или, если нужен total:
        # total_sun = master_info["balance"] + master_info["frozen_balance_for_energy_v2"] + ...
        # master_trx_spend = total_sun / 1e6
        
        if master_trx_spend < 6:
            # Логируем
            log.warning(
                f"Внимание: на мастер-кошельке {master_addr} всего {master_trx_spend:.2f} TRX. "
                f"Недостаточно для заморозки (нужно >=6 TRX)."
            )
            # (опционально) Шлём администратору предупреждение
            if config.ADMIN_CHAT_ID:
                try:
                    await bot.send_message(
                        config.ADMIN_CHAT_ID,
                        f"⚠️ Остаток TRX на мастер-кошельке: {master_trx_spend:.2f}\n"
                        f"Переводы от пользователей невозможны!"
                    )
                except Exception as e:
                    log.warning(f"Cannot notify admin: {e}")

            # Пропускаем этот депозит
            continue



            # Успешно перевели — оформляем платёж
       
        # === Стандартная схема с freeze ===

        # (a) Активируем адрес, если на нём 0 TRX
        if get_trx_balance_v2(dep_addr) == 0:
            log.info(f"🚚 Активируем депозит: +1.1 TRX → {dep_addr}  (user #{user_id})")
            if not fund_address(master_priv, master_addr, dep_addr):
                log.error("❌ Не удалось активировать депозит-адрес (1.1 TRX)")
                continue
            time.sleep(3)  # подождём 1-2 блока

        # (b) Выполняем freezeBalance (5 TRX) c master -> dep_addr, чтобы был ENERGY
        freeze_sun = 5_000_000  # 5 TRX
        
        freeze_txid = freeze_balance_v2(
            owner_address=master_addr,
            owner_priv=master_priv,
            receiver_address=dep_addr,
            amount_sun=freeze_sun,
            resource="ENERGY"
        )
        if not freeze_txid:
            log.error("❌ FreezeBalance не выполнен, пропускаем депозит.")
            continue
        
        # Запишем в базу freeze
        record_freeze_in_db(dep_addr, freeze_sun, freeze_txid, "ENERGY")

        # (c) Ждём появления энергии, упростим до ~3 секунд ожидания
        time.sleep(3)

        # (d) Переводим USDT (safe_usdt_transfer)
        txid = safe_usdt_transfer(master_priv, master_addr, dep_priv, dep_addr, usdt)
        if not txid:
            log.error("❌ USDT transfer не прошёл")
            continue

        # После успеха — запись платежа, подписка, уведомление
        _after_success_payment(user_id, tg_id, dep_addr, usdt, txid, master_addr)

    log.info("Poll done.")


# ────────────────────────────────────────────────────────────────
# Служебная обёртка для корректного оформления платежа в БД + чат
# ────────────────────────────────────────────────────────────────

# ─── helper: безопасный USDT-трансфер с 1 повтором ──────────────
def safe_usdt_transfer(master_priv: str, master_addr: str,
                       dep_priv: str, dep_addr: str,
                       amount: float) -> Optional[str]:
    """
    • если на депозите < 0.5 TRX → докидываем 0.5 TRX
    • 1-я попытка отправить USDT
    • при BANDWIDTH_ERROR → спим 5 с и пробуем ещё раз
    """
    if get_trx_balance_v2(dep_addr)["balance"] < 500_000:                        # <0.5 TRX
        if fund_address(master_priv, master_addr, dep_addr):
            log.info(f"🚚 Extra 0.5 TRX → {dep_addr} (for bandwidth)")
            time.sleep(3)

    for i in (1, 2):
        txid = usdt_transfer(dep_priv, dep_addr, master_addr, amount)
        if txid:
            return txid
        log.warning("⌛ wait 5 s — ресурсы ещё не активировались")
        time.sleep(5)
    return None


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