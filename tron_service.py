#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tron_service.py — работа с TRON через TronGrid (без tronpy/TronWeb).
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
FUND_EXTRA_SUN     = 100_000             # 0.1 TRX запас
USDT_CONTRACT      = config.TRC20_USDT_CONTRACT or "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

# ────────────────────────────────────────────────────────────────
# helper: POST с ретраями
# ────────────────────────────────────────────────────────────────
def tron_post(url: str, *, json: Optional[dict] = None,
              timeout: int = 10, retries: int = 3) -> dict:
    """POST к TronGrid с 3-кратным ретраем."""
    for attempt in range(1, retries+1):
        try:
            r = requests.post(url, json=json, headers=HEADERS, timeout=timeout)
            if r.status_code == 200:
                return r.json()
            log.warning(f"tron_post {url} HTTP {r.status_code}")
        except Exception as e:
            log.warning(f"tron_post {url} fail {attempt}/{retries}: {e}")
        time.sleep(0.4 * attempt)
    return {}

# ────────────────────────────────────────────────────────────────
# 2.  Keccak-256
# ────────────────────────────────────────────────────────────────
try:
    import sha3
    def keccak_256(data: bytes) -> bytes:
        h = sha3.keccak_256(); h.update(data); return h.digest()
except ImportError:
    from Crypto.Hash import keccak     # pycryptodome
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
    return raw[:-4]

def b58_to_hex(addr: str) -> str: return b58decode_check(addr).hex()
def hex_to_b58(hex_addr: str) -> str:
    if hex_addr.startswith("0x"): hex_addr = hex_addr[2:]
    raw = bytes.fromhex(hex_addr)
    chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return base58.b58encode(raw+chk).decode()

def pub_to_b58(pub65: bytes) -> str:
    h   = keccak_256(pub65[1:])
    raw = b"\x41" + h[-20:]
    chk = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return base58.b58encode(raw+chk).decode()

def _looks_like_hex(s:str)->bool:
    try: int(s,16); return 40<=len(s)<=44
    except ValueError: return False

# ────────────────────────────────────────────────────────────────
# 4.  Подпись транзакции
# ────────────────────────────────────────────────────────────────
def sign_tx(tx:Dict, priv_hex:str)->Dict:
    priv_hex = priv_hex.lstrip("0x").rjust(64,"0")
    sk  = ecdsa.SigningKey.from_string(bytes.fromhex(priv_hex),
                                       curve=ecdsa.SECP256k1)
    pub = b"\x04"+sk.verifying_key.to_string()
    txid= bytes.fromhex(tx["txID"])

    owner_raw = tx["raw_data"]["contract"][0]["parameter"]["value"]["owner_address"].lstrip("0x")
    owner_b58 = hex_to_b58(owner_raw[-42:]) if _looks_like_hex(owner_raw) else owner_raw
    if pub_to_b58(pub)!=owner_b58:
        raise ValueError("privkey mismatch")

    sig_rs = sk.sign_digest(txid, sigencode=ecdsa.util.sigencode_string_canonize)
    cands  = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
        sig_rs, txid, curve=ecdsa.SECP256k1,
        sigdecode=ecdsa.util.sigdecode_string,
        hashfunc=hashlib.sha256)
    for rec_id,vk in enumerate(cands):
        if pub_to_b58(b"\x04"+vk.to_string())==owner_b58:
            signed=tx.copy(); signed["signature"]=[(sig_rs+bytes([rec_id])).hex()]
            return signed
    raise ValueError("Cannot build signature")

def sign_and_broadcast(raw_tx:dict, priv_hex:str)->Optional[str]:
    signed = sign_tx(raw_tx, priv_hex)
    br = tron_post(f"{TRONGRID_API}/wallet/broadcasttransaction", json=signed)
    if not br.get("result"):
        log.error(f"broadcast failed: {br}"); return None
    return br.get("txid")

# ────────────────────────────────────────────────────────────────
# 5.  Master-адрес
# ────────────────────────────────────────────────────────────────
def derive_master()->Tuple[str,str]:
    if getattr(config,"TRON_MASTER_PRIVKEY",None):
        priv=config.TRON_MASTER_PRIVKEY.lstrip("0x")
        sk  = ecdsa.SigningKey.from_string(bytes.fromhex(priv),curve=ecdsa.SECP256k1)
        return pub_to_b58(b"\x04"+sk.verifying_key.to_string()), priv
    seed=Bip39SeedGenerator(config.TRON_MASTER_SEED).Generate()
    acc =(Bip44.FromSeed(seed,Bip44Coins.TRON).Purpose().Coin()
               .Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0))
    return acc.PublicKey().ToAddress(), acc.PrivateKey().Raw().ToHex()

# ────────────────────────────────────────────────────────────────
# 6.  Баланс USDT / TRX
# ────────────────────────────────────────────────────────────────
def get_usdt_balance(addr:str)->float:
    param=b58_to_hex(addr)[2:].rjust(64,"0")
    r=tron_post(f"{TRONGRID_API}/wallet/triggerconstantcontract",
        json={"owner_address":addr,"contract_address":USDT_CONTRACT,
              "function_selector":"balanceOf(address)",
              "parameter":param,"visible":True})
    if not r.get("result",{}).get("result",True):
        log.warning("balanceOf error")
        return 0.0
    val=int(r.get("constant_result",["0"])[0],16)
    return val/1e6

def get_trx_balance(addr:str)->int:
    acc=tron_post(f"{TRONGRID_API}/wallet/getaccount",
                  json={"address":addr,"visible":True})
    return acc.get("balance",0)

# ────────────────────────────────────────────────────────────────
# 7.  TRC-20 transfer
# ────────────────────────────────────────────────────────────────
def usdt_transfer(priv_from:str, addr_from:str,
                  addr_to:str, amount:float,
                  fee_limit:int=20_000_000)->Optional[str]:
    value=int(round(amount*1e6))
    param=b58_to_hex(addr_to)[2:].rjust(64,"0")+hex(value)[2:].rjust(64,"0")
    txo=tron_post(f"{TRONGRID_API}/wallet/triggersmartcontract",
        json={"contract_address":USDT_CONTRACT,"owner_address":addr_from,
              "function_selector":"transfer(address,uint256)",
              "parameter":param,"fee_limit":fee_limit,"visible":True})
    tx=txo.get("transaction")
    if not tx:
        log.error("create transfer failed"); return None
    return sign_and_broadcast(tx, priv_from)



# ────────────────────────────────────────────────────────────────
# 7-bis.  Создание депозитного адреса + QR-код
# ────────────────────────────────────────────────────────────────
def generate_ephemeral_address(user_id: int) -> Dict[str, str]:
    """
    Генерирует новый KeyPair, сохраняет (addr, priv_hex, created_at) в Supabase
    и возвращает словарь с адресом и приватным ключом.
    """
    priv = os.urandom(32)
    sk   = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    pub  = b"\x04" + sk.verifying_key.to_string()
    addr = pub_to_b58(pub)

    supabase_client.set_deposit_address_and_privkey(user_id, addr, priv.hex())
    log.info(f"Создан депозит {addr} для user={user_id}")
    return {"address": addr, "private_key": priv.hex()}


def create_qr_code(data: str) -> str:
    """
    Генерирует PNG-файл с QR-кодом (адрес или любой текст) и
    возвращает путь к временно сохранённому файлу.
    Файл НЕ удаляется автоматически — вызывающая сторона сама решает,
    когда убрать.
    """
    img = qrcode.make(data)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    img.save(tmp.name)
    return tmp.name




# ────────────────────────────────────────────────────────────────
# 8.  TRX helper-функции
# ────────────────────────────────────────────────────────────────
def send_trx(master_priv:str, master_addr:str,
             dest_addr:str, amount_sun:int)->bool:
    raw=tron_post(f"{TRONGRID_API}/wallet/createtransaction",
                  json={"owner_address":master_addr,"to_address":dest_addr,
                        "amount":amount_sun,"visible":True})
    if "txID" not in raw: log.error("create trx failed"); return False
    txid=sign_and_broadcast(raw, master_priv)
    if not txid: return False
    log.info(f"TRX {amount_sun/1e6:.2f} sent to {dest_addr}, tx={txid}")
    return True

def return_trx(dep_priv:str, dep_addr:str,
               master_addr:str, amount:int)->Optional[str]:
    raw=tron_post(f"{TRONGRID_API}/wallet/createtransaction",
                  json={"owner_address":dep_addr,"to_address":master_addr,
                        "amount":amount,"visible":True})
    if "txID" not in raw: return None
    return sign_and_broadcast(raw, dep_priv)

# ────────────────────────────────────────────────────────────────
# 9.  Основной опрос депозитов
# ────────────────────────────────────────────────────────────────
async def poll_trc20_transactions(bot:Bot)->None:
    log.info("Start poll…")
    master_addr, master_priv = derive_master()
    rows=supabase_client.get_pending_deposits_with_privkey()

    for row in rows:
        user_id   = row["id"]
        tg_id     = row["telegram_id"]
        dep_addr  = row["deposit_address"]
        dep_priv  = row["deposit_privkey"]
        created   = row["deposit_created_at"]

        # проверяем 24 ч
        if (datetime.now()-created).total_seconds()>24*3600:
            if get_usdt_balance(dep_addr)==0:
                supabase_client.reset_deposit_address_and_privkey(user_id)
                continue

        usdt=get_usdt_balance(dep_addr)
        if usdt<=0: continue

        # ── 0. продлеваем подписку ПРЯМО СЕЙЧАС ────────────────────
        days = math.ceil(usdt*config.DAYS_FOR_USDT/config.SUBSCRIPTION_PRICE_USDT)
        supabase_client.apply_subscription_extension(user_id, days)
        until = supabase_client.get_subscription_until(user_id)
        start_str = datetime.now().strftime("%d.%m.%Y")
        end_str   = until.strftime("%d.%m.%Y") if until else "—"
        try:
            await bot.send_message(
                tg_id,
                f"Перевод в сумме {usdt:.2f} USDT получен.\n"
                f"Ваша подписка оформлена на {days} дней.\n"
                f"Доступ к TradingGroup разрешён\n"
                f"с *{start_str}* по *{end_str}*.",
                parse_mode="Markdown")
        except Exception: pass

        # ── 1. пополняем депозит на 30 TRX ────────────────────────
        if not send_trx(master_priv, master_addr, dep_addr, 30_000_000):
            continue
        await asyncio.sleep(3)

        # ── 2. переводим USDT ─────────────────────────────────────
        txid = usdt_transfer(dep_priv, dep_addr, master_addr, usdt,
                             fee_limit=config.TRC20_USDT_FEE_LIMIT)
        if not txid:
            log.error("USDT transfer failed"); continue

        # ── 3. возвращаем остаток TRX ─────────────────────────────
        leftover = get_trx_balance(dep_addr)
        if leftover>100_000:
            ret = return_trx(dep_priv, dep_addr, master_addr, leftover-100_000)
            if not ret:
                await bot.send_message(config.ADMIN_CHAT_ID,
                    f"⚠️ Не удалось вернуть {leftover/1e6:.2f} TRX c {dep_addr}")
                continue

        # ── 4. финальная запись и очистка ─────────────────────────
        supabase_client.create_payment(user_id, txid, usdt, 0)
        supabase_client.update_payment_days(user_id, usdt, days)
        supabase_client.reset_deposit_address_and_privkey(user_id)
        log.info(f"✅ {usdt:.2f} USDT с {dep_addr} → мастер; подписка до {end_str}")

    log.info("Poll done.")