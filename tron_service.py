#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tron_service.py — работа с TRON через TronGrid (без tronpy/TronWeb).
"""

import os, math, time, base64, logging, tempfile, requests, qrcode, base58, ecdsa, hashlib, asyncio
from datetime import datetime, timedelta, timezone
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
MIN_LEFTOVER_SUN = 1_000_000  # 1 TRX — оставляем на будущие комиссии

# ────────────────────────────────────────────────────────────────
# helper: POST с ретраями
# ────────────────────────────────────────────────────────────────


def as_utc(dt):
    """Вернёт datetime с tzinfo=UTC; если dt=None – None."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)



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
# 6.  Баланс TRX с учётом Freeze V2
# ────────────────────────────────────────────────────────────────
def get_trx_balance_v2(addr_b58: str) -> dict:
    """
    Возвращает словарь:
      balance                     – свободные TRX (Sun)
      frozen_balance_for_energy   – TRX, замороженные под ENERGY (Sun)
      frozen_balance_for_bandwidth– TRX, замороженные под BANDWIDTH (Sun)
    Этого достаточно для get_total_balance_v2.
    """
    data = tron_post(f"{TRONGRID_API}/wallet/getaccount",
                     json={"address": addr_b58, "visible": True})

    out = {"balance":               data.get("balance", 0),
           "frozen_balance_for_energy_v2":    0,
           "frozen_balance_for_bandwidth_v2": 0}

    for item in data.get("frozenV2", []):
        # TronGrid даёт объекты вида {"amount":N} и/или {"type":"ENERGY"}
        if item.get("type") == "ENERGY":
            out["frozen_balance_for_energy_v2"] += item.get("amount", 0)
        elif item.get("type") == "BANDWIDTH":
            out["frozen_balance_for_bandwidth_v2"] += item.get("amount", 0)

    return out


# ────────────────────────────────────────────────────────────────
# 6-bis.  Итоговый баланс TRX (свободный + замороженный V2)
# ────────────────────────────────────────────────────────────────
from typing import Tuple

def get_total_balance_v2(addr_b58: str) -> Tuple[int, int]:
    """
    Возвращает кортеж (spend_sun, total_sun):

    • spend_sun – свободный баланс (Sun)  
    • total_sun – spend_sun + замороженные ENERGY/BANDWIDTH (V2)

    Используется при старте бота и для мониторинга.
    """
    acc = get_trx_balance_v2(addr_b58)

    spend_sun = acc["balance"]
    frozen    = (
        acc.get("frozen_balance_for_energy_v2", 0) +
        acc.get("frozen_balance_for_bandwidth_v2", 0)
    )
    return spend_sun, spend_sun + frozen



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
# 7-bis.  Оповещение, если на мастере мало TRX
# ────────────────────────────────────────────────────────────────
async def notify_if_low_trx(bot: Bot, master_addr: str,
                            threshold_sun: int = 50_000_000) -> None:
    """
    Если свободных TRX на master-кошельке < threshold, шлём предупреждение админу.
    """
    bal = get_trx_balance_v2(master_addr)["balance"]          # свободные Sun
    if bal >= threshold_sun:
        return

    chat_id = getattr(config, "ADMIN_CHAT_ID", None)
    if not chat_id:
        return

    try:
        await bot.send_message(
            chat_id,
            f"⚠️ На master-кошельке {bal/1e6:.2f} TRX "
            f"(меньше порога {threshold_sun/1e6:.0f}). Пополните баланс!"
        )
    except Exception as e:
        log.warning(f"notify_if_low_trx: cannot send message: {e}")


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
async def poll_trc20_transactions(bot: Bot) -> None:
    """Сканируем депозитные адреса, продлеваем подписку, переводим средства."""
    log.info("Start poll…")
    master_addr, master_priv = derive_master()
    rows = supabase_client.get_pending_deposits_with_privkey()

    for row in rows:
        user_id   = row["id"]
        tg_id     = row["telegram_id"]
        dep_addr  = row["deposit_address"]
        dep_priv  = row["deposit_privkey"]
        created   = row["deposit_created_at"]

        if created.tzinfo is None:                 # делаем aware в UTC
            created = created.replace(tzinfo=timezone.utc)

        # 1) если 24 ч прошло и баланса нет — обнуляем адрес
        if (datetime.now(timezone.utc) - created).total_seconds() > 24 * 3600:
            if get_usdt_balance(dep_addr) == 0:
                supabase_client.reset_deposit_address_and_privkey(user_id)
                continue

        usdt = get_usdt_balance(dep_addr)
        if usdt <= 0:
            continue

        # 2) — продлеваем подписку с учётом триала/текущей подписки
        days_paid = math.ceil(
            usdt * config.DAYS_FOR_USDT / config.SUBSCRIPTION_PRICE_USDT
        )

        # ── ищем данные пользователя по Telegram-ID ──────────────────────────────
        user = supabase_client.get_user_by_telegram_id(tg_id)
        if not user:
            log.error("User tg=%s not found while processing deposit %s", tg_id, dep_addr)
            continue                                   # пропускаем запись

        now_utc       = datetime.now(timezone.utc)
        trial_end = as_utc(user.get("trial_end"))         # конец триала, может быть None
        sub_end   = as_utc(user.get("subscription_end"))   # конец подписки, может быть None

# выбираем самую позднюю из «сейчас / trial_end / subscription_end»
        base_start = max(d for d in (now_utc, trial_end, sub_end) if d)

# days_paid вычисляете выше (как и раньше)
        new_end = base_start + timedelta(days=days_paid)

# ── ОБНОВЛЯЕМ базу с правильной функцией / полем ────────────────────────
        supabase_client.update_subscription_end(user_id, new_end)

# ── уведомляем пользователя ─────────────────────────────────────────────
        start_str = base_start.astimezone().strftime("%d.%m.%Y")
        end_str   = new_end.astimezone().strftime("%d.%m.%Y")


        try:
            await bot.send_message(
                tg_id,
                f"Перевод в сумме {usdt:.2f} USDT получен.\n"
                f"Ваша подписка оформлена на {days_paid} дней.\n"
                f"Доступ к TradingGroup разрешён\n"
                f"с *{start_str}* по *{end_str}*.",
                parse_mode="Markdown",
            )
        except Exception:
            pass

        # 3) — пополняем депозит TRX для комиссии (30 TRX)
        if not send_trx(master_priv, master_addr, dep_addr, 30_000_000):
            continue
        await asyncio.sleep(3)

        # 4) — переводим USDT на мастер-адрес
        txid = usdt_transfer(
            dep_priv, dep_addr, master_addr, usdt,
            fee_limit=config.TRC20_USDT_FEE_LIMIT
        )
        if not txid:
            log.error("USDT transfer failed")
            continue

        # 5) — возвращаем почти весь остаток TRX, оставив 1 TRX
        leftover = get_trx_balance(dep_addr)
        if leftover > MIN_LEFTOVER_SUN:
            sweep_amount = leftover - MIN_LEFTOVER_SUN
            ret = return_trx(dep_priv, dep_addr, master_addr, sweep_amount)
            if not ret:
                await bot.send_message(
                    config.ADMIN_CHAT_ID,
                    f"⚠️ Не удалось вернуть {leftover / 1e6:.2f} TRX c {dep_addr}",
                )
                # не прерываем — продолжаем, чтобы не дублировать подписку

        # 6) — финальная запись и очистка
        supabase_client.create_payment(user_id, txid, usdt, 0)
        supabase_client.update_payment_days(user_id, usdt, days_paid)
        supabase_client.reset_deposit_address_and_privkey(user_id)

        log.info(
            "✅ %.2f USDT с %s → мастер; подписка до %s",
            usdt, dep_addr, end_str,
        )

    log.info("Poll done.")


    # ────────────────────────────────────────────────────────────────
# 11-bis.  Печать баланса мастера при старте бота
# ────────────────────────────────────────────────────────────────
async def print_master_balance_at_start(bot: Bot) -> None:
    """
    • Считает текущие балансы мастера (USDT + TRX со свободным и frozen-V2).
    • Выводит информацию в лог.
    • Если указан ADMIN_CHAT_ID ― присылает краткое сообщение админу.
    """
    master_addr, _ = derive_master()

    usdt           = get_usdt_balance(master_addr)
    spend_sun, tot = get_total_balance_v2(master_addr)
    frozen_sun     = max(0, tot - spend_sun)

    # напоминание об остатке TRX
    await notify_if_low_trx(bot, master_addr)

    log.info(
        "Bot started ✅\n"
        f"Master address: {master_addr}\n"
        f"Balance: {usdt:.2f} USDT | {frozen_sun/1e6:.2f} TRX freeze / {tot/1e6:.2f} TRX total"
    )

    admin_chat = getattr(config, "ADMIN_CHAT_ID", None)
    if admin_chat:
        try:
            await bot.send_message(
                admin_chat,
                (
                    "🏁 *Бот запущен*\n"
                    f"`{master_addr}`\n"
                    f"*USDT*: {usdt:.2f}\n"
                    f"*TRX*:  {tot/1e6:.2f} "
                    f"(в том числе заморожено {frozen_sun/1e6:.2f})"
                ),
                parse_mode="Markdown"
            )
        except Exception as e:
            log.warning(f"Cannot notify admin: {e}")

