#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
• Фризуем 1 TRX на ENERGY на 3 дня
• Через ~60 c пытаемся перевести 3.40 USDT
"""

import time, requests, logging, os, ecdsa
from tron_service import (b58_to_hex, sign_tx, usdt_transfer,
                          get_trx_balance, get_usdt_balance)

logging.basicConfig(level=logging.INFO, format="%(message)s")
TRONGRID = "https://api.trongrid.io"
HEADERS  = {}                 # ← если есть PRO-API-KEY – добавьте {'TRON-PRO-API-KEY': ...}

DEP_ADDR  = "TWtHZSRv8B1wRVtugp6fAxRK98scEfAtZ8"
DEP_PRIV  = "265f1baf0a5f27a715c2b7fd4991215f3f5a805129259e8b682dd93a8735e877"
MASTER    = "TNCzEE272xwu3zz1zJw4En1AiGxaXuiwMS"
AMOUNT    = 3.40

# ---------- 1) freeze 1 TRX → ENERGY -----------------------------------------
if get_trx_balance(DEP_ADDR) < 1_000_000:
    raise SystemExit("На депозите нет 1 TRX для фриза - пополните 1 TRX и повторите")

payload = {
    "owner_address": b58_to_hex(DEP_ADDR),
    "frozen_balance": 1_000_000,   # 1 TRX
    "resource_type":  "ENERGY",
    "lock_time":      3*24*3600,   # 3 дня
    "visible":        False
}
tx = requests.post(f"{TRONGRID}/wallet/freezebalancev2",
                   json=payload, headers=HEADERS, timeout=10).json()
signed = sign_tx(tx, DEP_PRIV)
br = requests.post(f"{TRONGRID}/wallet/broadcasttransaction",
                   json=signed, headers=HEADERS, timeout=10).json()
assert br.get("result"), f"freeze broadcast failed: {br}"
logging.info("✅ freeze-ENERGY tx %s (ждём 3 блока)…", br["txid"])

time.sleep(60)          # надёжно: 60 с ≈ 3-4 блока

# ---------- 2) USDT transfer --------------------------------------------------
txid = usdt_transfer(DEP_PRIV, DEP_ADDR, MASTER,
                     AMOUNT,                 # 3.40 USDT
                     fee_limit=8_000_000)    # 8 TRX
if txid:
    logging.info("🎉 DONE!  USDT tx %s", txid)
else:
    logging.error("😥 всё ещё OUT OF ENERGY… проверьте баланс, попробуйте +1 TRX фриза")