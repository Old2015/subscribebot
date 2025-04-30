#!/usr/bin/env python3
# check_locked_real.py
import requests, json, sys, os, base58, hashlib

TRONGRID_API = "https://api.trongrid.io"
MASTER = "TRMTBW9ph1c7KapZjMKucDP2V3dYQ5TgrG"      # ← ваш адресс

def get_account(b58: str) -> dict:
    return requests.post(
        TRONGRID_API + "/wallet/getaccount",
        json={"address": b58, "visible": True}, timeout=10
    ).json()

acc = get_account(MASTER)
pledge_sun = acc.get("account_resource", {}).get("pledge_balance_for_energy", 0)
frozen_sun = acc.get("frozen_balance_for_energy", 0) + acc.get("frozen_balance", 0)

print(f"🔒 pledge_balance_for_energy : {pledge_sun/1e6:,.2f} TRX")
print(f"❄️  frozen_balance (+energy) : {frozen_sun/1e6:,.2f} TRX")
print(f"💰 spendable balance         : {acc.get('balance',0)/1e6:,.2f} TRX")