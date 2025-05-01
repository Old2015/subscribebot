#!/usr/bin/env python3
# test_tron_api.py
import requests
import sys

# ========== НАСТРОЙКА ==========
TRON_API_KEY = "eab8ef1e-293a-4085-a65f-e39752e46afb"  # ваш ключ
TEST_ADDRESS = "TNCzEE272xwu3zz1zJw4En1AiGxaXuiwMS" # пример master-адрес
TRONGRID_API = "https://api.trongrid.io"     # бесплатный узел, если PRO, тоже можно

HEADERS = {
    "Content-Type": "application/json",
    # TronGrid распознаёт ключ по заголовку TRON-PRO-API-KEY
    "TRON-PRO-API-KEY": TRON_API_KEY
}

def main():
    # 1) /wallet/getaccount
    url1 = f"{TRONGRID_API}/wallet/getaccount"
    body1 = {"address": TEST_ADDRESS, "visible": True}
    print("=== GETACCOUNT ===")
    try:
        r1 = requests.post(url1, json=body1, headers=HEADERS, timeout=10)
        print("status_code =", r1.status_code)
        print("response text =", r1.text)
        print("--------------")
    except Exception as e:
        print("Error getaccount:", e)

    # 2) /wallet/getaccountresource
    url2 = f"{TRONGRID_API}/wallet/getaccountresource"
    body2 = {"address": TEST_ADDRESS, "visible": True}
    print("=== GETACCOUNTRESOURCE ===")
    try:
        r2 = requests.post(url2, json=body2, headers=HEADERS, timeout=10)
        print("status_code =", r2.status_code)
        print("response text =", r2.text)
        print("--------------")
    except Exception as e:
        print("Error getaccountresource:", e)

    # 3) /wallet/getaccountresourcev2
    url3 = f"{TRONGRID_API}/wallet/getaccountresourcev2"
    body3 = {"address": TEST_ADDRESS, "visible": True}
    print("=== GETACCOUNTRESOURCEv2 ===")
    try:
        r3 = requests.post(url3, json=body3, headers=HEADERS, timeout=10)
        print("status_code =", r3.status_code)
        print("response text =", r3.text)
        print("--------------")
    except Exception as e:
        print("Error getaccountresourcev2:", e)

if __name__ == "__main__":
    main()
