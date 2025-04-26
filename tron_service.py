import logging
import tempfile
import qrcode
from datetime import datetime
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip44DepthError
from config import TRON_MASTER_SEED

log = logging.getLogger(__name__)


def poll_trc20_transactions():
    """
    Заглушка: вызывается планировщиком (main.py) каждые N минут,
    чтобы проверить поступление USDT на ваши адреса.
    Реализация будет позже.
    """
    log.debug("poll_trc20_transactions: not yet implemented.")

    
def create_qr_code(data: str) -> str:
    """
    Генерирует PNG-файл с QR-кодом. Возвращает путь к файлу.
    """
    try:
        img = qrcode.make(data)
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        img.save(tmp.name)
        return tmp.name
    except Exception as e:
        log.error(f"Error creating QR code: {e}")
        return ""

def generate_new_tron_address(index: int) -> dict:
    """
    Используем master seed (TRON_MASTER_SEED) из .env и BIP44 для Tron:
      - coin_type=195
      - путь: m/44'/195'/0'/0/index

    Возвращаем dict: {"address": "Txxx...", "private_key": "hex"}
    """
    try:
        # 1) Генерируем seed из сид-фразы
        #   В библиотеках bip_utils актуальная сигнатура:
        #   seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
        seed_bytes = Bip39SeedGenerator(TRON_MASTER_SEED).Generate()

        # 2) Инициализируем BIP44 для Tron
        bip44_m = Bip44.FromSeed(seed_bytes, Bip44Coins.TRON)

        # 3) Деривация: m/44'/195'/0'/0/index
        bip44_addr = bip44_m.Purpose() \
                            .Coin() \
                            .Account(0) \
                            .Change(Bip44Changes.CHAIN_EXT) \
                            .AddressIndex(index)

        priv_key_obj = bip44_addr.PrivateKey()
        pub_key_obj = bip44_addr.PublicKey()

        private_key_hex = priv_key_obj.Raw().ToHex()
        tron_address = pub_key_obj.ToAddress()   # 'T...' Tron base58 address

        return {
            "address": tron_address,
            "private_key": private_key_hex
        }

    except Bip44DepthError as e:
        log.error(f"Index out of depth for BIP44: {e}")
        return {
            "address": "",
            "private_key": ""
        }
    except Exception as e:
        log.error(f"Error generating Tron address from seed: {e}")
        return {
            "address": "",
            "private_key": ""
        }