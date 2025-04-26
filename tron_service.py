import config
import qrcode
import tempfile
# from tronpy import Tron
# from tronpy.keys import PrivateKey
# ...

def generate_new_tron_address():
    """
    Заглушка: в реальности нужно генерировать адрес с помощью
    tronpy + master seed (HD) или просто random PrivateKey().
    """
    new_address = "TEXAMPLE123..."
    return new_address

def create_qr_code(data:str):
    """
    Генерируем QR-код для адреса (или URI).
    Возвращаем путь к временному PNG-файлу.
    """
    try:
        img = qrcode.make(data)
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        img.save(tmp.name)
        return tmp.name
    except Exception as e:
        print("QR error:", e)
        return None

def poll_trc20_transactions():
    """
    Заглушка: опрашиваем блокчейн Tron, ищем входящие транзакции USDT
    Возвращаем список словарей: { 'to':..., 'amount':..., 'txhash':... }
    """
    # Реализовать через tronpy + logs
    return []
