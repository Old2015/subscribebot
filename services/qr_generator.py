# services/qr_generator.py
import qrcode
import tempfile

def create_qr_code(data: str):
    try:
        img = qrcode.make(data)
        temp_path = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        img.save(temp_path.name)
        return temp_path.name
    except Exception as e:
        print("QR generation error:", e)
        return None
