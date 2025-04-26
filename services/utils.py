# services/utils.py
from datetime import datetime, timezone

def now_utc():
    return datetime.now(timezone.utc)

def format_datetime(dt) -> str:
    if not dt:
        return "N/A"
    if isinstance(dt, datetime):
        return dt.strftime("%Y-%m-%d %H:%M")
    return str(dt)
