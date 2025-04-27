import psycopg2
import logging
from datetime import datetime
from config import DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME

log = logging.getLogger(__name__)

def _get_connection():
    return psycopg2.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME
    )

def check_db_structure():
    """
    Проверяем, что таблицы 'users' и 'payments' доступны.
    Если их нет или есть проблемы — логируем ошибку.
    """
    tables = ["users", "payments"]
    for t in tables:
        try:
            with _get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT 1 FROM {t} LIMIT 1")
            log.info(f"Таблица '{t}' доступна.")
        except psycopg2.Error as e:
            log.error(f"Ошибка проверки таблицы '{t}': {e}")

def increment_deposit_index(user_id: int):
    """
    Увеличить deposit_index на 1 и вернуть новое значение.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                   SET deposit_index = deposit_index + 1
                 WHERE id = %s
                 RETURNING deposit_index
            """, (user_id,))
            row = cur.fetchone()
            conn.commit()
            if row:
                return row[0]
    return 0


def create_user_custom_trial(telegram_id: int, username: str, trial_end: datetime):
    """
    Создаём пользователя с trial_end = заданная дата/время.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (telegram_id, username, trial_end, created_at)
                VALUES (%s, %s, %s, NOW())
                RETURNING *
            """, (telegram_id, username, trial_end))
            row = cur.fetchone()
            conn.commit()
            if row:
                cols = [desc[0] for desc in cur.description]
                return dict(zip(cols, row))
    return None

def get_user_by_telegram_id(telegram_id: int):
    """
    Ищем пользователя в таблице 'users' по полю telegram_id.
    Возвращаем словарь (колонки) или None, если не найден.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE telegram_id = %s", (telegram_id,))
            row = cur.fetchone()
            if not row:
                return None
            cols = [desc[0] for desc in cur.description]
            return dict(zip(cols, row))

def create_user_with_trial(telegram_id: int, username: str, trial_days: int):
    """
    Создаём нового пользователя:
      - telegram_id (уникальный)
      - username
      - trial_end = NOW() + interval 'X day'
      - created_at = NOW()
    Возвращаем dict с данными пользователя (строка из БД).
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (telegram_id, username, trial_end, created_at)
                VALUES (%s, %s, NOW() + interval '%s day', NOW())
                RETURNING *
            """, (telegram_id, username, trial_days))
            row = cur.fetchone()
            conn.commit()

            if row:
                cols = [desc[0] for desc in cur.description]
                return dict(zip(cols, row))
            return None

def update_deposit_info(user_id: int, address: str):
    """
    Сохраняем адрес для оплаты (TRC20/ETH) в таблице 'users'.
    deposit_address = address
    (приватный ключ не храним!)
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                   SET deposit_address = %s
                 WHERE id = %s
            """, (address, user_id))
            conn.commit()

def update_deposit_created_at(user_id: int, created_at: datetime):
    """
    Обновляем время, когда был выдан адрес (deposit_created_at).
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                   SET deposit_created_at = %s
                 WHERE id = %s
            """, (created_at, user_id))
            conn.commit()

def reset_deposit_address(user_id: int):
    """
    Сбрасываем поля deposit_address и deposit_created_at,
    если нужно освободить/отключить старый адрес.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                   SET deposit_address = NULL,
                       deposit_created_at = NULL
                 WHERE id = %s
            """, (user_id,))
            conn.commit()

# Примеры функций для таблицы payments, если нужны:

def create_payment(user_id: int, txhash: str, amount_usdt: float, days_added: int):
    """
    Вставляем запись о платеже в 'payments':
      user_id, txhash, amount_usdt, days_added, paid_at=NOW(), status='paid', created_at=NOW()
    Возвращаем id платёжной записи.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO payments(user_id, txhash, amount_usdt, days_added, paid_at, status, created_at)
                VALUES (%s, %s, %s, %s, NOW(), 'paid', NOW())
                RETURNING id
            """, (user_id, txhash, amount_usdt, days_added))
            row = cur.fetchone()
            conn.commit()
            if row:
                return row[0]
            return None

def get_payment_by_id(payment_id: int):
    """
    Пример: вернуть запись о платеже по ID.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM payments WHERE id = %s", (payment_id,))
            row = cur.fetchone()
            if row:
                cols = [desc[0] for desc in cur.description]
                return dict(zip(cols, row))
    return None