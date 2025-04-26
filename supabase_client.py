import psycopg2
import logging
from datetime import datetime, timedelta
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
    Проверяем, что таблицы 'users' и 'payments' существуют.
    Если что-то не так – выводим ошибку в лог.
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

def get_user_by_telegram_id(telegram_id: int):
    """
    Возвращает словарь с данными пользователя, 
    если в таблице users есть запись, иначе None.
    Предполагаем, что telegram_id BIGINT UNIQUE.
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
    Создаёт нового пользователя в таблице 'users', 
    выставляет trial_end = NOW() + interval 'X day'.
    Возвращает словарь с полями пользователя.
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

def update_deposit_info(user_id: int, address: str, pk: str):
    """
    Сохраняем в таблице users:
      deposit_address = address
      private_key = pk  (опционально, если у вас есть такое поле)
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            # Убедитесь, что в таблице users есть поля deposit_address, private_key
            cur.execute("""
                UPDATE users
                   SET deposit_address = %s,
                       private_key = %s
                 WHERE id = %s
            """, (address, pk, user_id))
            conn.commit()

def update_deposit_created_at(user_id: int, created_at: datetime):
    """
    Обновляет deposit_created_at = created_at.
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
    Сбрасываем поля deposit_address, deposit_created_at, private_key (если есть).
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                   SET deposit_address = NULL,
                       deposit_created_at = NULL,
                       private_key = NULL
                 WHERE id = %s
            """, (user_id,))
            conn.commit()

#
# Пример методов для payments (если нужно)
#

def create_payment(user_id: int, txhash: str, amount_usdt: float, days_added: int):
    """
    Вставляем запись о платеже в таблицу payments.
    paid_at (вручную или NOW()), status='paid'...
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
    Пример функции: вернуть запись из payments по ID.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM payments WHERE id=%s", (payment_id,))
            row = cur.fetchone()
            if row:
                cols = [desc[0] for desc in cur.description]
                return dict(zip(cols, row))
    return None