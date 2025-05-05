import psycopg2
import logging

from datetime import datetime, timedelta
from config import DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME
from typing import Optional
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





def set_deposit_address_and_privkey(user_id: int, address: str, privkey: str):
    """
    Записываем одноразовый депозитный адрес, его приватный ключ и время выдачи.
    """
    with _get_connection() as conn, conn.cursor() as cur:
        cur.execute("""
            UPDATE users
               SET deposit_address     = %s,
                   deposit_privkey     = %s,
                   deposit_created_at  = NOW(),
                   energy_deposit_sun  = NULL
             WHERE id = %s
        """, (address, privkey, user_id))
        conn.commit()

def get_pending_deposits_with_privkey():
    """
    Возвращает пользователей с активным депозитом, где есть и адрес, и приватный ключ.
    """
    with _get_connection() as conn, conn.cursor() as cur:
        cur.execute("""
            SELECT id, telegram_id, deposit_address, deposit_privkey, deposit_created_at
              FROM users
             WHERE deposit_address IS NOT NULL
               AND deposit_privkey IS NOT NULL
        """)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in rows]
    
def get_all_deposit_addresses() -> list[str]:
    with _get_connection() as c, c.cursor() as cur:
        cur.execute("SELECT deposit_address FROM users WHERE deposit_address IS NOT NULL")
        return [r[0] for r in cur.fetchall()]
    

def reset_deposit_address_and_privkey(user_id: int):
    """
    Обнуляем одноразовый адрес после использования/истечения.
    """
    with _get_connection() as conn, conn.cursor() as cur:
        cur.execute("""
            UPDATE users
               SET deposit_address    = NULL,
                   deposit_privkey    = NULL,
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




def create_payment(user_id: int, txhash: str, amount_usdt: float, days_added: int):
    """
    Создаём запись в payments.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO payments(user_id, txhash, amount_usdt, days_added, 
                                     paid_at, created_at)
                VALUES (%s, %s, %s, %s, NOW(), NOW())
            """, (user_id, txhash, amount_usdt, days_added))
            conn.commit()


def update_deposit_address(user_id: int, address: str, priv_hex: str | None):
    """
    Обновляем (или создаём) адрес депозита.
    Если priv_hex=None  – приватный ключ не меняем.
    """
    with _get_connection() as conn, conn.cursor() as cur:
        if priv_hex is None:
            cur.execute("""
                UPDATE users
                   SET deposit_address = %s,
                       deposit_created_at = NOW()
                 WHERE id = %s
            """, (address, user_id))
        else:
            cur.execute("""
                UPDATE users
                   SET deposit_address = %s,
                       deposit_privkey   = %s,
                       deposit_created_at = NOW()
                 WHERE id = %s
            """, (address, priv_hex, user_id))

def update_payment_days(user_id: int, amount_usdt: float, days_added: int) -> None:
    """
    Обновляет поле days_added в САМОЙ ПОСЛЕДНЕЙ записи payments
    для данного user_id и той же суммы USDT.
    """
    with _get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            WITH last_pay AS (
                SELECT id
                FROM   payments
                WHERE  user_id = %s
                  AND  amount_usdt = %s
                ORDER  BY id DESC
                LIMIT  1
            )
            UPDATE payments AS p
            SET    days_added = %s
            FROM   last_pay
            WHERE  p.id = last_pay.id
            RETURNING p.id
            """,
            (user_id, amount_usdt, days_added)
        )
        conn.commit()

def apply_subscription_extension(user_id: int, days_to_add: int):
    """
    Продляем/назначаем подписку. 
    Учитываем trial_end vs subscription_end:
      - Если subscription_end > now => subscription_end += days_to_add
      - Иначе => subscription_end = now + days_to_add
      - Но если trial_end > now => подписка может начаться после trial_end
    """
    now = datetime.now()
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT trial_end, subscription_start, subscription_end
                  FROM users
                 WHERE id=%s
            """, (user_id,))
            row = cur.fetchone()
            if not row:
                return
            trial_end, sub_start, sub_end = row

            # Вычислим start_point
            if trial_end and trial_end > now:
                start_point = trial_end
            else:
                # Если sub_end еще активен => начинаем с sub_end
                if sub_end and sub_end > now:
                    start_point = sub_end
                else:
                    start_point = now

            new_sub_start = start_point if sub_start is None or sub_start < start_point else sub_start
            new_sub_end = start_point + timedelta(days=days_to_add)

            cur.execute("""
                UPDATE users
                   SET subscription_start = %s,
                       subscription_end   = %s
                 WHERE id = %s
            """, (new_sub_start, new_sub_end, user_id))
            conn.commit()

def get_user_sub_info(user_id: int) -> str:
    """
    Пример: вернём строку "Ваша подписка до 12.06.2025 (ещё 45 дней)."
    Если нет sub_end, "Подписка не оформлена" 
    """
    now = datetime.now()
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT subscription_start, subscription_end
                  FROM users
                 WHERE id=%s
            """, (user_id,))
            row = cur.fetchone()
            if not row:
                return "Подписка не найдена."
            sstart, send = row
            if not send:
                return "Подписка не оформлена."

            if send > now:
                dleft = (send - now).days
                return f"Ваша подписка действует до {send.strftime('%d.%m.%Y')} (~{dleft} дн)."
            else:
                return "Подписка истекла."

# внизу файла (после apply_subscription_extension)

def get_subscription_(user_id: int):
    """
    Возвращает datetime expiration (или None),
    чтобы красиво показать диапазон доступа пользователю.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT subscription_end FROM users WHERE id=%s",
                (user_id,)
            )
            row = cur.fetchone()
            return row[0] if row else None
        
# Добавьте или обновите функцию
def update_subscription_end(user_id: int, new_until: datetime) -> None:
    """
    Обновляет поле subscription_end у пользователя.
    """
    with _get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE users
               SET subscription_end = %s
             WHERE id = %s
            """,
            (new_until, user_id)
        )

def get_all_users():
    with _get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM users")
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in rows]
    

def get_pending_payment(user_id: int, deposit_addr: str) -> Optional[int]:
    with _get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id FROM payments
             WHERE user_id = %s AND deposit_address = %s AND status = 'pending'
            """,
            (user_id, deposit_addr)
        )
        row = cur.fetchone()
        return row[0] if row else None


def create_pending_payment(user_id: int, deposit_addr: str,
                           amount_usdt: float, days_added: int) -> int:
    with _get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO payments (user_id, deposit_address,
                                  amount_usdt, days_added, status)
            VALUES (%s, %s, %s, %s, 'pending')
            RETURNING id
            """,
            (user_id, deposit_addr, amount_usdt, days_added)
        )
        conn.commit()
        return cur.fetchone()[0]
    
def mark_payment_paid(payment_id: int, txid: str):
    with _get_connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE payments
               SET status = 'paid',
                   txhash = %s,
                   paid_at = NOW()
             WHERE id = %s
            """,
            (txid, payment_id)
        )
        conn.commit()

