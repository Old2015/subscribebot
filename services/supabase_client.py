# services/supabase_client.py
import os
import psycopg2
from datetime import datetime, timedelta

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

def _get_connection():
    return psycopg2.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME
    )

def get_user_by_telegram_id(telegram_id: int):
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE telegram_id=%s", (telegram_id,))
            row = cur.fetchone()
            if row:
                # Преобразуем row -> dict
                columns = [desc[0] for desc in cur.description]
                return dict(zip(columns, row))
    return None

def create_user(telegram_id: int, username: str = None):
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (telegram_id, username, created_at)
                VALUES (%s, %s, NOW())
                RETURNING id, telegram_id
            """, (telegram_id, username))
            row = cur.fetchone()
            conn.commit()
            columns = [desc[0] for desc in cur.description]
            return dict(zip(columns, row))

def update_trial_info(user_id: int, trial_days: int):
    # trial_end = now + trial_days
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET trial_start = NOW(),
                    trial_end = NOW() + interval '%s day',
                    trial_used = TRUE
                WHERE id = %s
                RETURNING id, trial_end
            """, (trial_days, user_id))
            row = cur.fetchone()
            conn.commit()
            if row:
                columns = [desc[0] for desc in cur.description]
                return dict(zip(columns, row))
    return None

def update_deposit_address(user_id: int, address: str):
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET deposit_address = %s,
                    deposit_created_at = NOW()
                WHERE id = %s
            """, (address, user_id))
            conn.commit()

def reset_deposit_address(user_id: int):
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET deposit_address = NULL,
                    deposit_created_at = NULL
                WHERE id = %s
            """, (user_id,))
            conn.commit()

# Пример: выбор пользователей, у кого trial_end < now() и subscription_end < now()
def get_users_for_trial_expiration():
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT *
                FROM users
                WHERE trial_end IS NOT NULL
                  AND trial_end < NOW()
                  AND (subscription_end IS NULL OR subscription_end < NOW())
            """)
            rows = cur.fetchall()
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, r)) for r in rows]

def get_users_for_subscription_expiration():
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT *
                FROM users
                WHERE subscription_end IS NOT NULL
                  AND subscription_end < NOW()
            """)
            rows = cur.fetchall()
            columns = [desc[0] for desc in cur.description]
            return [dict(zip(columns, r)) for r in rows]

def get_admin_report_data():
    """
    Возвращает словарь с ключами:
      active_subscribers
      total_users
      month_sum
      year_sum
      all_time_sum
      subscribed_24h
      unsubscribed_24h
      sum_24h
    (упрощённый вариант, нужно доработать SQL)
    """
    data = {
        "active_subscribers": 0,
        "total_users": 0,
        "month_sum": 0,
        "year_sum": 0,
        "all_time_sum": 0,
        "subscribed_24h": 0,
        "unsubscribed_24h": 0,
        "sum_24h": 0
    }
    # Примерное заполнение
    with _get_connection() as conn:
        with conn.cursor() as cur:
            # Активных подписчиков
            cur.execute("""
                SELECT COUNT(*) FROM users
                WHERE subscription_end > NOW()
            """)
            data["active_subscribers"] = cur.fetchone()[0]

            # Всего пользователей
            cur.execute("SELECT COUNT(*) FROM users")
            data["total_users"] = cur.fetchone()[0]

            # За месяц
            cur.execute("""
                SELECT COALESCE(SUM(amount_usdt), 0)
                FROM payments
                WHERE paid_at >= date_trunc('month', NOW())
            """)
            data["month_sum"] = float(cur.fetchone()[0] or 0)

            # За год
            cur.execute("""
                SELECT COALESCE(SUM(amount_usdt), 0)
                FROM payments
                WHERE paid_at >= date_trunc('year', NOW())
            """)
            data["year_sum"] = float(cur.fetchone()[0] or 0)

            # За все время
            cur.execute("""
                SELECT COALESCE(SUM(amount_usdt), 0)
                FROM payments
            """)
            data["all_time_sum"] = float(cur.fetchone()[0] or 0)

            # За последние сутки
            cur.execute("""
                SELECT COALESCE(COUNT(*), 0)
                FROM payments
                WHERE paid_at >= NOW() - interval '1 day'
            """)
            data["subscribed_24h"] = cur.fetchone()[0]

            cur.execute("""
                SELECT COALESCE(SUM(amount_usdt), 0)
                FROM payments
                WHERE paid_at >= NOW() - interval '1 day'
            """)
            data["sum_24h"] = float(cur.fetchone()[0] or 0)

            # Потерявших подписку за сутки (упростим: считаем кол-во, у кого subscription_end
            # оказался в этом промежутке)
            cur.execute("""
                SELECT COUNT(*) 
                FROM users
                WHERE subscription_end >= (NOW() - interval '1 day')
                  AND subscription_end < NOW()
            """)
            data["unsubscribed_24h"] = cur.fetchone()[0]

    return data
