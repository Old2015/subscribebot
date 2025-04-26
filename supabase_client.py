import psycopg2
import os
from datetime import datetime

# Берём настройки из config.py (но можно напрямую из env)
import config

def _get_connection():
    return psycopg2.connect(
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        host=config.DB_HOST,
        port=config.DB_PORT,
        database=config.DB_NAME
    )

def create_user(telegram_id: int, username: str = None):
    """
    Создаем запись пользователя (с trial_start, trial_end, subscription_end = NULL, ...)
    Если хотим сразу записать начало триала, то делаем в другом методе.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (telegram_id, username, created_at)
                VALUES (%s, %s, NOW())
                RETURNING id, telegram_id
            """, (telegram_id, username))
            row = cur.fetchone()
            conn.commit()
            return row  # (id, telegram_id)

def get_user_by_telegram_id(telegram_id: int):
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE telegram_id=%s", (telegram_id,))
            row = cur.fetchone()
            if row:
                cols = [desc[0] for desc in cur.description]
                return dict(zip(cols, row))
    return None

def update_trial_info(user_id: int, days:int):
    """ Устанавливаем trial_start=NOW, trial_end=NOW+days, trial_used=TRUE """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                   SET trial_start = NOW(),
                       trial_end = NOW() + interval '%s day',
                       trial_used = TRUE
                 WHERE id = %s
                 RETURNING id, trial_end
            """, (days, user_id))
            row = cur.fetchone()
            conn.commit()
            if row:
                cols = [desc[0] for desc in cur.description]
                return dict(zip(cols, row))
    return None

def set_deposit_address(user_id: int, address: str):
    """ Сохраняем пользователю deposit_address, deposit_created_at=NOW() """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET deposit_address=%s,
                    deposit_created_at=NOW()
                WHERE id=%s
            """, (address, user_id))
            conn.commit()

def reset_deposit_address(user_id: int):
    """ Обнуляем deposit_address (если нет оплаты за 24ч) """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET deposit_address=NULL,
                    deposit_created_at=NULL
                WHERE id=%s
            """, (user_id,))
            conn.commit()

# Пример вставки записи в payments
def insert_payment(user_id:int, txhash:str, amount:float, days_added:int):
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO payments (user_id, txhash, amount_usdt, days_added, paid_at)
                VALUES (%s, %s, %s, %s, NOW())
            """, (user_id, txhash, amount, days_added))
            conn.commit()

def extend_subscription(user_id: int, days: int):
    """
    Продлеваем подписку на N дней.
    subscription_end = GREATEST(subscription_end, NOW()) + N дней
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET subscription_end = 
                    CASE
                        WHEN subscription_end > NOW() THEN subscription_end + interval '%s day'
                        ELSE NOW() + interval '%s day'
                    END
                WHERE id=%s
                RETURNING subscription_end
            """, (days, days, user_id))
            row = cur.fetchone()
            conn.commit()
            if row:
                return row[0]
    return None

def get_users_for_trial_expiration():
    """
    Выбираем пользователей, у кого trial_end < NOW() И (subscription_end IS NULL OR < NOW()).
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM users
                 WHERE trial_end < NOW()
                   AND (subscription_end IS NULL OR subscription_end < NOW())
                   AND trial_used = TRUE
            """)
            rows = cur.fetchall()
            cols = [desc[0] for desc in cur.description]
            return [dict(zip(cols, r)) for r in rows]

def get_users_for_subscription_expiration():
    """
    Выбираем пользователей, у кого subscription_end < NOW() (и не NULL).
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM users
                WHERE subscription_end IS NOT NULL
                  AND subscription_end < NOW()
            """)
            rows = cur.fetchall()
            cols = [desc[0] for desc in cur.description]
            return [dict(zip(cols, r)) for r in rows]

def get_admin_report_data():
    """
    Собираем статистику, в т.ч. кол-во активных подписчиков, суммы платежей и т.д.
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

    with _get_connection() as conn:
        with conn.cursor() as cur:
            # Активные (subscription_end > NOW)
            cur.execute("""
                SELECT COUNT(*) FROM users
                WHERE subscription_end > NOW()
            """)
            data["active_subscribers"] = cur.fetchone()[0]

            # Всего
            cur.execute("SELECT COUNT(*) FROM users")
            data["total_users"] = cur.fetchone()[0]

            # Сумма за месяц
            cur.execute("""
                SELECT COALESCE(SUM(amount_usdt), 0)
                FROM payments
                WHERE paid_at >= date_trunc('month', NOW())
            """)
            data["month_sum"] = float(cur.fetchone()[0] or 0)

            # Сумма за год
            cur.execute("""
                SELECT COALESCE(SUM(amount_usdt), 0)
                FROM payments
                WHERE paid_at >= date_trunc('year', NOW())
            """)
            data["year_sum"] = float(cur.fetchone()[0] or 0)

            # Сумма за все время
            cur.execute("""SELECT COALESCE(SUM(amount_usdt), 0) FROM payments""")
            data["all_time_sum"] = float(cur.fetchone()[0] or 0)

            # Кол-во подписок за сутки
            cur.execute("""
                SELECT COUNT(*) 
                FROM payments
                WHERE paid_at >= NOW() - interval '1 day'
            """)
            data["subscribed_24h"] = cur.fetchone()[0]

            # Сумма за сутки
            cur.execute("""
                SELECT COALESCE(SUM(amount_usdt), 0)
                FROM payments
                WHERE paid_at >= NOW() - interval '1 day'
            """)
            data["sum_24h"] = float(cur.fetchone()[0] or 0)

            # Потерявших подписку за сутки (упрощенно)
            cur.execute("""
                SELECT COUNT(*) 
                FROM users
                WHERE subscription_end >= (NOW() - interval '1 day')
                  AND subscription_end < NOW()
            """)
            data["unsubscribed_24h"] = cur.fetchone()[0]

    return data
