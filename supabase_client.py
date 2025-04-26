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
    """Проверяем, что таблицы users/payments существуют."""
    for table in ["users", "payments"]:
        try:
            with _get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT 1 FROM {table} LIMIT 1;")
            log.info(f"Таблица '{table}' доступна.")
        except psycopg2.Error as e:
            log.error(f"Ошибка проверки структуры БД для '{table}': {e}")

def get_user_by_telegram_id(telegram_id: int):
    """Вернёт словарь с полями пользователя или None."""
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE telegram_id=%s", (telegram_id,))
            row = cur.fetchone()
            if not row:
                return None
            cols = [desc[0] for desc in cur.description]
            return dict(zip(cols, row))

def create_user_with_trial(telegram_id: int, username: str, trial_days: int):
    """
    Создаем нового пользователя, выставляем trial_end = now + trial_days
    Возвращаем словарь с данными пользователя.
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (telegram_id, username, trial_end, created_at)
                VALUES (%s, %s, (NOW() + interval '%s day'), NOW())
                RETURNING *
            """, (telegram_id, username, trial_days))
            row = cur.fetchone()
            conn.commit()

            cols = [desc[0] for desc in cur.description]
            return dict(zip(cols, row))

def update_trial_end(user_id: int, new_end):
    """
    Примерная функция, если нужно как-то обновлять trial_end
    """
    with _get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                   SET trial_end = %s
                 WHERE id = %s
                 RETURNING *
            """, (new_end, user_id))
            row = cur.fetchone()
            conn.commit()
            if row:
                cols = [desc[0] for desc in cur.description]
                return dict(zip(cols, row))
    return None