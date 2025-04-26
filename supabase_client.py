# supabase_client.py

import psycopg2
import logging
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
    """Проверяем, что таблицы users и payments существуют"""
    for table in ["users", "payments"]:
        try:
            with _get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT 1 FROM {table} LIMIT 1;")
            log.info(f"Таблица '{table}' доступна.")
        except psycopg2.Error as e:
            log.error(f"Ошибка проверки структуры БД для таблицы '{table}': {e}")

# Остальные методы (create_user, update_trial_info, insert_payment, и т.д.)...