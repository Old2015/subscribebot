#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# main.py

import asyncio
from aiogram import executor
from config import dp
import logging

# Импортируем файл, чтобы логгеры были сконфигурированы до начала работы
import logger_config  # <-- вызывает настройку логирования
from supabase_client import check_db_structure

async def on_startup(_):
    logging.info("Bot is starting...")
    # Проверяем базу
    check_db_structure()
    logging.info("DB structure check is done.")
    print("Bot is online.")

def main():
    from subscription import register_handlers as reg_sub
    from start import register_handlers as reg_start
    # и т.д. или как у вас

    # Регистрируем хендлеры
    reg_start(dp)
    reg_sub(dp)
    
    # Запуск поллинга
    executor.start_polling(dp, skip_updates=True, on_startup=on_startup)

if __name__ == "__main__":
    main()