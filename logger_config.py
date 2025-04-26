# logger_config.py

import logging
import sys

LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'

def setup_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Ловим все логи

    formatter = logging.Formatter(LOG_FORMAT)

    # 1) Файл для ВСЕХ логов
    fh_full = logging.FileHandler("subscribefull.log", mode='a', encoding='utf-8')
    fh_full.setLevel(logging.DEBUG)
    fh_full.setFormatter(formatter)
    logger.addHandler(fh_full)

    # 2) Файл для основных логов (INFO+)
    fh_main = logging.FileHandler("subscribe.log", mode='a', encoding='utf-8')
    fh_main.setLevel(logging.INFO)
    fh_main.setFormatter(formatter)
    logger.addHandler(fh_main)

    # 3) Консоль (тоже INFO+)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logging.debug("Logger set up: DEBUG to subscribefull.log, INFO+ to subscribe.log & console.")