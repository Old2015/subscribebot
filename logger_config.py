# logger_config.py

import logging
import sys

# Создаем форматтер, который будет использоваться во всех хендлерах
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
formatter = logging.Formatter(LOG_FORMAT)

# Создаем логгер (можно взять корневой: logging.getLogger())
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)  # Уровень DEBUG для корневого логгера

# 1) subscribefull.log (записываем ВСЁ, включая DEBUG)
full_handler = logging.FileHandler("subscribefull.log", mode='a', encoding='utf-8')
full_handler.setLevel(logging.DEBUG)
full_handler.setFormatter(formatter)
logger.addHandler(full_handler)

# 2) subscribe.log (записываем «основные» логи – с INFO и выше)
main_handler = logging.FileHandler("subscribe.log", mode='a', encoding='utf-8')
main_handler.setLevel(logging.INFO)
main_handler.setFormatter(formatter)
logger.addHandler(main_handler)

# 3) вывод в консоль (тоже INFO и выше)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Таким образом, все логи уровня DEBUG пойдут в subscribefull.log,
# а логи уровня INFO и выше пойдут в subscribe.log и в консоль.

# Чтобы в других модулях просто использовать:
# import logging
# log = logging.getLogger(__name__)
# log.debug("debug message")
# log.info("info message")
# etc.
