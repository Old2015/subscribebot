from aiogram import Router, types
from aiogram.filters import Command
import logging

# Если нужно, импортируем supabase_client, config и т.д., в зависимости от логики
# import config
# import supabase_client

# Создаём роутер
start_router = Router()
log = logging.getLogger(__name__)

# Создаем "Reply-клавиатуру" c двумя кнопками
# "Статус подписки" и "Оформить подписку"
main_menu = types.ReplyKeyboardMarkup(
    keyboard=[
        [
            types.KeyboardButton(text="Статус подписки"),
            types.KeyboardButton(text="Оформить подписку"),
        ]
    ],
    resize_keyboard=True  # чтобы кнопки не были громоздкими
)

@start_router.message(Command("start"))
async def cmd_start(message: types.Message):
    """
    Хендлер на команду /start:
    1. Приветствие
    2. Отправляем ReplyKeyboard
    """
    log.info(f"/start from user {message.from_user.id}")

    # Можно создать/проверить пользователя в БД, дать триал и т.д.
    # ...

    await message.answer(
        text="Добро пожаловать в приватную торговую группу !\nВ режиме реального времени публикуется каждая сделка профессионального трейдера Анонимуса: лимитные и маркет‑ордера, установка и снятие стопов, частичное и полное закрытие позиций.\nСигналы приходят в группу через API спустя доли секунды после исполнения трейдером. \nСтиль торговли — консервативный, с акцентом на строгий риск‑менеджмент. \nЛичность трейдера и участников не раскрывается - это основа безопасности и стабильности канала. \n\nГарантии ? \nВсе просто: пока трейдер жив и сохраняет анонимность, группа продолжит работать и приносить пользу участникам. \n\n\nВам предоставлен тестовый доступ в торговую группу три дня.\nПо истечению тестового периода Вы можете оформить подписку, стоимость 100USDT в месяц.\n",
        reply_markup=main_menu  # отправляем клавиатуру
    )