from aiogram import Router, types
import logging

subscription_router = Router()
log = logging.getLogger(__name__)

@subscription_router.message(lambda msg: msg.text == "Статус подписки")
async def status_sub(message: types.Message):
    """Пользователь нажал кнопку «Статус подписки» (ReplyKeyboard)."""
    log.info(f"User {message.from_user.id} clicked 'Статус подписки'")
    # Тут ваша логика: проверить subscription_end, trial_end и т.д.
    await message.answer("Ваша подписка: ... (здесь выведите реальный статус)")

@subscription_router.message(lambda msg: msg.text == "Оформить подписку")
async def subscribe_sub(message: types.Message):
    """Пользователь нажал «Оформить подписку»."""
    log.info(f"User {message.from_user.id} clicked 'Оформить подписку'")
    # Тут логика оформления подписки
    # например, генерируем уникальный адрес Tron, шлём инструкцию.
    await message.answer("Оформляем подписку... (заглушка)")