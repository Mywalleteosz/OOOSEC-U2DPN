from aiogram import Router
from aiogram.types import Message

router = Router()


@router.message(commands=["start"])
async def start_command(message: Message):
    await message.answer(
        "👋 Привет!\n\n"
        "Я простой Telegram-бот.\n"
        "Команды:\n"
        "/start - запуск\n"
        "/help - помощь"
    )


@router.message(commands=["help"])
async def help_command(message: Message):
    await message.answer(
        "ℹ️ Помощь:\n"
        "Напиши мне любое сообщение."
    )
