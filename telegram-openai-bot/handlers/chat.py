from aiogram import Router
from aiogram.types import Message

from services.openai import ask_gpt


router = Router()


@router.message()
async def chat_handler(message: Message):

    if not message.text:
        return

    await message.answer("⏳ Обрабатываю...")


    answer = await ask_gpt(
        message.text
    )


    await message.answer(answer)
