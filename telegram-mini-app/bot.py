import asyncio
from aiogram import Bot, Dispatcher
from aiogram.types import Message, KeyboardButton, ReplyKeyboardMarkup, WebAppInfo
from config import BOT_TOKEN


bot = Bot(BOT_TOKEN)

dp = Dispatcher()


@dp.message(commands=["start"])
async def start(message: Message):

    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [
                KeyboardButton(
                    text="🚀 Открыть приложение",
                    web_app=WebAppInfo(
                        url="https://Acmes.com"
                    )
                )
            ]
        ],
        resize_keyboard=True
    )

    await message.answer(
        "Открывай Mini App:",
        reply_markup=keyboard
    )


async def main():

    print("Mini App Bot started")

    await dp.start_polling(bot)


if __name__=="__main__":
    asyncio.run(main())
