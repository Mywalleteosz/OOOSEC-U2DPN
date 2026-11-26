import asyncio
import os

from aiogram import Bot, Dispatcher
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.types import BotCommand

from config import BOT_TOKEN
from handlers.dashboard import router as dashboard_router
from handlers.start import router as start_router
from handlers.chat import router as chat_router


async def main():
    proxy = (os.getenv("PROXY_URL") or "").strip() or None
    session = AiohttpSession(proxy=proxy) if proxy else AiohttpSession()
    bot = Bot(token=BOT_TOKEN, session=session)

    dp = Dispatcher()
    dp.include_router(start_router)
    dp.include_router(dashboard_router)
    dp.include_router(chat_router)

    await bot.set_my_commands(
        [
            BotCommand(command="start", description="Открыть Security Desk"),
            BotCommand(command="menu", description="Главное меню"),
            BotCommand(command="help", description="Помощь"),
        ]
    )

    print("🛡️ LI0Tb Security Desk started", flush=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
