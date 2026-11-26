import os
import asyncio

from aiogram import Bot, Dispatcher
from aiogram.client.session.aiohttp import AiohttpSession

from config import BOT_TOKEN

from handlers.start import router as start_router
from handlers.chat import router as chat_router


async def main():
    proxy = (os.getenv("PROXY_URL") or "").strip() or None
    session = AiohttpSession(proxy=proxy) if proxy else AiohttpSession()
    bot = Bot(token=BOT_TOKEN, session=session)

    dp = Dispatcher()
    dp.include_router(start_router)
    dp.include_router(chat_router)

    print("🚀 Telegram OpenAI Bot started", flush=True)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
