import os
import asyncio

from aiogram import Bot, Dispatcher
from aiogram.client.session.aiohttp import AiohttpSession

from config import BOT_TOKEN

from handlers.start import router as start_router
from handlers.chat import router as chat_router


# #region agent log
def _agent_log(message, data, hypothesis_id):
    import json, time
    payload = {
        "sessionId": "3335ff",
        "runId": "p0p1",
        "hypothesisId": hypothesis_id,
        "location": "telegram-openai-bot/bot.py",
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    line = json.dumps(payload) + "\n"
    for path in (
        "/home/telo/.cursor/debug-3335ff.log",
        "/host-cursor/debug-3335ff.log",
        "/tmp/debug-3335ff.log",
    ):
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
            break
        except OSError:
            continue
# #endregion


async def main():

    proxy = (os.getenv("PROXY_URL") or "").strip() or None
    # #region agent log
    from urllib.parse import urlparse
    parsed = urlparse(proxy) if proxy else None
    _agent_log(
        "proxy config",
        {
            "proxy_set": bool(proxy),
            "scheme": parsed.scheme if parsed else None,
            "loopback": (parsed.hostname in ("127.0.0.1", "localhost", "::1")) if parsed else False,
            "port": parsed.port if parsed else None,
        },
        "E",
    )
    # #endregion

    try:
        session = AiohttpSession(proxy=proxy) if proxy else AiohttpSession()
    except Exception as exc:
        # #region agent log
        _agent_log("session failed", {"error_type": type(exc).__name__}, "G")
        # #endregion
        raise

    try:
        bot = Bot(
            token=BOT_TOKEN,
            session=session
        )
    except Exception as exc:
        # #region agent log
        _agent_log(
            "bot construct failed",
            {"error_type": type(exc).__name__},
            "A",
        )
        # #endregion
        raise

    # #region agent log
    _agent_log(
        "bot constructed",
        {"proxy_set": bool(proxy)},
        "B",
    )
    # #endregion

    dp = Dispatcher()

    dp.include_router(start_router)
    dp.include_router(chat_router)

    print("🚀 Telegram OpenAI Bot started", flush=True)

    # #region agent log
    _agent_log("polling starting", {"routers": ["start", "chat"]}, "B")
    import time as _time
    t0 = _time.time()
    try:
        me = await bot.get_me()
        _agent_log(
            "get_me ok",
            {"ms": int((_time.time() - t0) * 1000), "is_bot": bool(me.is_bot)},
            "C",
        )
    except Exception as exc:
        _agent_log(
            "get_me failed",
            {"error_type": type(exc).__name__, "ms": int((_time.time() - t0) * 1000)},
            "C",
        )
        raise
    # #endregion

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
