import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = (os.getenv("BOT_TOKEN") or "").strip()
OPENAI_API_KEY = (os.getenv("OPENAI_API_KEY") or "").strip()

# #region agent log
def _agent_log(message, data, hypothesis_id):
    import json, time
    payload = {
        "sessionId": "3335ff",
        "runId": "p0p1",
        "hypothesisId": hypothesis_id,
        "location": "telegram-openai-bot/config.py",
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

_id_part, _, _secret_part = BOT_TOKEN.partition(":")
_token_shape_ok = bool(_id_part.isdigit() and _secret_part)

# #region agent log
_agent_log(
    "env loaded",
    {
        "token_set": bool(BOT_TOKEN),
        "token_len": len(BOT_TOKEN),
        "has_colon": ":" in BOT_TOKEN,
        "token_shape_ok": _token_shape_ok,
        "openai_set": bool(OPENAI_API_KEY),
        "openai_len": len(OPENAI_API_KEY),
    },
    "A",
)
# #endregion

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing")

if not _token_shape_ok:
    raise RuntimeError("BOT_TOKEN is invalid")

if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY is missing")
