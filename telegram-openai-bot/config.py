import os
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = (os.getenv("BOT_TOKEN") or "").strip()
OPENAI_API_KEY = (os.getenv("OPENAI_API_KEY") or "").strip()

_id_part, _, _secret_part = BOT_TOKEN.partition(":")
_token_shape_ok = bool(_id_part.isdigit() and _secret_part)

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing")

if not _token_shape_ok:
    raise RuntimeError("BOT_TOKEN is invalid")

if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY is missing")
