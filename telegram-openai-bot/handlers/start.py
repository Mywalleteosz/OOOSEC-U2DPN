from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from ui.menu import main_menu_keyboard

router = Router(name="security-desk-start")

WELCOME_TEXT = (
    "🛡️ <b>LI0Tb SECURITY DESK</b>\n"
    "<i>Security • Automation • Intelligence</i>\n\n"
    "Твоя панель управления безопасностью.\n"
    "Выбери нужный раздел в меню ниже."
)


@router.message(Command("start", "menu"))
async def start_handler(message: Message) -> None:
    await message.answer(
        WELCOME_TEXT,
        reply_markup=main_menu_keyboard(),
        parse_mode="HTML",
    )


@router.message(Command("help"))
async def help_handler(message: Message) -> None:
    await message.answer(
        "❔ <b>LI0Tb Security Desk</b>\n\n"
        "/start или /menu — открыть панель\n"
        "/help — показать эту справку\n\n"
        "Для общения с AI Analyst отправь обычное текстовое сообщение. "
        "Не отправляй секреты, пароли и приватные ключи.",
        reply_markup=main_menu_keyboard(),
        parse_mode="HTML",
    )
