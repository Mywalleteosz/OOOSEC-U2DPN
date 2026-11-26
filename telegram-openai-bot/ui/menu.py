from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


def main_menu_keyboard() -> InlineKeyboardMarkup:
    """Build the main Security Desk navigation."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="🔎 Сканирование", callback_data="desk:scan"),
                InlineKeyboardButton(text="🌐 URL / IP", callback_data="desk:intel"),
            ],
            [
                InlineKeyboardButton(text="🐧 Linux аудит", callback_data="desk:linux"),
                InlineKeyboardButton(text="🤖 AI Analyst", callback_data="desk:ai"),
            ],
            [
                InlineKeyboardButton(text="📊 Состояние", callback_data="desk:status"),
                InlineKeyboardButton(text="❔ Помощь", callback_data="desk:help"),
            ],
        ]
    )


def back_to_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="⬅️ Главное меню", callback_data="desk:home")]
        ]
    )
