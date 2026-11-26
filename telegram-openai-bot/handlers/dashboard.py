from aiogram import F, Router
from aiogram.types import CallbackQuery

from ui.menu import back_to_menu_keyboard, main_menu_keyboard

router = Router(name="security-desk-dashboard")

HOME_TEXT = (
    "🛡️ <b>LI0Tb SECURITY DESK</b>\n"
    "<i>Security • Automation • Intelligence</i>\n\n"
    "Выбери модуль. На этом этапе готов интерфейс; "
    "подключение сканеров и Security Core выполняется отдельно."
)


@router.callback_query(F.data == "desk:home")
async def show_home(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.message:
        await callback.message.edit_text(
            HOME_TEXT,
            reply_markup=main_menu_keyboard(),
            parse_mode="HTML",
        )


@router.callback_query(F.data == "desk:scan")
async def show_scan(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.message:
        await callback.message.edit_text(
            "🔎 <b>Scanner Engine</b>\n\n"
            "Модуль сканирования будет подключён через Security Core. "
            "Произвольное выполнение команд и запуск Docker из Telegram не предусмотрены.\n\n"
            "Сейчас доступен только интерфейс.",
            reply_markup=back_to_menu_keyboard(),
            parse_mode="HTML",
        )


@router.callback_query(F.data == "desk:intel")
async def show_intel(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.message:
        await callback.message.edit_text(
            "🌐 <b>URL / IP Intelligence</b>\n\n"
            "Здесь появится проверка доменов, IP и ссылок по подключённым источникам. "
            "Ввод адресов пока не запускает внешние запросы.",
            reply_markup=back_to_menu_keyboard(),
            parse_mode="HTML",
        )


@router.callback_query(F.data == "desk:linux")
async def show_linux(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.message:
        await callback.message.edit_text(
            "🐧 <b>Linux Audit</b>\n\n"
            "Планируется read-only аудит: версия ОС, обновления, открытые порты "
            "и базовые настройки защиты. Удалённые shell-команды не выполняются.",
            reply_markup=back_to_menu_keyboard(),
            parse_mode="HTML",
        )


@router.callback_query(F.data == "desk:ai")
async def show_ai(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.message:
        await callback.message.edit_text(
            "🤖 <b>AI Analyst</b>\n\n"
            "Отправь следующим сообщением вопрос или описание инцидента — "
            "текущий GPT-чат обработает его. Не отправляй пароли, токены и приватные ключи.",
            reply_markup=back_to_menu_keyboard(),
            parse_mode="HTML",
        )


@router.callback_query(F.data == "desk:status")
async def show_status(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.message:
        await callback.message.edit_text(
            "📊 <b>Состояние панели</b>\n\n"
            "• Telegram UI: активен\n"
            "• AI-чат: использует существующий обработчик\n"
            "• Security Core API: ещё не подключён к боту\n"
            "• Scanner Worker: не запускается из Telegram\n\n"
            "Статус показывает готовность интерфейса, а не проверку серверной инфраструктуры.",
            reply_markup=back_to_menu_keyboard(),
            parse_mode="HTML",
        )


@router.callback_query(F.data == "desk:help")
async def show_help(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.message:
        await callback.message.edit_text(
            "❔ <b>Как пользоваться</b>\n\n"
            "/start или /menu — открыть панель\n"
            "/help — справка\n\n"
            "Сканирование, URL/IP и Linux Audit пока представлены как безопасные "
            "интерфейсные разделы. Реальные действия появятся после подключения API "
            "и проверки прав доступа.",
            reply_markup=back_to_menu_keyboard(),
            parse_mode="HTML",
        )
