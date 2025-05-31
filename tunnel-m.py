import asyncio
import sqlite3
import paramiko
import re
import uuid
from aiogram import Bot, Dispatcher, types
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.utils.markdown import escape_md
from config import API_TOKEN, ADMIN_ID, ALLOWED_USER_IDS

storage = MemoryStorage()
bot = Bot(token=API_TOKEN)
dp = Dispatcher(bot, storage=storage)

def init_db():
    conn = sqlite3.connect('tunnels.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS tunnels (
            tunnel_id TEXT PRIMARY KEY,
            tunnel_name TEXT,
            user_id INTEGER,
            iran_server_ip TEXT,
            iran_username TEXT,
            iran_password TEXT,
            kharej_server_ip TEXT,
            kharej_username TEXT,
            kharej_password TEXT,
            iran_ip TEXT,
            kharej_ip TEXT,
            iran_ipv6 TEXT,
            kharej_ipv6 TEXT,
            psk TEXT,
            mtu_6to4 TEXT,
            mtu_gre TEXT,
            crontab_hour TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class ServerConfig(StatesGroup):
    MainMenu = State()
    TunnelMenu = State()
    TunnelName = State()
    IranServerIP = State()
    IranUsername = State()
    IranPassword = State()
    KharejServerIP = State()
    KharejUsername = State()
    KharejPassword = State()
    IranIP = State()
    KharejIP = State()
    PSK = State()
    MTU_6to4 = State()
    MTU_GRE = State()
    CrontabHour = State()
    SelectTunnel = State()
    DeleteTunnel = State()

def get_main_menu_keyboard():
    keyboard = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    keyboard.add(KeyboardButton("🚀 ساخت تونل جدید"))
    keyboard.add(KeyboardButton("📊 بررسی وضعیت تونل‌ها"))
    keyboard.add(KeyboardButton("🗑 حذف تونل"))
    return keyboard

def get_tunnel_menu_keyboard():
    keyboard = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
    keyboard.add(KeyboardButton("🔗 تونل 1 ایران به 1 خارج"))
    keyboard.add(KeyboardButton("⬅️ بازگشت به منوی اصلی"))
    return keyboard

def get_back_buttons():
    keyboard = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    keyboard.add(KeyboardButton("⬅️ بازگشت به مرحله قبل"), KeyboardButton("🏠 بازگشت به منوی اصلی"))
    return keyboard

def get_mtu_6to4_selection_keyboard():
    keyboard = InlineKeyboardMarkup(row_width=1)
    keyboard.add(InlineKeyboardButton("📏 پیش‌فرض (1480)", callback_data="mtu_6to4_default"))
    keyboard.add(InlineKeyboardButton("✍️ وارد کردن دستی", callback_data="mtu_6to4_manual"))
    keyboard.add(InlineKeyboardButton("⬅️ بازگشت به مرحله قبل", callback_data="back_to_psk"))
    keyboard.add(InlineKeyboardButton("🏠 بازگشت به منوی اصلی", callback_data="back_to_main"))
    return keyboard

def get_mtu_gre_selection_keyboard():
    keyboard = InlineKeyboardMarkup(row_width=1)
    keyboard.add(InlineKeyboardButton("📏 پیش‌فرض (1424)", callback_data="mtu_gre_default"))
    keyboard.add(InlineKeyboardButton("✍️ وارد کردن دستی", callback_data="mtu_gre_manual"))
    keyboard.add(InlineKeyboardButton("⬅️ بازگشت به مرحله قبل", callback_data="back_to_mtu_6to4"))
    keyboard.add(InlineKeyboardButton("🏠 بازگشت به منوی اصلی", callback_data="back_to_main"))
    return keyboard

def is_valid_crontab_hour(hour):
    try:
        hour = int(hour)
        return 0 <= hour <= 23
    except ValueError:
        return False

def is_valid_ip(ip):
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))

def is_valid_ipv6(ip):
    pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$|^2002:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$'
    return bool(re.match(pattern, ip))

def check_user_access(user_id):
    if user_id == ADMIN_ID:
        return 'admin'
    if user_id in ALLOWED_USER_IDS:
        return 'user'
    return None

async def ping_ssh(host, username, password, target_ip, message, operation="بررسی وضعیت"):
    try:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md(f"⏳ {operation} برای {host} به {target_ip}..."),
            parse_mode="MarkdownV2"
        )
        # بررسی ماژول ip6gre
        module_check = await execute_ssh_command(host, username, password, "lsmod | grep ip6gre")
        print(f"ماژول ip6gre در {host}: {module_check}")
        if not module_check.strip():
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md(f"⚠️ ماژول ip6gre در {host} لود نشده است: {module_check}"),
                parse_mode="MarkdownV2"
            )
            return {"status": "error", "rtt": "N/A", "error": "ماژول ip6gre لود نشده است"}

        # بررسی رابط GRE
        interface = "GRE6Tun_To_IR" if target_ip == "172.20.40.2" else "GRE6Tun_To_KH"
        ip_check = await execute_ssh_command(host, username, password, f"ip addr show {interface} | grep {target_ip}")
        print(f"چک IP در {host} برای {target_ip}: {ip_check}")
        if not ip_check.strip():
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md(f"⚠️ آدرس {target_ip} روی رابط {interface} در {host} تنظیم نشده: {ip_check}"),
                parse_mode="MarkdownV2"
            )
            return {"status": "error", "rtt": "N/A", "error": f"آدرس {target_ip} روی رابط {interface} تنظیم نشده است"}

        # اجرای پینگ
        command = f"ping -c 4 {target_ip}"
        output = await execute_ssh_command(host, username, password, command)
        print(f"خروجی پینگ در {host} به {target_ip}: {output}")
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md(f"📋 خروجی پینگ از {host} به {target_ip}: {output}"),
            parse_mode="MarkdownV2"
        )
        if not output:
            return {"status": "error", "rtt": "N/A", "error": "هیچ خروجی از پینگ دریافت نشد"}

        packet_loss = re.search(r'(\d+)% packet loss', output)
        if packet_loss and int(packet_loss.group(1)) == 0:
            rtt_match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms', output)
            rtt = rtt_match.group(1) if rtt_match else "N/A"
            return {"status": "connected", "rtt": rtt}
        else:
            return {"status": "disconnected", "rtt": "N/A", "error": f"پکت‌ها از دست رفتند: {output}"}
    except Exception as e:
        error_msg = f"خطا در پینگ از {host} به {target_ip}: {str(e)}"
        print(error_msg)
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md(f"❌ {error_msg}"),
            parse_mode="MarkdownV2"
        )
        return {"status": "error", "rtt": "N/A", "error": str(e)}

@dp.message_handler(commands=['start'])
async def start_command(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    role = check_user_access(user_id)
    if not role:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ متأسفیم، شما دسترسی استفاده از این ربات را ندارید. لطفاً با مدیر تماس بگیرید."),
            parse_mode="MarkdownV2"
        )
        return
    
    welcome_msg = (
        escape_md("🌟 خوش اومدی به ربات مدیریت تونل اوارا 🌟\n\n") +
        escape_md(f"شما به‌عنوان {'مدیر' if role == 'admin' else 'کاربر'} وارد شده‌اید.\n") +
        escape_md("برای اطلاع از به‌روزرسانی‌های ربات و حمایت از ما، وارد کانال ما شوید.\n") +
        escape_md("📚 برای اطلاع از به‌روزرسانی‌های ربات و حمایت از ما وارد کانال ما شوید: ") +
        "@evara_tu"
    )
    try:
        await bot.send_message(
            chat_id=message.chat.id,
            text=welcome_msg,
            reply_markup=get_main_menu_keyboard(),
            parse_mode="MarkdownV2"
        )
    except Exception as e:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md(f"❌ خطایی رخ داد: {str(e)}. لطفاً دوباره تلاش کنید."),
            reply_markup=get_main_menu_keyboard(),
            parse_mode="MarkdownV2"
        )
    await ServerConfig.MainMenu.set()

@dp.message_handler(state=ServerConfig.MainMenu)
async def main_menu(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    role = check_user_access(user_id)
    if not role:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ دسترسی غیرمجاز! لطفاً دوباره وارد شوید."),
            parse_mode="MarkdownV2"
        )
        await state.finish()
        return

    if message.text == "🚀 ساخت تونل جدید":
        await state.update_data(tunnel_id=str(uuid.uuid4()), user_id=user_id)
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("✨ لطفاً یک نام برای تونل جدید وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.TunnelName.set()
    elif message.text == "📊 بررسی وضعیت تونل‌ها":
        conn = sqlite3.connect('tunnels.db')
        c = conn.cursor()
        if role == 'admin':
            c.execute('SELECT tunnel_id, tunnel_name, user_id FROM tunnels ORDER BY created_at DESC')
        else:
            c.execute('SELECT tunnel_id, tunnel_name, user_id FROM tunnels WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
        tunnels = c.fetchall()
        conn.close()
        
        if not tunnels:
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md("⚠️ هیچ تونلی یافت نشد!"),
                reply_markup=get_main_menu_keyboard(),
                parse_mode="MarkdownV2"
            )
            await ServerConfig.MainMenu.set()
        else:
            keyboard = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
            for tunnel in tunnels:
                tunnel_name = f"{tunnel[1]} (کاربر: {tunnel[2]})" if role == 'admin' else tunnel[1]
                keyboard.add(KeyboardButton(tunnel_name))
            keyboard.add(KeyboardButton("⬅️ بازگشت به منوی اصلی"))
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md("🔍 لطفاً تونل موردنظر را برای بررسی انتخاب کنید:"),
                reply_markup=keyboard,
                parse_mode="MarkdownV2"
            )
            await ServerConfig.SelectTunnel.set()
    elif message.text == "🗑 حذف تونل":
        conn = sqlite3.connect('tunnels.db')
        c = conn.cursor()
        if role == 'admin':
            c.execute('SELECT tunnel_id, tunnel_name, user_id FROM tunnels ORDER BY created_at DESC')
        else:
            c.execute('SELECT tunnel_id, tunnel_name, user_id FROM tunnels WHERE user_id = ? ORDER BY created_at DESC', (user_id,))
        tunnels = c.fetchall()
        conn.close()
        
        if not tunnels:
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md("⚠️ هیچ تونلی برای حذف یافت نشد!"),
                reply_markup=get_main_menu_keyboard(),
                parse_mode="MarkdownV2"
            )
            await ServerConfig.MainMenu.set()
        else:
            keyboard = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
            for tunnel in tunnels:
                tunnel_name = f"{tunnel[1]} (کاربر: {tunnel[2]})" if role == 'admin' else tunnel[1]
                keyboard.add(KeyboardButton(tunnel_name))
            keyboard.add(KeyboardButton("⬅️ بازگشت به منوی اصلی"))
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md("🗑 لطفاً تونل موردنظر را برای حذف انتخاب کنید:"),
                reply_markup=keyboard,
                parse_mode="MarkdownV2"
            )
            await ServerConfig.DeleteTunnel.set()
    else:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً گزینه‌ای معتبر انتخاب کنید!"),
            reply_markup=get_main_menu_keyboard(),
            parse_mode="MarkdownV2"
        )

@dp.message_handler(state=ServerConfig.SelectTunnel)
async def select_tunnel(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    role = check_user_access(user_id)
    if not role:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ دسترسی غیرمجاز!"),
            parse_mode="MarkdownV2"
        )
        await state.finish()
        return
    
    if message.text == "⬅️ بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    
    tunnel_name = message.text.split(" (کاربر:")[0]
    conn = sqlite3.connect('tunnels.db')
    c = conn.cursor()
    if role == 'admin':
        c.execute('SELECT tunnel_id, iran_server_ip, iran_username, iran_password, kharej_server_ip, kharej_username, kharej_password, iran_ipv6, kharej_ipv6, user_id FROM tunnels WHERE tunnel_name = ?', (tunnel_name,))
    else:
        c.execute('SELECT tunnel_id, iran_server_ip, iran_username, iran_password, kharej_server_ip, kharej_username, kharej_password, iran_ipv6, kharej_ipv6, user_id FROM tunnels WHERE tunnel_name = ? AND user_id = ?', (tunnel_name, user_id))
    tunnel = c.fetchone()
    conn.close()
    
    if not tunnel:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("⚠️ تونل با این نام یافت نشد یا متعلق به شما نیست!"),
            reply_markup=get_main_menu_keyboard(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.MainMenu.set()
        return
    
    tunnel_id, iran_server_ip, iran_username, iran_password, kharej_server_ip, kharej_username, kharej_password, iran_ipv6, kharej_ipv6, tunnel_user_id = tunnel
    
    # تعریف آدرس‌های GRE برای پینگ
    iran_gre_ip = "172.20.40.1"
    kharej_gre_ip = "172.20.40.2"
    
    iran_ping = await ping_ssh(iran_server_ip, iran_username, iran_password, kharej_gre_ip, message, "بررسی وضعیت تونل ایران")
    kharej_ping = await ping_ssh(kharej_server_ip, kharej_username, kharej_password, iran_gre_ip, message, "بررسی وضعیت تونل خارج")
    
    response = f"📊 *وضعیت تونل '{escape_md(tunnel_name)}'* 📊\n\n"
    if role == 'admin':
        response += f"👤 *کاربر:* {tunnel_user_id}\n"
    response += f"🌍 *سرور ایران ({escape_md(iran_gre_ip)}):*\n"
    if iran_ping["status"] == "connected":
        response += f"   ✅ *وصل است* (زمان پاسخ: {iran_ping['rtt']} ms)\n"
    elif iran_ping["status"] == "disconnected":
        response += "   ❌ *قطع است* (پاسخی دریافت نشد)\n"
    else:
        response += f"   ⚠️ *خطا:* {escape_md(iran_ping['error'])}\n"
    
    response += f"🌎 *سرور خارج ({escape_md(kharej_gre_ip)}):*\n"
    if kharej_ping["status"] == "connected":
        response += f"   ✅ *وصل است* (زمان پاسخ: {kharej_ping['rtt']} ms)\n"
    elif kharej_ping["status"] == "disconnected":
        response += "   ❌ *قطع است* (پاسخی دریافت نشد)\n"
    else:
        response += f"   ⚠️ *خطا:* {escape_md(kharej_ping['error'])}\n"
    
    await bot.send_message(
        chat_id=message.chat.id,
        text=response,
        reply_markup=get_main_menu_keyboard(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.MainMenu.set()

@dp.message_handler(state=ServerConfig.DeleteTunnel)
async def delete_tunnel(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    role = check_user_access(user_id)
    if not role:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ دسترسی غیرمجاز!"),
            parse_mode="MarkdownV2"
        )
        await state.finish()
        return
    
    if message.text == "⬅️ بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    
    tunnel_name = message.text.split(" (کاربر:")[0]
    conn = sqlite3.connect('tunnels.db')
    c = conn.cursor()
    if role == 'admin':
        c.execute('SELECT tunnel_id, iran_server_ip, iran_username, iran_password, kharej_server_ip, kharej_username, kharej_password FROM tunnels WHERE tunnel_name = ?', (tunnel_name,))
    else:
        c.execute('SELECT tunnel_id, iran_server_ip, iran_username, iran_password, kharej_server_ip, kharej_username, kharej_password FROM tunnels WHERE tunnel_name = ? AND user_id = ?', (tunnel_name, user_id))
    tunnel = c.fetchone()
    conn.close()
    
    if not tunnel:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("⚠️ تونل با این نام یافت نشد یا متعلق به شما نیست!"),
            reply_markup=get_main_menu_keyboard(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.MainMenu.set()
        return
    
    tunnel_id, iran_server_ip, iran_username, iran_password, kharej_server_ip, kharej_username, kharej_password = tunnel
    
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md(f"⏳ لطفاً منتظر بمانید، در حال حذف تونل '{tunnel_name}' هستیم..."),
        parse_mode="MarkdownV2"
    )
    
    iran_cleanup_commands = [
        "sudo rm -f /etc/rc.local",
        "sudo rm -f /etc/ipsec.conf",
        "sudo rm -f /etc/ipsec.secrets",
        "sudo rm -f /usr/local/bin/recycle-gre-ipsec.sh",
        "sudo ip tun del GRE6Tun_To_IR || true",
        "sudo ip tun del 6to4_To_IR || true",
        "crontab -r || true"
    ]
    
    kharej_cleanup_commands = [
        "sudo rm -f /etc/rc.local",
        "sudo rm -f /etc/ipsec.conf",
        "sudo rm -f /etc/ipsec.secrets",
        "sudo rm -f /usr/local/bin/recycle-gre-ipsec.sh",
        "sudo ip tun del GRE6Tun_To_KH || true",
        "sudo ip tun del 6to4_To_KH || true",
        "crontab -r || true"
    ]
    
    for cmd in iran_cleanup_commands:
        result = await execute_ssh_command(iran_server_ip, iran_username, iran_password, cmd)
        if "خطا" in result:
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md(f"❌ خطا در حذف تنظیمات سرور ایران: {result}"),
                reply_markup=get_main_menu_keyboard(),
                parse_mode="MarkdownV2"
            )
            await ServerConfig.MainMenu.set()
            return
    
    for cmd in kharej_cleanup_commands:
        result = await execute_ssh_command(kharej_server_ip, kharej_username, kharej_password, cmd)
        if "خطا" in result:
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md(f"❌ خطا در حذف تنظیمات سرور خارج: {result}"),
                reply_markup=get_main_menu_keyboard(),
                parse_mode="MarkdownV2"
            )
            await ServerConfig.MainMenu.set()
            return
    
    conn = sqlite3.connect('tunnels.db')
    c = conn.cursor()
    c.execute('DELETE FROM tunnels WHERE tunnel_id = ?', (tunnel_id,))
    conn.commit()
    conn.close()
    
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md(f"✅ تونل '{tunnel_name}' با موفقیت از هر دو سرور و دیتابیس حذف شد!"),
        reply_markup=get_main_menu_keyboard(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.MainMenu.set()

@dp.message_handler(state=ServerConfig.TunnelName)
async def process_tunnel_name(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("🏠 به منوی اصلی بازگشتید! لطفاً یک گزینه را انتخاب کنید:"),
            reply_markup=get_main_menu_keyboard(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.MainMenu.set()
        return
    tunnel_name = message.text.strip()
    if not tunnel_name:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً یک نام معتبر برای تونل وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        return
    await state.update_data(tunnel_name=tunnel_name)
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🔗 لطفاً نوع تونل را انتخاب کنید:"),
        reply_markup=get_tunnel_menu_keyboard(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.TunnelMenu.set()

@dp.message_handler(state=ServerConfig.TunnelMenu)
async def tunnel_menu(message: types.Message, state: FSMContext):
    if message.text == "🔗 تونل 1 ایران به 1 خارج":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("🌍 لطفاً IP سرور ایران را برای اتصال SSH وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.IranServerIP.set()
    elif message.text == "⬅️ بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
    else:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً گزینه‌ای معتبر انتخاب کنید:"),
            reply_markup=get_tunnel_menu_keyboard(),
            parse_mode="MarkdownV2"
        )

async def back_to_main_menu(message: types.Message, state: FSMContext):
    await state.finish()
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🏠 به منوی اصلی بازگشتید! لطفاً یک گزینه را انتخاب کنید:"),
        reply_markup=get_main_menu_keyboard(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.MainMenu.set()

@dp.message_handler(state=ServerConfig.IranServerIP)
async def process_iran_server_ip(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("✨ لطفاً یک نام برای تونل وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.TunnelName.set()
        return
    if not is_valid_ip(message.text.strip()):
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً یک IP معتبر وارد کنید (مثلاً 192.168.1.1):"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        return
    await state.update_data(iran_server_ip=message.text)
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("👤 لطفاً نام کاربری سرور ایران را وارد کنید:"),
        reply_markup=get_back_buttons(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.IranUsername.set()

@dp.message_handler(state=ServerConfig.IranUsername)
async def process_iran_username(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("🌍 لطفاً IP سرور ایران را برای اتصال SSH وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.IranServerIP.set()
        return
    await state.update_data(iran_username=message.text)
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🔒 لطفاً رمز عبور سرور ایران را وارد کنید:"),
        reply_markup=get_back_buttons(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.IranPassword.set()

@dp.message_handler(state=ServerConfig.IranPassword)
async def process_iran_password(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("👤 لطفاً نام کاربری سرور ایران را وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.IranUsername.set()
        return
    await state.update_data(iran_password=message.text)
    data = await state.get_data()
    iran_server_ip = data['iran_server_ip']
    iran_username = data['iran_username']
    iran_password = data['iran_password']

    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("⏳ لطفاً منتظر بمانید، در حال تست اتصال به سرور ایران هستیم..."),
        parse_mode="MarkdownV2"
    )
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(iran_server_ip, username=iran_username, password=iran_password, timeout=10)
        ssh.close()
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("✅ با موفقیت به سرور ایران متصل شد!"),
            parse_mode="MarkdownV2"
        )
    except Exception as e:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md(f"❌ اتصال به سرور ایران ناموفق بود: {str(e)}\nلطفاً دوباره اطلاعات را وارد کنید."),
            parse_mode="MarkdownV2"
        )
        await back_to_main_menu(message, state)
        return

    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🌎 لطفاً IP سرور خارج را برای اتصال SSH وارد کنید:"),
        reply_markup=get_back_buttons(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.KharejServerIP.set()

@dp.message_handler(state=ServerConfig.KharejServerIP)
async def process_kharej_server_ip(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("🔒 لطفاً رمز عبور سرور ایران را وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.IranPassword.set()
        return
    if not is_valid_ip(message.text.strip()):
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً یک IP معتبر وارد کنید (مثلاً 192.168.1.2):"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        return
    await state.update_data(kharej_server_ip=message.text)
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("👤 لطفاً نام کاربری سرور خارج را وارد کنید:"),
        reply_markup=get_back_buttons(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.KharejUsername.set()

@dp.message_handler(state=ServerConfig.KharejUsername)
async def process_kharej_username(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("🌎 لطفاً IP سرور خارج را برای اتصال SSH وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.KharejServerIP.set()
        return
    await state.update_data(kharej_username=message.text)
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🔒 لطفاً رمز عبور سرور خارج را وارد کنید:"),
        reply_markup=get_back_buttons(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.KharejPassword.set()

@dp.message_handler(state=ServerConfig.KharejPassword)
async def process_kharej_password(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("👤 لطفاً نام کاربری سرور خارج را وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.KharejUsername.set()
        return
    await state.update_data(kharej_password=message.text)
    data = await state.get_data()
    kharej_server_ip = data['kharej_server_ip']
    kharej_username = data['kharej_username']
    kharej_password = data['kharej_password']

    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("⏳ لطفاً منتظر بمانید، در حال تست اتصال به سرور خارج هستیم..."),
        parse_mode="MarkdownV2"
    )
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(kharej_server_ip, username=kharej_username, password=kharej_password, timeout=10)
        ssh.close()
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("✅ با موفقیت به سرور خارج متصل شد!"),
            parse_mode="MarkdownV2"
        )
    except Exception as e:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md(f"❌ اتصال به سرور خارج ناموفق بود: {str(e)}\nلطفاً دوباره اطلاعات را وارد کنید."),
            parse_mode="MarkdownV2"
        )
        await back_to_main_menu(message, state)
        return

    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("⏳ لطفاً منتظر بمانید، در حال نصب پیش‌نیازها روی سرورها هستیم..."),
        parse_mode="MarkdownV2"
    )
    
    initial_commands = [
        "apt update && apt upgrade -y",
        "sudo modprobe ip_gre",
        "sudo modprobe ip6gre",
        "lsmod | grep gre",
        "sudo apt update",
        "sudo apt install strongswan strongswan-starter -y"
    ]

    iran_server_ip = data['iran_server_ip']
    iran_username = data['iran_username']
    iran_password = data['iran_password']
    for cmd in initial_commands:
        result = await execute_ssh_command(iran_server_ip, iran_username, iran_password, cmd)
        if "خطا" in result:
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md(f"❌ خطا در نصب پیش‌نیازها روی سرور ایران: {result}"),
                parse_mode="MarkdownV2"
            )
            await back_to_main_menu(message, state)
            return

    for cmd in initial_commands:
        result = await execute_ssh_command(kharej_server_ip, kharej_username, kharej_password, cmd)
        if "خطا" in result:
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md(f"❌ خطا در نصب پیش‌نیازها روی سرور خارج: {result}"),
                parse_mode="MarkdownV2"
            )
            await back_to_main_menu(message, state)
            return

    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("✅ پیش‌نیازها با موفقیت روی هر دو سرور نصب شدند!"),
        parse_mode="MarkdownV2"
    )
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🌍 لطفاً IP سرور ایران را وارد کنید:"),
        reply_markup=get_back_buttons(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.IranIP.set()

@dp.message_handler(state=ServerConfig.IranIP)
async def process_iran_ip(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("🔒 لطفاً رمز عبور سرور خارج را وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.KharejPassword.set()
        return
    if not is_valid_ip(message.text.strip()):
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً یک IP معتبر برای سرور ایران وارد کنید (مثلاً 192.168.1.1):"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        return
    await state.update_data(iran_ip=message.text)
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🌎 لطفاً IP سرور خارج را وارد کنید:"),
        reply_markup=get_back_buttons(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.KharejIP.set()

@dp.message_handler(state=ServerConfig.KharejIP)
async def process_kharej_ip(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("🌍 لطفاً IP سرور ایران را وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.IranIP.set()
        return
    if not is_valid_ip(message.text.strip()):
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً یک IP معتبر برای سرور خارج وارد کنید (مثلاً 192.168.1.2):"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        return
    await state.update_data(kharej_ip=message.text)
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🔑 لطفاً یک رمز سخت برای تونل وارد کنید:"),
        reply_markup=get_back_buttons(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.PSK.set()

@dp.message_handler(state=ServerConfig.PSK)
async def process_psk(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("🌎 لطفاً IP سرور خارج را وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.KharejIP.set()
        return
    psk = message.text.strip()
    if not psk:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً یک رمز سخت برای تونل وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        return
    await state.update_data(psk=psk)
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("📏 لطفاً MTU برای تونل 6to4 را انتخاب کنید:"),
        reply_markup=get_mtu_6to4_selection_keyboard(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.MTU_6to4.set()

@dp.callback_query_handler(lambda c: c.data in ["mtu_6to4_default", "mtu_6to4_manual", "back_to_psk", "back_to_main"], state=ServerConfig.MTU_6to4)
async def process_mtu_6to4_selection(callback_query: types.CallbackQuery, state: FSMContext):
    await callback_query.answer()
    if callback_query.data == "back_to_main":
        try:
            await callback_query.message.edit_text(
                text=escape_md("🏠 به منوی اصلی بازگشتید! لطفاً یک گزینه را انتخاب کنید:"),
                reply_markup=get_main_menu_keyboard(),
                parse_mode="MarkdownV2"
            )
        except:
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text=escape_md("🏠 به منوی اصلی بازگشتید! لطفاً یک گزینه را انتخاب کنید:"),
                reply_markup=get_main_menu_keyboard(),
                parse_mode="MarkdownV2"
            )
        await state.finish()
        await ServerConfig.MainMenu.set()
        return
    if callback_query.data == "back_to_psk":
        try:
            await callback_query.message.edit_text(
                text=escape_md("🔑 لطفاً یک رمز سخت برای تونل وارد کنید:"),
                reply_markup=get_back_buttons(),
                parse_mode="MarkdownV2"
            )
        except:
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text=escape_md("🔑 لطفاً یک رمز سخت برای تونل وارد کنید:"),
                reply_markup=get_back_buttons(),
                parse_mode="MarkdownV2"
            )
        await ServerConfig.PSK.set()
        return
    if callback_query.data == "mtu_6to4_default":
        await state.update_data(mtu_6to4="1480")
        try:
            await callback_query.message.edit_text(
                text=escape_md("✅ MTU برای تونل 6to4 به‌صورت پیش‌فرض (1480) تنظیم شد.\n📏 لطفاً MTU برای تونل GRE را انتخاب کنید:"),
                reply_markup=get_mtu_gre_selection_keyboard(),
                parse_mode="MarkdownV2"
            )
        except:
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text=escape_md("✅ MTU برای تونل 6to4 به‌صورت پیش‌فرض (1480) تنظیم شد.\n📏 لطفاً MTU برای تونل GRE را انتخاب کنید:"),
                reply_markup=get_mtu_gre_selection_keyboard(),
                parse_mode="MarkdownV2"
            )
        await ServerConfig.MTU_GRE.set()
    else:
        try:
            await callback_query.message.edit_text(
                text=escape_md("✍️ لطفاً مقدار MTU برای تونل 6to4 را به‌صورت دستی وارد کنید (بین 1280 و 1500):"),
                reply_markup=get_back_buttons(),
                parse_mode="MarkdownV2"
            )
        except:
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text=escape_md("✍️ لطفاً مقدار MTU برای تونل 6to4 را به‌صورت دستی وارد کنید (بین 1280 و 1500):"),
                reply_markup=get_back_buttons(),
                parse_mode="MarkdownV2"
            )
        await ServerConfig.MTU_6to4.set()

@dp.message_handler(state=ServerConfig.MTU_6to4)
async def process_manual_mtu_6to4(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("📏 لطفاً MTU برای تونل 6to4 را انتخاب کنید:"),
            reply_markup=get_mtu_6to4_selection_keyboard(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.MTU_6to4.set()
        return
    try:
        mtu = int(message.text)
        if 1280 <= mtu <= 1500:
            await state.update_data(mtu_6to4=message.text)
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md(f"✅ MTU برای تونل 6to4 روی {mtu} تنظیم شد."),
                parse_mode="MarkdownV2"
            )
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md("📏 لطفاً MTU برای تونل GRE را انتخاب کنید:"),
                reply_markup=get_mtu_gre_selection_keyboard(),
                parse_mode="MarkdownV2"
            )
            await ServerConfig.MTU_GRE.set()
        else:
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md("❌ لطفاً مقدار MTU بین 1280 و 1500 وارد کنید:"),
                reply_markup=get_back_buttons(),
                parse_mode="MarkdownV2"
            )
    except ValueError:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً یک عدد معتبر برای MTU وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )

@dp.callback_query_handler(lambda c: c.data in ["mtu_gre_default", "mtu_gre_manual", "back_to_mtu_6to4", "back_to_main"], state=ServerConfig.MTU_GRE)
async def process_mtu_gre_selection(callback_query: types.CallbackQuery, state: FSMContext):
    await callback_query.answer()
    if callback_query.data == "back_to_main":
        try:
            await callback_query.message.edit_text(
                text=escape_md("🏠 به منوی اصلی بازگشتید! لطفاً یک گزینه را انتخاب کنید:"),
                reply_markup=get_main_menu_keyboard(),
                parse_mode="MarkdownV2"
            )
        except:
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text=escape_md("🏠 به منوی اصلی بازگشتید! لطفاً یک گزینه را انتخاب کنید:"),
                reply_markup=get_main_menu_keyboard(),
                parse_mode="MarkdownV2"
            )
        await state.finish()
        await ServerConfig.MainMenu.set()
        return
    if callback_query.data == "back_to_mtu_6to4":
        try:
            await callback_query.message.edit_text(
                text=escape_md("📏 لطفاً MTU برای تونل 6to4 را انتخاب کنید:"),
                reply_markup=get_mtu_6to4_selection_keyboard(),
                parse_mode="MarkdownV2"
            )
        except:
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text=escape_md("📏 لطفاً MTU برای تونل 6to4 را انتخاب کنید:"),
                reply_markup=get_mtu_6to4_selection_keyboard(),
                parse_mode="MarkdownV2"
            )
        await ServerConfig.MTU_6to4.set()
        return
    if callback_query.data == "mtu_gre_default":
        await state.update_data(mtu_gre="1424")
        try:
            await callback_query.message.edit_text(
                text=escape_md("✅ MTU برای تونل GRE به‌صورت پیش‌فرض (1424) تنظیم شد."),
                parse_mode="MarkdownV2"
            )
        except:
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text=escape_md("✅ MTU برای تونل GRE به‌صورت پیش‌فرض (1424) تنظیم شد."),
                parse_mode="MarkdownV2"
            )
        await process_config_files(callback_query.message, state)
    else:
        try:
            await callback_query.message.edit_text(
                text=escape_md("✍️ لطفاً مقدار MTU برای تونل GRE را به‌صورت دستی وارد کنید (بین 1280 و 1500):"),
                reply_markup=get_back_buttons(),
                parse_mode="MarkdownV2"
            )
        except:
            await bot.send_message(
                chat_id=callback_query.message.chat.id,
                text=escape_md("✍️ لطفاً مقدار MTU برای تونل GRE را به‌صورت دستی وارد کنید (بین 1280 و 1500):"),
                reply_markup=get_back_buttons(),
                parse_mode="MarkdownV2"
            )
        await ServerConfig.MTU_GRE.set()

@dp.message_handler(state=ServerConfig.MTU_GRE)
async def process_manual_mtu_gre(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("📏 لطفاً MTU برای تونل GRE را انتخاب کنید:"),
            reply_markup=get_mtu_gre_selection_keyboard(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.MTU_GRE.set()
        return
    try:
        mtu = int(message.text)
        if 1280 <= mtu <= 1500:
            await state.update_data(mtu_gre=message.text)
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md(f"✅ MTU برای تونل GRE روی {mtu} تنظیم شد."),
                parse_mode="MarkdownV2"
            )
            await process_config_files(message, state)
        else:
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md("❌ لطفاً مقدار MTU بین 1280 و 1500 وارد کنید:"),
                reply_markup=get_back_buttons(),
                parse_mode="MarkdownV2"
            )
    except ValueError:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً یک عدد معتبر برای MTU وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )

async def save_to_db(data):
    conn = sqlite3.connect('tunnels.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO tunnels (
            tunnel_id, tunnel_name, user_id, iran_server_ip, iran_username, iran_password, 
            kharej_server_ip, kharej_username, kharej_password, 
            iran_ip, kharej_ip, iran_ipv6, kharej_ipv6, psk, mtu_6to4, mtu_gre, crontab_hour
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data['tunnel_id'], data['tunnel_name'], data['user_id'],
        data['iran_server_ip'], data['iran_username'], data['iran_password'],
        data['kharej_server_ip'], data['kharej_username'], data['kharej_password'],
        data['iran_ip'], data['kharej_ip'], data['iran_ipv6'], data['kharej_ipv6'],
        data['psk'], data['mtu_6to4'], data['mtu_gre'], data.get('crontab_hour', '')
    ))
    conn.commit()
    conn.close()

async def process_config_files(message: types.Message, state: FSMContext):
    data = await state.get_data()
    iran_server_ip = data['iran_server_ip']
    iran_username = data['iran_username']
    iran_password = data['iran_password']
    kharej_server_ip = data['kharej_server_ip']
    kharej_username = data['kharej_username']
    kharej_password = data['kharej_password']
    iran_ip = data['iran_ip']
    kharej_ip = data['kharej_ip']
    psk = data['psk']
    mtu_6to4 = data['mtu_6to4']
    mtu_gre = data['mtu_gre']
    
    iran_ipv6 = "2002:504b:d769::2"
    kharej_ipv6 = "2002:504b:d769::1"
    await state.update_data(iran_ipv6=iran_ipv6, kharej_ipv6=kharej_ipv6)

    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("⏳ لطفاً منتظر بمانید، در حال نصب تونل روی سرورها هستیم..."),
        parse_mode="MarkdownV2"
    )
    
    iran_rc_local_content = f"""#!/bin/bash
ip tunnel add 6to4_To_IR mode sit remote {kharej_ip} local {iran_ip}
ip -6 addr add {iran_ipv6}/64 dev 6to4_To_IR
ip link set 6to4_To_IR mtu {mtu_6to4}
ip link set 6to4_To_IR up

# GRE over IPv6
ip -6 tunnel add GRE6Tun_To_IR mode ip6gre remote {kharej_ipv6} local {iran_ipv6}
ip addr add 172.20.40.1/30 dev GRE6Tun_To_IR
ip link set GRE6Tun_To_IR mtu {mtu_gre}
ip link set GRE6Tun_To_IR up

exit 0
"""
    iran_ipsec_conf_content = f"""config setup
    charondebug="none"

conn gre6tunnel
    left={iran_ipv6}
    leftid=@iran
    leftsubnet={iran_ipv6}/128
    right={kharej_ipv6}
    rightid=@kharej
    rightsubnet={kharej_ipv6}/128
    authby=secret
    auto=start
    keyexchange=ikev2
    ike=aes256-sha2_256-modp2048!
    esp=aes256-sha2_256!
"""
    iran_ipsec_secrets_content = f'@iran @kharej : PSK "{psk}"'

    kharej_rc_local_content = f"""#!/bin/bash
ip tunnel add 6to4_To_KH mode sit remote {iran_ip} local {kharej_ip}
ip -6 addr add {kharej_ipv6}/64 dev 6to4_To_KH
ip link set 6to4_To_KH mtu {mtu_6to4}
ip link set 6to4_To_KH up

# GRE over IPv6
ip -6 tunnel add GRE6Tun_To_KH mode ip6gre remote {iran_ipv6} local {kharej_ipv6}
ip addr add 172.20.40.2/30 dev GRE6Tun_To_KH
ip link set GRE6Tun_To_KH mtu {mtu_gre}
ip link set GRE6Tun_To_KH up

exit 0
"""
    kharej_ipsec_conf_content = f"""config setup
    charondebug="none"

conn gre6tunnel
    left={kharej_ipv6}
    leftid=@kharej
    leftsubnet={kharej_ipv6}/128
    right={iran_ipv6}
    rightid=@iran
    rightsubnet={iran_ipv6}/128
    authby=secret
    auto=start
    keyexchange=ikev2
    ike=aes256-sha2_256-modp2048!
    esp=aes256-sha2_256!
"""
    kharej_ipsec_secrets_content = f'@iran @kharej : PSK "{psk}"'

    iran_recycle_script_content = f"""#!/bin/bash
ipsec restart
ip link set GRE6Tun_To_IR down
ip link set 6to4_To_IR down
sleep 1
ip link set 6to4_To_IR up
ip link set GRE6Tun_To_IR up
"""

    kharej_recycle_script_content = f"""#!/bin/bash
ipsec restart
ip link set GRE6Tun_To_KH down
ip link set 6to4_To_KH down
sleep 1
ip link set 6to4_To_KH up
ip link set GRE6Tun_To_KH up
"""

    iran_commands = [
        f"echo '{iran_rc_local_content}' | sudo tee /etc/rc.local",
        "sudo chmod +x /etc/rc.local",
        "sudo bash /etc/rc.local",
        f"echo '{iran_ipsec_conf_content}' | sudo tee /etc/ipsec.conf",
        f"echo '{iran_ipsec_secrets_content}' | sudo tee /etc/ipsec.secrets",
        "sudo systemctl enable strongswan-starter",
        "sudo systemctl start strongswan-starter",
        f"echo '{iran_recycle_script_content}' | sudo tee /usr/local/bin/recycle-gre-ipsec.sh",
        "sudo chmod +x /usr/local/bin/recycle-gre-ipsec.sh"
    ]

    for cmd in iran_commands:
        result = await execute_ssh_command(iran_server_ip, iran_username, iran_password, cmd)
        if "خطا" in result:
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md(f"❌ خطا در پیکربندی سرور ایران: {result}"),
                parse_mode="MarkdownV2"
            )
            await back_to_main_menu(message, state)
            return

    kharej_commands = [
        f"echo '{kharej_rc_local_content}' | sudo tee /etc/rc.local",
        "sudo chmod +x /etc/rc.local",
        "sudo bash /etc/rc.local",
        f"echo '{kharej_ipsec_conf_content}' | sudo tee /etc/ipsec.conf",
        f"echo '{kharej_ipsec_secrets_content}' | sudo tee /etc/ipsec.secrets",
        "sudo systemctl enable strongswan-starter",
        "sudo systemctl start strongswan-starter",
        f"echo '{kharej_recycle_script_content}' | sudo tee /usr/local/bin/recycle-gre-ipsec.sh",
        "sudo chmod +x /usr/local/bin/recycle-gre-ipsec.sh"
    ]

    for cmd in kharej_commands:
        result = await execute_ssh_command(kharej_server_ip, kharej_username, kharej_password, cmd)
        if "خطا" in result:
            await bot.send_message(
                chat_id=message.chat.id,
                text=escape_md(f"❌ خطا در پیکربندی سرور خارج: {result}"),
                parse_mode="MarkdownV2"
            )
            await back_to_main_menu(message, state)
            return

    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("✅ تونل با موفقیت نصب شد!"),
        parse_mode="MarkdownV2"
    )
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md(f"🔗 تونل را برای سرور ایران با آی‌پی زیر پینگ کنید: {kharej_ipv6}"),
        parse_mode="MarkdownV2"
    )
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("⏰ لطفاً ساعت را برای ریست تونل وارد کنید (0-23):"),
        reply_markup=get_back_buttons(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.CrontabHour.set()

@dp.message_handler(state=ServerConfig.CrontabHour)
async def process_crontab_hour(message: types.Message, state: FSMContext):
    if message.text == "🏠 بازگشت به منوی اصلی":
        await back_to_main_menu(message, state)
        return
    if message.text == "⬅️ بازگشت به مرحله قبل":
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("📏 لطفاً MTU برای تونل GRE را انتخاب کنید:"),
            reply_markup=get_mtu_gre_selection_keyboard(),
            parse_mode="MarkdownV2"
        )
        await ServerConfig.MTU_GRE.set()
        return
    crontab_hour = message.text.strip()
    if not is_valid_crontab_hour(crontab_hour):
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md("❌ لطفاً یک ساعت معتبر بین 0 تا 23 وارد کنید:"),
            reply_markup=get_back_buttons(),
            parse_mode="MarkdownV2"
        )
        return

    data = await state.get_data()
    iran_server_ip = data['iran_server_ip']
    iran_username = data['iran_username']
    iran_password = data['iran_password']
    kharej_server_ip = data['kharej_server_ip']
    kharej_username = data['kharej_username']
    kharej_password = data['kharej_password']

    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("⏳ لطفاً منتظر بمانید، در حال تنظیم زمان‌بندی ریست تونل هستیم..."),
        parse_mode="MarkdownV2"
    )
    
    await state.update_data(crontab_hour=crontab_hour)
    await save_to_db(await state.get_data())

    crontab_time = f"0 {crontab_hour} * * *"
    crontab_cmd = f"(crontab -l 2>/dev/null; echo '{crontab_time} /usr/local/bin/recycle-gre-ipsec.sh >/dev/null 2>&1') | crontab -"

    result = await execute_ssh_command(iran_server_ip, iran_username, iran_password, crontab_cmd)
    if "خطا" in result:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md(f"❌ خطا در تنظیم کرون‌تب برای سرور ایران: {result}"),
            parse_mode="MarkdownV2"
        )
        await back_to_main_menu(message, state)
        return
    
    result = await execute_ssh_command(kharej_server_ip, kharej_username, kharej_password, crontab_cmd)
    if "خطا" in result:
        await bot.send_message(
            chat_id=message.chat.id,
            text=escape_md(f"❌ خطا در تنظیم کرون‌تب سرور خارج: {result}"),
            parse_mode="MarkdownV2"
        )
        await back_to_main_menu(message, state)
        return

    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("✅ تنظیم ریست تونل برای هر دو سرور با موفقیت انجام شد!"),
        parse_mode="MarkdownV2"
    )
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🎉 نصب تونل با موفقیت به پایان رسید!"),
        reply_markup=types.ReplyKeyboardRemove(),
        parse_mode="MarkdownV2"
    )
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("‼️ نکته: برای دایرکت تونل باید داخل سرور ایران آی‌پی 172.20.40.2 را استفاده کنید.\n✅ پیشنهاد ما استفاده از این ابزار است\n📌 [ابزار IPTABLE-Tunnel](https://github.com/azavaxhuman/IPTABLE-Tunnel-multi-port)"),
        parse_mode="MarkdownV2"
    )
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🌟 حالا می‌توانید وضعیت تونل را از منوی اصلی بررسی کنید یا تونل جدیدی ایجاد کنید!"),
        parse_mode="MarkdownV2"
    )
    await state.finish()
    await bot.send_message(
        chat_id=message.chat.id,
        text=escape_md("🏠 به منوی اصلی بازگشتید! لطفاً یک گزینه را انتخاب کنید."),
        reply_markup=get_main_menu_keyboard(),
        parse_mode="MarkdownV2"
    )
    await ServerConfig.MainMenu.set()

async def execute_ssh_command(host: str, username: str, password: str, command: str) -> str:
    ssh = None
    try:
        print(f"اتصال SSH به {host} برای اجرای دستور: {command}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password, timeout=30)
        print(f"اتصال SSH به {host} برقرار شد")
        stdin, stdout, stderr = ssh.exec_command(command, timeout=40)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        print(f"خروجی دستور {command}: {output}")
        if error and "Permission denied" in error:
            print(f"خطا در دسترسی: {error}")
            return f"خطا: دسترسی غیرمجاز برای اجرای دستور {command}"
        return output if output else error
    except Exception as e:
        error_msg = f"خطا: {str(e)} - میزبان: {host}, دستور: {command}"
        print(error_msg)
        return error_msg
    finally:
        if ssh:
            ssh.close()
            print(f"اتصال SSH به {host} بسته شد")

async def main():
    try:
        await dp.start_polling()
    except KeyboardInterrupt:
        pass
    finally:
        await dp.storage.close()
        await dp.storage.wait_closed()
        await bot.session.close()

if __name__ == '__main__':
    asyncio.run(main())