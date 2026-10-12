import os
import logging
import sqlite3
import time
import hashlib
import hmac
from datetime import datetime
from typing import List, Dict

import requests
from dotenv import load_dotenv
from telegram import Update, constants
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.request import HTTPXRequest

load_dotenv()

def get_env_bool(key: str, default: str) -> bool:
    return os.getenv(key, default).lower() == "true"

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
OWNER_ID = os.getenv("OWNER_TELEGRAM_ID")
PASSWORD_HASH = os.getenv("JARVIS_PASSWORD_HASH", "")
AUTH_MAX_ATTEMPTS = max(1, int(os.getenv("AUTH_MAX_ATTEMPTS", 5)))
AUTH_COOLDOWN_SECONDS = max(30, int(os.getenv("AUTH_COOLDOWN_SECONDS", 300)))
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip('/')
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

DAILY_LIMIT = int(os.getenv("DAILY_MESSAGE_LIMIT", 100))
TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", 30))
MAX_INPUT = int(os.getenv("MAX_INPUT_LENGTH", 2000))

def validate_config():
    missing = []
    if not TOKEN: missing.append("TELEGRAM_BOT_TOKEN")
    if not OWNER_ID: missing.append("OWNER_TELEGRAM_ID")
    if not PASSWORD_HASH: missing.append("JARVIS_PASSWORD_HASH")
    
    if missing:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing)}")
    
    try:
        owner_id = int(OWNER_ID)
        if owner_id <= 0:
            raise ValueError
    except (TypeError, ValueError):
        raise EnvironmentError("OWNER_TELEGRAM_ID must be a positive numeric Telegram user ID")
    if not verify_password_hash_format(PASSWORD_HASH):
        raise EnvironmentError("JARVIS_PASSWORD_HASH is invalid; generate it using the instructions in GUIDE.md")

try:
    OWNER_ID = int(OWNER_ID) if OWNER_ID else 0
except ValueError:
    OWNER_ID = 0

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

DB_PATH = "jarvis_bot.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            user_id INTEGER PRIMARY KEY, 
                            approved INTEGER DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS usage (
                            user_id INTEGER, 
                            date TEXT, 
                            count INTEGER DEFAULT 0, 
                            PRIMARY KEY (user_id, date))''')
        cursor.execute("INSERT OR IGNORE INTO users (user_id, approved) VALUES (?, 1)", (OWNER_ID,))
        cursor.execute("""CREATE TABLE IF NOT EXISTS authenticated_sessions (
                            user_id INTEGER PRIMARY KEY,
                            authenticated_at TEXT NOT NULL)""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS auth_attempts (
                            user_id INTEGER PRIMARY KEY,
                            attempts INTEGER NOT NULL DEFAULT 0,
                            blocked_until REAL NOT NULL DEFAULT 0)""")
        conn.commit()

def is_approved(user_id: int) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT approved FROM users WHERE user_id = ?", (user_id,))
        result = cursor.fetchone()
        return result is not None and result[0] == 1

def increment_usage(user_id: int) -> int:
    date_str = datetime.now().strftime("%Y-%m-%d")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO usage (user_id, date, count) VALUES (?, ?, 0)", (user_id, date_str))
        cursor.execute("UPDATE usage SET count = count + 1 WHERE user_id = ? AND date = ?", (user_id, date_str))
        cursor.execute("SELECT count FROM usage WHERE user_id = ? AND date = ?", (user_id, date_str))
        return cursor.fetchone()[0]

def get_current_usage(user_id: int) -> int:
    date_str = datetime.now().strftime("%Y-%m-%d")
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT count FROM usage WHERE user_id = ? AND date = ?", (user_id, date_str))
        result = cursor.fetchone()
        return result[0] if result else 0

def verify_password_hash_format(value: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = value.split("$")
        return (algorithm == "pbkdf2_sha256" and int(iterations) >= 100000
                and len(bytes.fromhex(salt_hex)) >= 16 and len(bytes.fromhex(digest_hex)) == 32)
    except (ValueError, TypeError):
        return False

def verify_password(password: str, encoded: str = PASSWORD_HASH) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(actual, bytes.fromhex(digest_hex))
    except (ValueError, TypeError, UnicodeError):
        return False

def is_authenticated(user_id: int) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT 1 FROM authenticated_sessions WHERE user_id = ?", (user_id,)).fetchone()
        return row is not None

def authenticate_user(user_id: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT OR REPLACE INTO authenticated_sessions (user_id, authenticated_at) VALUES (?, ?)",
                     (user_id, datetime.utcnow().isoformat(timespec="seconds")))
        conn.execute("DELETE FROM auth_attempts WHERE user_id = ?", (user_id,))

def logout_user(user_id: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM authenticated_sessions WHERE user_id = ?", (user_id,))

def check_auth_attempt(user_id: int):
    now = time.time()
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT attempts, blocked_until FROM auth_attempts WHERE user_id = ?", (user_id,)).fetchone()
        if row and row[1] > now:
            return False, int(row[1] - now) + 1
        if row and row[1] and row[1] <= now:
            conn.execute("DELETE FROM auth_attempts WHERE user_id = ?", (user_id,))
    return True, 0

def record_failed_auth(user_id: int) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute("SELECT attempts FROM auth_attempts WHERE user_id = ?", (user_id,)).fetchone()
        attempts = (row[0] if row else 0) + 1
        blocked_until = time.time() + AUTH_COOLDOWN_SECONDS if attempts >= AUTH_MAX_ATTEMPTS else 0
        conn.execute("INSERT OR REPLACE INTO auth_attempts (user_id, attempts, blocked_until) VALUES (?, ?, ?)",
                     (user_id, attempts, blocked_until))
        return attempts

async def password_gate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user = update.effective_user
    message = update.effective_message
    if not user or not message:
        return False
    if not is_approved(user.id):
        await message.reply_text("Access is restricted. Ask the bot owner to approve your Telegram ID.")
        return False
    if is_authenticated(user.id):
        return True
    allowed, wait_seconds = check_auth_attempt(user.id)
    if not allowed:
        await message.reply_text(f"Too many incorrect passwords. Try again in about {wait_seconds} seconds.")
        return False
    candidate = (message.text or "").strip()
    if candidate and verify_password(candidate):
        authenticate_user(user.id)
        await message.reply_text("Authentication successful. J.A.R.V.I.S. is ready. Send /help to see commands.")
        return False
    record_failed_auth(user.id)
    await message.reply_text("Password required. Send the access password as a message. Incorrect attempts are rate-limited.")
    return False

user_contexts: Dict[int, List[Dict[str, str]]] = {}

def reset_context(user_id: int):
    if user_id in user_contexts:
        del user_contexts[user_id]

def call_ollama(user_id: int, text: str) -> str:
    if user_id not in user_contexts:
        user_contexts[user_id] = []
    
    user_contexts[user_id].append({"role": "user", "content": text})
    context = user_contexts[user_id][-10:]
    
    headers = {}
    if OLLAMA_API_KEY:
        headers["Authorization"] = f"Bearer {OLLAMA_API_KEY}"

    payload = {"model": OLLAMA_MODEL, "messages": context, "stream": False}

    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat", 
            json=payload, 
            headers=headers, 
            timeout=TIMEOUT
        )
        response.raise_for_status()
        result = response.json()
        answer = result['message']['content']
        user_contexts[user_id].append({"role": "assistant", "content": answer})
        return answer
    except Exception as e:
        logger.error(f"Ollama API Error: {e}")
        return "⚠️ I'm having trouble connecting to my brain. Please try again later."


def format_response(text: str) -> str:
    """Convert common Markdown/LaTeX notation into readable Telegram plain text."""
    import re

    if not text:
        return text

    text = text.replace(r"\[", "").replace(r"\]", "")
    text = text.replace("$$", "").replace("$", "")
    text = re.sub(r"\\\((.*?)\\\)", r"\1", text, flags=re.DOTALL)

    text = re.sub(r"\\text\{([^{}]*)\}", r"\1", text)
    text = re.sub(r"\\mathrm\{([^{}]*)\}", r"\1", text)
    text = re.sub(r"\\mathbf\{([^{}]*)\}", r"\1", text)
    replacements = {
        r"\times": "×", r"\cdot": "·", r"\pi": "π",
        r"\Omega": "Ω", r"\mu": "μ", r"\sqrt": "√",
        r"\approx": "≈", r"\pm": "±", r"\neq": "≠",
        r"\leq": "≤", r"\geq": "≥", r"\rightarrow": "→",
        r"\Rightarrow": "⇒", r"\times": "×", r"\div": "÷",
        r"\cdots": "…", r"\infty": "∞", r"\angle": "∠",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)

    text = re.sub(r"√\{([^{}]*)\}", r"√(\1)", text)

    for _ in range(4):
        text = re.sub(
            r"\\frac\s*\{([^{}]*)\}\s*\{([^{}]*)\}",
            lambda m: f"{m.group(1)} / ({m.group(2)})", text
        )
    text = re.sub(r"\\(?:left|right)\b", "", text)
    text = text.replace(r"\,", " ").replace(r"\;", " ").replace(r"\!", "")
    text = text.replace(r"\%", "%").replace(r"\_", "_").replace(r"\{", "{").replace(r"\}", "}")
    text = re.sub(r"\\(?:mathrm|text|mathbf)\b", "", text)

    text = re.sub(r"(?m)^\s*#{1,6}\s*", "", text)
    text = text.replace("**", "").replace("__", "")
    text = re.sub(r"(?m)^\s*\*\s+", "• ", text)
    text = re.sub(r"(?m)^\s*-\s+", "• ", text)

    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


async def authorized_user_only(update: Update, context: ContextTypes.DEFAULT_TYPE, enforce_quota: bool = True):
    user = update.effective_user
    message = update.effective_message
    if not user or not message or not is_approved(user.id):
        if message:
            await message.reply_text("❌ Access restricted. Ask the bot owner to approve your Telegram ID.")
        return False
    if not is_authenticated(user.id):
        await message.reply_text("🔐 Authenticate first by sending the access password. Use /start for instructions.")
        return False
    if enforce_quota and get_current_usage(user.id) >= DAILY_LIMIT:
        await message.reply_text("🛑 Daily message limit reached. Try again tomorrow!")
        return False
    return True

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or not is_approved(user.id):
        await update.effective_message.reply_text("Access is restricted. Ask the bot owner to approve your Telegram ID.")
        return
    if not is_authenticated(user.id):
        await update.effective_message.reply_text("🔐 Enter the J.A.R.V.I.S. access password to continue.")
        return
    await update.effective_message.reply_text("Hello! I am J.A.R.V.I.S. — Personal AI Assistant. How can I help you today?")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await authorized_user_only(update, context): return
    text = (
        "🤖 *J.A.R.V.I.S. Commands*\n\n"
        "/start - Introduction\n"
        "/help - Show this menu\n"
        "/id - Get your numeric Telegram ID\n"
        "/usage - Check daily AI usage\n"
        "/reset - Clear conversation memory"
    )
    await update.message.reply_text(text, parse_mode=constants.ParseMode.MARKDOWN)

async def id_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await authorized_user_only(update, context): return
    await update.message.reply_text(f"Your Telegram ID: `{update.effective_user.id}`", parse_mode=constants.ParseMode.MARKDOWN)

async def usage_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await authorized_user_only(update, context, enforce_quota=False): return
    count = get_current_usage(update.effective_user.id)
    await update.message.reply_text(f"📊 Daily Usage: {count}/{DAILY_LIMIT} messages.")

async def reset_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await authorized_user_only(update, context, enforce_quota=False): return
    reset_context(update.effective_user.id)
    await update.message.reply_text("🧠 Conversation context has been reset.")

async def logout_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or not is_approved(user.id):
        await update.effective_message.reply_text("Access is restricted. Ask the bot owner to approve your Telegram ID.")
        return
    logout_user(user.id)
    await update.effective_message.reply_text("You are logged out. Send /start and enter the password to authenticate again.")

async def handle_password_or_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or not update.effective_message:
        return
    if not is_approved(user.id):
        await update.effective_message.reply_text("Access is restricted. Ask the bot owner to approve your Telegram ID.")
        return
    if not is_authenticated(user.id):
        await password_gate(update, context)
        return
    await handle_message(update, context)

async def approve_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌ Unauthorized. Owner only.")
        return
    if not is_authenticated(OWNER_ID):
        await update.effective_message.reply_text("🔐 Authenticate with /start and the password before using admin commands.")
        return
    try:
        target_id = int(context.args[0])
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("INSERT OR REPLACE INTO users (user_id, approved) VALUES (?, 1)", (target_id,))
        await update.message.reply_text(f"✅ User {target_id} approved.")
    except (IndexError, ValueError):
        await update.message.reply_text("Usage: /approve <user_id>")

async def revoke_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌ Unauthorized. Owner only.")
        return
    if not is_authenticated(OWNER_ID):
        await update.effective_message.reply_text("🔐 Authenticate with /start and the password before using admin commands.")
        return
    try:
        target_id = int(context.args[0])
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("UPDATE users SET approved = 0 WHERE user_id = ?", (target_id,))
        await update.message.reply_text(f"🚫 User {target_id} revoked.")
    except (IndexError, ValueError):
        await update.message.reply_text("Usage: /revoke <user_id>")

async def list_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌ Unauthorized. Owner only.")
        return
    if not is_authenticated(OWNER_ID):
        await update.effective_message.reply_text("🔐 Authenticate with /start and the password before using admin commands.")
        return
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE approved = 1")
        users = cursor.fetchall()
    user_list = "\n".join([str(u[0]) for u in users])
    await update.message.reply_text(f"👥 Approved Users:\n{user_list}")

async def deliver_response(update: Update, text: str):
    """Format common Markdown/LaTeX and deliver plain text within Telegram's limit."""
    text = format_response(text)
    for i in range(0, len(text), 4096):
        await update.effective_message.reply_text(text[i:i + 4096])

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await authorized_user_only(update, context): return
    
    text = update.message.text
    if not text: return
    if len(text) > MAX_INPUT:
        await update.message.reply_text("⚠️ Message too long.")
        return
    
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=constants.ChatAction.TYPING)
    increment_usage(update.effective_user.id)
    response_text = call_ollama(update.effective_user.id, text)
    await deliver_response(update, response_text)


def main():
    try:
        validate_config()
    except EnvironmentError as e:
        logger.error(f"Configuration Error: {e}")
        return

    init_db()
    request = HTTPXRequest(connect_timeout=30, read_timeout=45, write_timeout=30, pool_timeout=30)
    get_updates_request = HTTPXRequest(connect_timeout=30, read_timeout=45, write_timeout=30, pool_timeout=30)
    app = (ApplicationBuilder()
           .token(TOKEN)
           .request(request)
           .get_updates_request(get_updates_request)
           .build())
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("id", id_command))
    app.add_handler(CommandHandler("usage", usage_command))
    app.add_handler(CommandHandler("reset", reset_command))
    app.add_handler(CommandHandler("logout", logout_command))
    app.add_handler(CommandHandler("approve", approve_user))
    app.add_handler(CommandHandler("revoke", revoke_user))
    app.add_handler(CommandHandler("users", list_users))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_password_or_message))
    
    logger.info("J.A.R.V.I.S. is online...")
    app.run_polling()

if __name__ == "__main__":
    main()
