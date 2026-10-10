# J.A.R.V.I.S. — Personal AI Assistant Telegram Bot

J.A.R.V.I.S. is a **text-only** Telegram AI assistant powered by Ollama. It is designed for private use, featuring a robust authentication system and mathematical response formatting for better readability on Telegram.

## 🚀 Features

- **AI Conversations**: Powered by Ollama (local or cloud).
- **Dual-Layer Security**: Requires both owner-approved Telegram ID and a shared password.
- **Persistence**: SQLite database for user approvals, authenticated sessions, failed-login cooldowns, and daily usage.
- **Memory Management**: Per-user conversation contexts with a `/reset` command.
- **Usage Control**: Daily message quotas to prevent API abuse.
- **Math Formatting**: Automatically converts LaTeX and Markdown math notation into readable plain text symbols (e.g., `\pi` → `π`, `\frac{a}{b}` → `a / (b)`), as Telegram does not natively render LaTeX.
- **Admin Tools**: Owner-only commands for user management.

## 🛠️ Setup & Installation

### 1. Telegram Bot Setup
1. Message **@BotFather** on Telegram to create your bot.
2. Copy the **API Token** and paste it into `TELEGRAM_BOT_TOKEN` in your `.env` file.
3. To find your **Owner ID**: Use a bot like `@userinfobot` or use J.A.R.V.I.S.'s own `/id` command after starting the bot. Paste this numeric ID into `OWNER_TELEGRAM_ID`.

### 2. AI Configuration (Ollama)
- **Local Setup**: Install Ollama on your machine and ensure the service is running on port 11434.
- **Cloud Setup**: Set `OLLAMA_BASE_URL` to your cloud endpoint.
- **API Key**: If your provider requires authentication, add it to `OLLAMA_API_KEY`.

### 3. Installation
1. Clone the repository.
2. Install dependencies: `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and configure your variables.
4. Generate the password hash (see **Authentication** section below).
5. Run the bot: `python bot.py`

## 🔐 Authentication & User Management

The bot uses a **Whitelisting Model**. A user must satisfy **both** conditions to access AI features:
1. **ID Approval**: Their numeric Telegram ID must be approved by the owner via `/approve <user_id>`.
2. **Password**: They must send the shared password as a private message.

### Generating the Password Hash
The shared password is stored as a PBKDF2-SHA256 hash. **Never store the password in plaintext.** Use this script to generate your hash:

```bash
python - <<'PY'
import os, hashlib, getpass
password = getpass.getpass('J.A.R.V.I.S. access password: ').encode()
salt = os.urandom(16)
iterations = 260000
digest = hashlib.pbkdf2_hmac('sha256', password, salt, iterations)
print(f'pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}')
PY
```
Copy the output and paste it into `JARVIS_PASSWORD_HASH` in your `.env` file.

## 💻 Deployment

### Local Execution
```bash
python bot.py
```

### Persistent Deployment (VPS/Linux)
To keep the bot running 24/7, use **Systemd**:
1. Create a service file: `sudo nano /etc/systemd/system/jarvis.service`
2. Add the following configuration:
   ```ini
   [Unit]
   Description=JARVIS Telegram Bot
   After=network.target

   [Service]
   User=yourusername
   WorkingDirectory=/path/to/jarvis-telegram-bot
   ExecStart=/usr/bin/python3 bot.py
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```
3. Start and enable the service:
   ```bash
   sudo systemctl enable --now jarvis
   ```

### BotHost Deployment
If using BotHost or similar PaaS, simply set the environment variables in their dashboard and use `python bot.py` as the start command.

## ⌨️ Commands

| Command | Description | Access |
|---|---|---|
| `/start` | Introduction & Authentication | All |
| `/help` | Show this menu | Authenticated |
| `/id` | Get your numeric Telegram ID | Authenticated |
| `/usage` | Check daily AI usage | Authenticated |
| `/reset` | Clear conversation memory | Authenticated |
| `/logout` | End current session | All |
| `/approve <id>` | Approve a Telegram account | Owner Only |
| `/revoke <id>` | Revoke an account | Owner Only |
| `/users` | List all approved IDs | Owner Only |

## ⚙️ Environment Variables

| Variable | Purpose | Default / Example |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token from BotFather | *Required* |
| `OWNER_TELEGRAM_ID` | Owner's numeric Telegram ID | *Required* |
| `JARVIS_PASSWORD_HASH` | PBKDF2-SHA256 hash of shared password | *Required* |
| `OLLAMA_BASE_URL` | Ollama API base URL | `http://localhost:11434` |
| `OLLAMA_API_KEY` | Ollama API key (if required) | `optional` |
| `OLLAMA_MODEL` | Model identifier | `llama3` |
| `DAILY_MESSAGE_LIMIT` | Daily AI message limit | `100` |
| `REQUEST_TIMEOUT` | Ollama request timeout (sec) | `30` |
| `MAX_INPUT_LENGTH` | Maximum input length (chars) | `2000` |
| `AUTH_MAX_ATTEMPTS` | Max failed login attempts | `5` |
| `AUTH_COOLDOWN_SECONDS` | Login cooldown period (sec) | `300` |

---
**Security Warning:** Keep your `.env` file private. Never commit tokens, API keys, or password hashes to GitHub.
