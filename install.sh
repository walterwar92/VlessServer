#!/bin/bash
# ============================================================
# VLESS+Reality VPN Server + Telegram Bot
# Ubuntu 24.04 | Xray-core | python-telegram-bot 20.x
# ============================================================
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log()   { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step()  { echo -e "\n${CYAN}>>> $1${NC}"; }

# ── Root check ──────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Запустите от root: sudo bash install.sh"

echo -e "${BLUE}"
cat << 'BANNER'
╔══════════════════════════════════════════════╗
║   VLESS + Reality  VPN  Server Installer     ║
║   Telegram Bot Management (Admin / User)     ║
╚══════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

# ── Collect inputs ───────────────────────────────────────────
read -rp "Telegram Bot Token (от @BotFather): " BOT_TOKEN
[[ -z "$BOT_TOKEN" ]] && error "Bot token обязателен"

read -rp "Ваш Telegram User ID (числовой): " ADMIN_TG_ID
[[ -z "$ADMIN_TG_ID" ]] && error "Admin ID обязателен"
[[ ! "$ADMIN_TG_ID" =~ ^[0-9]+$ ]] && error "ID должен быть числом"

while true; do
    read -rsp "Пароль администратора: " ADMIN_PASSWORD; echo
    read -rsp "Повторите пароль: "      ADMIN_PASSWORD2; echo
    [[ "$ADMIN_PASSWORD" == "$ADMIN_PASSWORD2" ]] && break
    warn "Пароли не совпадают, попробуйте снова"
done
[[ -z "$ADMIN_PASSWORD" ]] && error "Пароль не может быть пустым"

read -rp "VPN порт [443]: " VPN_PORT
VPN_PORT=${VPN_PORT:-443}

read -rp "SNI домен для Reality [www.microsoft.com]: " SNI_DOMAIN
SNI_DOMAIN=${SNI_DOMAIN:-www.microsoft.com}

# ── Auto-detect server IP ────────────────────────────────────
step "Определение IP-адреса сервера"
SERVER_IP=$(curl -s4 --max-time 10 ifconfig.me 2>/dev/null \
         || curl -s4 --max-time 10 api.ipify.org 2>/dev/null \
         || curl -s4 --max-time 10 icanhazip.com 2>/dev/null)
[[ -z "$SERVER_IP" ]] && read -rp "Не удалось определить IP. Введите вручную: " SERVER_IP
log "IP сервера: $SERVER_IP"

INSTALL_DIR="/opt/vless-bot"
XRAY_CONF="/usr/local/etc/xray/config.json"
mkdir -p "$INSTALL_DIR" /var/log/xray

# ── System update ────────────────────────────────────────────
step "Обновление системы"
apt-get update -q
apt-get upgrade -y -q
apt-get install -y -q \
    curl wget unzip jq python3 python3-pip python3-venv \
    openssl uuid-runtime net-tools ufw ca-certificates

# ── Install Xray-core ────────────────────────────────────────
step "Установка Xray-core"
if ! command -v xray &>/dev/null; then
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root
fi
log "Xray версия: $(xray version 2>&1 | head -1)"

# ── Generate Reality keys ────────────────────────────────────
step "Генерация ключей Reality"
XRAY_KEYS=$(xray x25519)
PRIVATE_KEY=$(echo "$XRAY_KEYS" | grep "Private key:" | awk '{print $3}')
PUBLIC_KEY=$(echo  "$XRAY_KEYS" | grep "Public key:"  | awk '{print $3}')
SHORT_ID=$(openssl rand -hex 8)
ADMIN_UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)

log "Private Key : $PRIVATE_KEY"
log "Public Key  : $PUBLIC_KEY"
log "Short ID    : $SHORT_ID"
log "Admin UUID  : $ADMIN_UUID"

# ── Write Xray config ────────────────────────────────────────
step "Конфигурация Xray (VLESS+Reality)"
cat > "$XRAY_CONF" << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error":  "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": ${VPN_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id":    "${ADMIN_UUID}",
            "flow":  "xtls-rprx-vision",
            "email": "admin"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show":        false,
          "dest":        "${SNI_DOMAIN}:443",
          "xver":        0,
          "serverNames": ["${SNI_DOMAIN}"],
          "privateKey":  "${PRIVATE_KEY}",
          "shortIds":    ["${SHORT_ID}"]
        }
      },
      "sniffing": {
        "enabled":     true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom",   "tag": "direct"  },
    { "protocol": "blackhole", "tag": "blocked" }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type":         "field",
        "ip":           ["geoip:private"],
        "outboundTag":  "blocked"
      }
    ]
  }
}
EOF

# ── Python virtual environment ───────────────────────────────
step "Настройка Python-окружения"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q \
    "python-telegram-bot==20.8" \
    "aiosqlite==0.20.0"

# ── Hash admin password (SHA-256) ────────────────────────────
ADMIN_PASS_HASH=$(python3 -c \
    "import hashlib; print(hashlib.sha256('${ADMIN_PASSWORD}'.encode()).hexdigest())")

# ── Write config.json ────────────────────────────────────────
cat > "$INSTALL_DIR/config.json" << EOF
{
  "bot_token":          "${BOT_TOKEN}",
  "admin_tg_id":        ${ADMIN_TG_ID},
  "admin_password_hash":"${ADMIN_PASS_HASH}",
  "server_ip":          "${SERVER_IP}",
  "vpn_port":           ${VPN_PORT},
  "sni_domain":         "${SNI_DOMAIN}",
  "public_key":         "${PUBLIC_KEY}",
  "short_id":           "${SHORT_ID}",
  "xray_config":        "${XRAY_CONF}",
  "install_dir":        "${INSTALL_DIR}",
  "db_path":            "${INSTALL_DIR}/vpn.db"
}
EOF

# ── Write bot.py ─────────────────────────────────────────────
step "Создание Telegram-бота"
cat > "$INSTALL_DIR/bot.py" << 'PYEOF'
#!/usr/bin/env python3
"""
VLESS+Reality VPN Telegram Bot
Roles: admin (full access) | user (keys + status)
"""
import asyncio
import hashlib
import json
import logging
import subprocess
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import aiosqlite
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    BotCommand,
)
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ConversationHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ── Config ───────────────────────────────────────────────────
CFG_PATH = Path("/opt/vless-bot/config.json")
with CFG_PATH.open() as _f:
    CFG = json.load(_f)

BOT_TOKEN    = CFG["bot_token"]
ADMIN_TG_ID  = int(CFG["admin_tg_id"])
PASS_HASH    = CFG["admin_password_hash"]
SERVER_IP    = CFG["server_ip"]
VPN_PORT     = CFG["vpn_port"]
SNI_DOMAIN   = CFG["sni_domain"]
PUBLIC_KEY   = CFG["public_key"]
SHORT_ID     = CFG["short_id"]
XRAY_CONFIG  = CFG["xray_config"]
DB_PATH      = CFG["db_path"]

# ── Logging ──────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("vless-bot")

# ── Conversation states ──────────────────────────────────────
WAIT_PASS = 1

# ═══════════════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════════════

async def db_init():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER UNIQUE NOT NULL,
                username    TEXT,
                first_name  TEXT,
                role        TEXT    DEFAULT 'user',
                is_active   INTEGER DEFAULT 1,
                created_at  TEXT    DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS vpn_keys (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id),
                uuid       TEXT    UNIQUE NOT NULL,
                label      TEXT,
                is_active  INTEGER DEFAULT 1,
                created_at TEXT    DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS invite_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                token      TEXT    UNIQUE NOT NULL,
                created_by INTEGER NOT NULL REFERENCES users(id),
                used_by    INTEGER REFERENCES users(id),
                is_used    INTEGER DEFAULT 0,
                created_at TEXT    DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
                telegram_id    INTEGER PRIMARY KEY,
                authenticated  INTEGER DEFAULT 0,
                authenticated_at TEXT
            );
        """)
        await db.commit()


async def db_get_user(tg_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE telegram_id=?", (tg_id,)
        ) as c:
            return await c.fetchone()


async def db_all_users():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users ORDER BY created_at DESC"
        ) as c:
            return await c.fetchall()


async def db_create_user(tg_id: int, username: str, first_name: str,
                          role: str = "user") -> str:
    """Insert user + generate first VPN key. Returns new UUID."""
    new_uuid = str(uuid.uuid4())
    label = f"Key-{first_name}"
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO users (telegram_id, username, first_name, role) VALUES (?,?,?,?)",
            (tg_id, username, first_name, role),
        )
        row = await db.execute("SELECT last_insert_rowid()")
        user_id = (await row.fetchone())[0]
        await db.execute(
            "INSERT INTO vpn_keys (user_id, uuid, label) VALUES (?,?,?)",
            (user_id, new_uuid, label),
        )
        await db.commit()
    await xray_add_client(new_uuid, f"user_{tg_id}")
    return new_uuid


async def db_get_active_keys(tg_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT vk.* FROM vpn_keys vk
               JOIN users u ON vk.user_id = u.id
               WHERE u.telegram_id=? AND vk.is_active=1""",
            (tg_id,),
        ) as c:
            return await c.fetchall()


async def db_reissue_key(tg_id: int) -> str:
    """Revoke old key(s) and create a new one. Returns new UUID."""
    new_uuid = str(uuid.uuid4())
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        async with db.execute(
            """SELECT vk.uuid FROM vpn_keys vk
               JOIN users u ON vk.user_id = u.id
               WHERE u.telegram_id=? AND vk.is_active=1""",
            (tg_id,),
        ) as c:
            old_keys = await c.fetchall()

        for k in old_keys:
            await xray_remove_client(k["uuid"])
            await db.execute(
                "UPDATE vpn_keys SET is_active=0 WHERE uuid=?", (k["uuid"],)
            )

        async with db.execute(
            "SELECT id, first_name FROM users WHERE telegram_id=?", (tg_id,)
        ) as c:
            user = await c.fetchone()

        await db.execute(
            "INSERT INTO vpn_keys (user_id, uuid, label) VALUES (?,?,?)",
            (user["id"], new_uuid, f"Key-{user['first_name']}"),
        )
        await db.commit()

    await xray_add_client(new_uuid, f"user_{tg_id}")
    return new_uuid


async def db_revoke_user(tg_id: int):
    """Deactivate user and all their keys."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT vk.uuid FROM vpn_keys vk
               JOIN users u ON vk.user_id = u.id
               WHERE u.telegram_id=? AND vk.is_active=1""",
            (tg_id,),
        ) as c:
            keys = await c.fetchall()

        for k in keys:
            await xray_remove_client(k["uuid"])

        await db.execute(
            """UPDATE vpn_keys SET is_active=0
               WHERE user_id=(SELECT id FROM users WHERE telegram_id=?)""",
            (tg_id,),
        )
        await db.execute(
            "UPDATE users SET is_active=0 WHERE telegram_id=?", (tg_id,)
        )
        await db.commit()


async def db_create_invite(admin_tg_id: int) -> str:
    token = str(uuid.uuid4())[:8].upper()
    expires = (datetime.now() + timedelta(days=7)).isoformat(timespec="seconds")
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id FROM users WHERE telegram_id=?", (admin_tg_id,)
        ) as c:
            admin = await c.fetchone()
        await db.execute(
            "INSERT INTO invite_tokens (token, created_by, expires_at) VALUES (?,?,?)",
            (token, admin["id"], expires),
        )
        await db.commit()
    return token


async def db_use_invite(token: str, tg_id: int,
                         username: str, first_name: str):
    """Return (uuid, error_str). error_str is None on success."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM invite_tokens WHERE token=? AND is_used=0", (token,)
        ) as c:
            inv = await c.fetchone()

        if not inv:
            return None, "Инвайт не найден или уже использован"
        if datetime.fromisoformat(inv["expires_at"]) < datetime.now():
            return None, "Инвайт просрочен"

    new_uuid = await db_create_user(tg_id, username, first_name)

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id FROM users WHERE telegram_id=?", (tg_id,)
        ) as c:
            new_user = await c.fetchone()
        await db.execute(
            "UPDATE invite_tokens SET is_used=1, used_by=? WHERE token=?",
            (new_user["id"], token),
        )
        await db.commit()

    return new_uuid, None


# ── Admin session ────────────────────────────────────────────

async def admin_is_auth(tg_id: int) -> bool:
    if tg_id != ADMIN_TG_ID:
        return False
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT authenticated FROM admin_sessions WHERE telegram_id=?",
            (tg_id,),
        ) as c:
            row = await c.fetchone()
            return bool(row and row[0])


async def admin_set_auth(tg_id: int, val: bool):
    ts = datetime.now().isoformat(timespec="seconds")
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO admin_sessions (telegram_id, authenticated, authenticated_at)
               VALUES (?,?,?)
               ON CONFLICT(telegram_id) DO UPDATE SET
                 authenticated=excluded.authenticated,
                 authenticated_at=excluded.authenticated_at""",
            (tg_id, 1 if val else 0, ts),
        )
        await db.commit()


# ═══════════════════════════════════════════════════════════════
#  XRAY MANAGEMENT
# ═══════════════════════════════════════════════════════════════

def _xray_reload():
    """Restart xray to pick up config changes."""
    subprocess.run(["systemctl", "restart", "xray"],
                   capture_output=True, check=False)


async def xray_add_client(client_uuid: str, email: str):
    try:
        with open(XRAY_CONFIG) as f:
            cfg = json.load(f)
        clients = cfg["inbounds"][0]["settings"]["clients"]
        if not any(c["id"] == client_uuid for c in clients):
            clients.append({
                "id":    client_uuid,
                "flow":  "xtls-rprx-vision",
                "email": email,
            })
        with open(XRAY_CONFIG, "w") as f:
            json.dump(cfg, f, indent=2)
        _xray_reload()
    except Exception as e:
        logger.error("xray_add_client error: %s", e)


async def xray_remove_client(client_uuid: str):
    try:
        with open(XRAY_CONFIG) as f:
            cfg = json.load(f)
        cfg["inbounds"][0]["settings"]["clients"] = [
            c for c in cfg["inbounds"][0]["settings"]["clients"]
            if c["id"] != client_uuid
        ]
        with open(XRAY_CONFIG, "w") as f:
            json.dump(cfg, f, indent=2)
        _xray_reload()
    except Exception as e:
        logger.error("xray_remove_client error: %s", e)


# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════

def make_vless_link(client_uuid: str, tag: str) -> str:
    return (
        f"vless://{client_uuid}@{SERVER_IP}:{VPN_PORT}"
        f"?encryption=none&security=reality"
        f"&sni={SNI_DOMAIN}&fp=chrome"
        f"&pbk={PUBLIC_KEY}&sid={SHORT_ID}"
        f"&type=tcp&flow=xtls-rprx-vision"
        f"#{tag}"
    )


def get_server_status() -> str:
    # Xray active?
    r = subprocess.run(["systemctl", "is-active", "xray"],
                       capture_output=True, text=True)
    xray_st = r.stdout.strip()
    emoji = "🟢" if xray_st == "active" else "🔴"

    # Uptime
    up = subprocess.run(["uptime", "-p"], capture_output=True, text=True)
    uptime = up.stdout.strip()

    # Load average
    with open("/proc/loadavg") as f:
        la = f.read().split()[:3]
    load = " / ".join(la)

    # Memory
    mem = subprocess.run(["free", "-h"], capture_output=True, text=True)
    mem_line = mem.stdout.split("\n")[1].split()
    ram_used  = mem_line[2] if len(mem_line) > 2 else "?"
    ram_total = mem_line[1] if len(mem_line) > 1 else "?"

    return (
        f"📊 *Статус сервера*\n\n"
        f"{emoji} Xray: `{xray_st}`\n"
        f"⏱ Uptime: `{uptime}`\n"
        f"📈 Load: `{load}`\n"
        f"💾 RAM: `{ram_used} / {ram_total}`\n"
        f"🌐 IP: `{SERVER_IP}:{VPN_PORT}`\n"
        f"🔒 SNI: `{SNI_DOMAIN}`"
    )


# ═══════════════════════════════════════════════════════════════
#  KEYBOARDS
# ═══════════════════════════════════════════════════════════════

def kb_admin():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("👥 Пользователи",    callback_data="adm_users"),
            InlineKeyboardButton("🔗 Создать инвайт",  callback_data="adm_invite"),
        ],
        [
            InlineKeyboardButton("📊 Статус сервера",  callback_data="srv_status"),
            InlineKeyboardButton("🚫 Отозвать доступ", callback_data="adm_revoke"),
        ],
        [
            InlineKeyboardButton("🔑 Мои ключи",       callback_data="my_keys"),
            InlineKeyboardButton("🔄 Перевыпустить",   callback_data="reissue_confirm"),
        ],
        [InlineKeyboardButton("🚪 Выйти", callback_data="adm_logout")],
    ])


def kb_user():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔑 Мои ключи",         callback_data="my_keys")],
        [InlineKeyboardButton("🔄 Перевыпустить ключ", callback_data="reissue_ask")],
        [InlineKeyboardButton("📊 Статус сервера",     callback_data="srv_status")],
    ])


def kb_back(target="main"):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔙 Назад", callback_data=f"back_{target}")]
    ])


def kb_confirm_reissue():
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ Да, перевыпустить", callback_data="reissue_confirm"),
            InlineKeyboardButton("❌ Отмена",             callback_data="back_main"),
        ]
    ])


# ═══════════════════════════════════════════════════════════════
#  HANDLERS
# ═══════════════════════════════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    tg_id = user.id
    args  = ctx.args or []

    # ── Admin flow ──
    if tg_id == ADMIN_TG_ID:
        if await admin_is_auth(tg_id):
            db_user = await db_get_user(tg_id)
            if not db_user:
                await db_create_user(tg_id, user.username or "", user.first_name, "admin")
            await update.message.reply_text(
                f"👑 *Панель администратора*\n\nДобро пожаловать, {user.first_name}!",
                parse_mode="Markdown",
                reply_markup=kb_admin(),
            )
        else:
            await update.message.reply_text(
                "🔐 Введите пароль администратора:"
            )
            return WAIT_PASS
        return ConversationHandler.END

    # ── User flow ──
    db_user = await db_get_user(tg_id)

    if db_user:
        if not db_user["is_active"]:
            await update.message.reply_text("❌ Ваш аккаунт заблокирован. Обратитесь к администратору.")
            return ConversationHandler.END
        await update.message.reply_text(
            f"👋 Привет, *{user.first_name}*!\n\n🔑 Управление VPN-подключением",
            parse_mode="Markdown",
            reply_markup=kb_user(),
        )
        return ConversationHandler.END

    # New user — needs invite
    if args:
        token = args[0]
        new_uuid, err = await db_use_invite(
            token, tg_id, user.username or "", user.first_name
        )
        if err:
            await update.message.reply_text(f"❌ {err}")
        else:
            link = make_vless_link(new_uuid, user.first_name)
            await update.message.reply_text(
                f"✅ *Аккаунт создан!*\n\n"
                f"🔑 Ваш VLESS-ключ:\n`{link}`\n\n"
                f"Импортируйте его в v2rayNG / Hiddify / NekoBox.",
                parse_mode="Markdown",
                reply_markup=kb_user(),
            )
    else:
        await update.message.reply_text(
            "👋 Привет!\n\n"
            "Для доступа к VPN вам нужна *инвайт-ссылка* от администратора.\n"
            "Получите её и перейдите по ней.",
            parse_mode="Markdown",
        )
    return ConversationHandler.END


async def wait_password(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    tg_id = update.effective_user.id
    user  = update.effective_user
    entered_hash = hashlib.sha256(update.message.text.encode()).hexdigest()

    if entered_hash == PASS_HASH:
        await admin_set_auth(tg_id, True)
        db_user = await db_get_user(tg_id)
        if not db_user:
            await db_create_user(tg_id, user.username or "", user.first_name, "admin")
        await update.message.reply_text(
            "✅ *Аутентификация прошла успешно!*\n\n👑 Добро пожаловать, Администратор!",
            parse_mode="Markdown",
            reply_markup=kb_admin(),
        )
        return ConversationHandler.END
    else:
        await update.message.reply_text("❌ Неверный пароль.\n\nПопробуйте снова:")
        return WAIT_PASS


async def cmd_logout(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    tg_id = update.effective_user.id
    if tg_id == ADMIN_TG_ID:
        await admin_set_auth(tg_id, False)
        await update.message.reply_text("🚪 Вы вышли из панели администратора.")


# ── Callback router ──────────────────────────────────────────

async def on_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    user = update.effective_user

    # ── back_main ──
    if data == "back_main":
        if user.id == ADMIN_TG_ID and await admin_is_auth(user.id):
            await query.edit_message_text(
                "👑 *Панель администратора*", parse_mode="Markdown",
                reply_markup=kb_admin()
            )
        else:
            await query.edit_message_text(
                "🔑 Управление VPN", reply_markup=kb_user()
            )
        return

    # ── Server status (available to all) ──
    if data == "srv_status":
        txt = get_server_status()
        await query.edit_message_text(
            txt, parse_mode="Markdown", reply_markup=kb_back()
        )
        return

    # ── My keys (available to all) ──
    if data == "my_keys":
        keys = await db_get_active_keys(user.id)
        if keys:
            lines = []
            for k in keys:
                link = make_vless_link(k["uuid"], k["label"] or "VPN")
                lines.append(f"*{k['label']}*\n`{link}`")
            txt = "🔑 *Ваши активные ключи:*\n\n" + "\n\n".join(lines)
        else:
            txt = "❌ У вас нет активных ключей."
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=kb_back())
        return

    # ── Reissue (ask confirmation) ──
    if data == "reissue_ask":
        await query.edit_message_text(
            "⚠️ *Перевыпуск ключа*\n\n"
            "Старый ключ будет немедленно аннулирован.\n"
            "Продолжить?",
            parse_mode="Markdown",
            reply_markup=kb_confirm_reissue(),
        )
        return

    # ── Reissue (confirm) ──
    if data == "reissue_confirm":
        db_user = await db_get_user(user.id)
        if not db_user or not db_user["is_active"]:
            await query.edit_message_text("❌ Аккаунт не найден или заблокирован.")
            return
        new_uuid = await db_reissue_key(user.id)
        link = make_vless_link(new_uuid, user.first_name)
        await query.edit_message_text(
            f"✅ *Ключ перевыпущен!*\n\n🔑 Новый ключ:\n`{link}`",
            parse_mode="Markdown",
            reply_markup=kb_back(),
        )
        return

    # ══════════════════════════════════════════
    # ADMIN-ONLY callbacks (require auth)
    # ══════════════════════════════════════════
    if user.id != ADMIN_TG_ID or not await admin_is_auth(user.id):
        await query.edit_message_text("❌ Доступ запрещён.")
        return

    # ── Admin: list users ──
    if data == "adm_users":
        users = await db_all_users()
        if not users:
            txt = "👥 Пользователей нет."
        else:
            lines = []
            for u in users:
                st   = "✅" if u["is_active"] else "🚫"
                role = "👑" if u["role"] == "admin" else "👤"
                uname = f"@{u['username']}" if u["username"] else "—"
                lines.append(
                    f"{st}{role} *{u['first_name']}* ({uname})\n"
                    f"   ID: `{u['telegram_id']}` | {u['created_at'][:10]}"
                )
            txt = "👥 *Список пользователей:*\n\n" + "\n\n".join(lines)
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=kb_back())
        return

    # ── Admin: create invite ──
    if data == "adm_invite":
        token = await db_create_invite(user.id)
        bot_me = await ctx.bot.get_me()
        link = f"https://t.me/{bot_me.username}?start={token}"
        await query.edit_message_text(
            f"🔗 *Инвайт-ссылка создана*\n\n"
            f"Ссылка:\n{link}\n\n"
            f"Токен: `{token}`\n"
            f"⏰ Действует 7 дней",
            parse_mode="Markdown",
            reply_markup=kb_back(),
        )
        return

    # ── Admin: revoke user (step 1 — ask ID) ──
    if data == "adm_revoke":
        ctx.user_data["awaiting"] = "revoke_id"
        await query.edit_message_text(
            "🚫 *Отзыв доступа*\n\n"
            "Введите Telegram ID пользователя (число).\n"
            "Получить ID можно из списка пользователей 👥",
            parse_mode="Markdown",
            reply_markup=kb_back(),
        )
        return

    # ── Admin: logout ──
    if data == "adm_logout":
        await admin_set_auth(user.id, False)
        await query.edit_message_text(
            "🚪 Вы вышли из панели администратора.\n"
            "Для входа используйте /start"
        )
        return


# ── Text message handler (for admin input flows) ─────────────

async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user

    if user.id == ADMIN_TG_ID and await admin_is_auth(user.id):
        awaiting = ctx.user_data.get("awaiting")

        if awaiting == "revoke_id":
            ctx.user_data.pop("awaiting", None)
            text = update.message.text.strip()
            try:
                target_id = int(text)
            except ValueError:
                await update.message.reply_text(
                    "❌ Введите числовой Telegram ID.",
                    reply_markup=kb_admin(),
                )
                return

            target = await db_get_user(target_id)
            if not target:
                await update.message.reply_text(
                    "❌ Пользователь не найден.",
                    reply_markup=kb_admin(),
                )
                return

            if target_id == ADMIN_TG_ID:
                await update.message.reply_text(
                    "❌ Нельзя заблокировать администратора.",
                    reply_markup=kb_admin(),
                )
                return

            await db_revoke_user(target_id)
            await update.message.reply_text(
                f"✅ Доступ пользователя *{target['first_name']}* (`{target_id}`) отозван.",
                parse_mode="Markdown",
                reply_markup=kb_admin(),
            )
            return

    # Unrecognized message
    db_user = await db_get_user(user.id)
    if db_user and db_user["is_active"]:
        if user.id == ADMIN_TG_ID and await admin_is_auth(user.id):
            await update.message.reply_text("Используйте кнопки меню:", reply_markup=kb_admin())
        else:
            await update.message.reply_text("Используйте кнопки меню:", reply_markup=kb_user())


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

async def post_init(app: Application):
    await db_init()
    logger.info("Database initialised at %s", DB_PATH)
    await app.bot.set_my_commands([
        BotCommand("start",  "Запустить / войти"),
        BotCommand("logout", "Выйти (только для админа)"),
    ])


def main():
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .post_init(post_init)
        .build()
    )

    conv = ConversationHandler(
        entry_points=[CommandHandler("start", cmd_start)],
        states={
            WAIT_PASS: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, wait_password)
            ],
        },
        fallbacks=[CommandHandler("start", cmd_start)],
        allow_reentry=True,
    )

    app.add_handler(conv)
    app.add_handler(CommandHandler("logout", cmd_logout))
    app.add_handler(CallbackQueryHandler(on_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    logger.info("Bot polling started")
    app.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
PYEOF

# ── Systemd service for bot ──────────────────────────────────
step "Создание systemd-сервисов"

cat > /etc/systemd/system/vless-bot.service << EOF
[Unit]
Description=VLESS VPN Telegram Bot
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/bot.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# ── Firewall ─────────────────────────────────────────────────
step "Настройка файрвола (UFW)"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow ssh comment "SSH" >/dev/null
ufw allow "${VPN_PORT}/tcp" comment "VLESS Reality" >/dev/null
echo "y" | ufw enable >/dev/null
log "UFW настроен: SSH + ${VPN_PORT}/tcp открыты"

# ── Start services ───────────────────────────────────────────
step "Запуск сервисов"
systemctl daemon-reload

systemctl enable xray   --quiet
systemctl restart xray  || warn "Не удалось запустить xray, проверьте журнал"

systemctl enable vless-bot  --quiet
systemctl restart vless-bot || warn "Не удалось запустить vless-bot"

sleep 2
XRAY_STATUS=$(systemctl is-active xray)
BOT_STATUS=$(systemctl is-active vless-bot)

# ── Kernel tuning for low-latency / high throughput ──────────
step "Оптимизация сетевого стека"
cat > /etc/sysctl.d/99-vless.conf << 'SYSCTL'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
SYSCTL
sysctl -p /etc/sysctl.d/99-vless.conf >/dev/null 2>&1 || true

# ── Summary ──────────────────────────────────────────────────
VLESS_LINK="vless://${ADMIN_UUID}@${SERVER_IP}:${VPN_PORT}?encryption=none&security=reality&sni=${SNI_DOMAIN}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&type=tcp&flow=xtls-rprx-vision#Admin-VPN"

echo
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              УСТАНОВКА ЗАВЕРШЕНА                         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${GREEN}Сервер${NC}"
echo "  IP-адрес  : $SERVER_IP"
echo "  Порт      : $VPN_PORT"
echo "  SNI       : $SNI_DOMAIN"
echo
echo -e "${GREEN}Reality ключи${NC}"
echo "  Public Key : $PUBLIC_KEY"
echo "  Short ID   : $SHORT_ID"
echo
echo -e "${GREEN}Статус сервисов${NC}"
[ "$XRAY_STATUS"  = "active" ] && echo -e "  Xray      : ${GREEN}●${NC} active" || echo -e "  Xray      : ${RED}●${NC} $XRAY_STATUS"
[ "$BOT_STATUS"   = "active" ] && echo -e "  Bot       : ${GREEN}●${NC} active" || echo -e "  Bot       : ${RED}●${NC} $BOT_STATUS"
echo
echo -e "${GREEN}Ваш VLESS-ключ (админ)${NC}"
echo "$VLESS_LINK"
echo
echo -e "${YELLOW}Команды управления${NC}"
echo "  journalctl -fu vless-bot   — логи бота"
echo "  journalctl -fu xray        — логи xray"
echo "  systemctl restart vless-bot"
echo "  systemctl restart xray"
echo
echo -e "${CYAN}Telegram-бот: откройте бота и введите /start${NC}"
echo -e "${CYAN}Пароль администратора задан при установке${NC}"
echo
echo -e "${GREEN}Конфиги сохранены в: ${INSTALL_DIR}/${NC}"
