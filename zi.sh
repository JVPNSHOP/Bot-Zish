#!/usr/bin/env bash
# install_zivpn_public_notify.sh
# Public ZIVPN + Telegram bot installer
# Public mode (everyone can create/list/renew/delete) + admin notifications
set -euo pipefail
IFS=$'\n\t'

### ===== CONFIG - edit if you want BEFORE running =====
BOT_TOKEN_DEFAULT="8409119937:AAGsRoqiyg-U_caPKsDUpnhzMN8SyG5Y0qw"
# For public mode ADMIN_IDS left empty by default (comma separated list allowed)
ADMIN_IDS_DEFAULT=""
ZIVPN_SERVER_IP_DEFAULT="$(curl -s https://ifconfig.co || echo "your.server.ip")"
### =====================================================

echo "== ZIVPN + Telegram Bot (PUBLIC MODE, notify admins) Installer =="
echo "Running as: $(whoami) on $(hostname)"
sleep 1

# 1) system packages
echo "-- Installing system packages --"
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install -y wget curl openssl python3 python3-venv python3-pip ufw iptables sqlite3 jq

# 2) install zivpn binary + config
echo "-- Installing ZIVPN binary and default config --"
sudo systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true
sudo wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn
sudo chmod +x /usr/local/bin/zivpn
sudo mkdir -p /etc/zivpn

if ! sudo wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json; then
  echo '{"config":["zi"], "listen":"0.0.0.0:5667"}' | sudo tee /etc/zivpn/config.json >/dev/null
fi

sudo openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=ZIVPN/OU=IT/CN=zivpn" \
  -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt >/dev/null 2>&1 || true

sudo sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sudo sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

# systemd unit for zivpn
sudo tee /etc/systemd/system/zivpn.service > /dev/null <<'UNIT'
[Unit]
Description=zivpn VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now zivpn.service

# 3) firewall / iptables
NETIF=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || echo "eth0")
echo "-- Configuring firewall/iptables for interface ${NETIF} --"
sudo iptables -t nat -A PREROUTING -i "${NETIF}" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
sudo ufw allow 6000:19999/udp || true
sudo ufw allow 5667/udp || true

# 4) helper create script
echo "-- Creating helper /usr/local/bin/create_vpn_user.sh --"
sudo tee /usr/local/bin/create_vpn_user.sh > /dev/null <<'BASH'
#!/usr/bin/env bash
# /usr/local/bin/create_vpn_user.sh <username> <days> [password]
set -euo pipefail
USERNAME="${1:-}"
DAYS="${2:-7}"
PASSWORD_ARG="${3:-}"

if [ -z "$USERNAME" ]; then
  echo "ERROR: username required" >&2
  exit 2
fi

if ! [[ "$DAYS" =~ ^[0-9]+$ ]]; then
  DAYS=7
fi

if [ -n "$PASSWORD_ARG" ]; then
  PASSWORD="$PASSWORD_ARG"
else
  PASSWORD=$(tr -dc 'A-Za-z0-9!@#$%_-' </dev/urandom | head -c12 || echo "zi$(date +%s)")
fi

EXPIRES=$(date -d "+${DAYS} days" +%F 2>/dev/null || echo "$(date +%F)")
CFG_FILE="/etc/zivpn/config.json"
TMP="$(mktemp)"

if [ ! -f "$CFG_FILE" ]; then
  echo '{"config":["zi"], "listen":"0.0.0.0:5667"}' > "$CFG_FILE"
fi

python3 - <<PY
import json, sys
f="$CFG_FILE"
out="$TMP"
with open(f,'r') as fh:
    try:
        j=json.load(fh)
    except:
        j={}
arr=j.get("config",[])
if "$PASSWORD" not in arr:
    arr.append("$PASSWORD")
j["config"]=arr
with open(out,'w') as fo:
    json.dump(j, fo, indent=2)
print("PASSWORD:%s EXPIRES:%s" % ("$PASSWORD", "$EXPIRES"))
PY

if [ -f "$TMP" ]; then
  sudo mv "$TMP" "$CFG_FILE"
fi

# output line consumed by bot
echo "PASSWORD:${PASSWORD} EXPIRES:${EXPIRES}"
exit 0
BASH

sudo chmod +x /usr/local/bin/create_vpn_user.sh

# 5) python venv + deps
echo "-- Creating bot venv and installing python deps --"
sudo mkdir -p /opt/zivpn_bot
sudo chown "$(whoami):$(whoami)" /opt/zivpn_bot

python3 -m venv /opt/zivpn_bot/venv
/opt/zivpn_bot/venv/bin/pip install --upgrade pip >/dev/null
/opt/zivpn_bot/venv/bin/pip install python-telegram-bot==20.3 >/dev/null

# 6) sqlite DB
echo "-- Creating accounts DB --"
sudo mkdir -p /var/lib/zivpn_bot
sudo chown "$(whoami):$(whoami)" /var/lib/zivpn_bot
sqlite3 /var/lib/zivpn_bot/accounts.db <<'SQL'
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  created_by INTEGER,
  created_at TEXT,
  expires_at TEXT,
  revoked INTEGER DEFAULT 0
);
SQL

# 7) write env file
echo "-- Writing /etc/default/zivpn_bot --"
sudo tee /etc/default/zivpn_bot > /dev/null <<EOF
# BOT environment for zivpn_bot
BOT_TOKEN="${BOT_TOKEN_DEFAULT}"
ADMIN_IDS="${ADMIN_IDS_DEFAULT}"
ZIVPN_SERVER_IP="${ZIVPN_SERVER_IP_DEFAULT}"
EOF

sudo chmod 644 /etc/default/zivpn_bot
sudo chown root:root /etc/default/zivpn_bot

# 8) bot script (public + notify)
echo "-- Writing bot script to /opt/zivpn_bot/bot.py --"
sudo tee /opt/zivpn_bot/bot.py > /dev/null <<'PY'
#!/usr/bin/env python3
# bot.py - Public ZIVPN bot with admin notifications
import os, sqlite3, subprocess, datetime, json, logging, asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, constants
from telegram.ext import ApplicationBuilder, CommandHandler, ConversationHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

ENV_FILE="/etc/default/zivpn_bot"
DB_PATH="/var/lib/zivpn_bot/accounts.db"
CREATE_SCRIPT="/usr/local/bin/create_vpn_user.sh"

STATE_USERNAME, STATE_PASSWORD, STATE_EXPIRY, STATE_RENEW = range(4)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("zivpn_bot")

def load_env():
    env={}
    try:
        with open(ENV_FILE,'r') as f:
            for ln in f:
                ln=ln.strip()
                if not ln or ln.startswith('#') or '=' not in ln:
                    continue
                k,v = ln.split('=',1)
                v=v.strip().strip('"').strip("'")
                env[k.strip()]=v
    except Exception as e:
        logger.error("load_env error: %s", e)
    return env

env = load_env()
BOT_TOKEN = env.get("BOT_TOKEN")
ADMIN_IDS_RAW = env.get("ADMIN_IDS","")
ADMIN_IDS = []
for x in ADMIN_IDS_RAW.split(","):
    x = x.strip()
    if x:
        try:
            ADMIN_IDS.append(int(x))
        except:
            pass
ZIVPN_SERVER_IP = env.get("ZIVPN_SERVER_IP","your.server.ip")

logger.info("Started zivpn public bot (notify admins=%s)", ADMIN_IDS)

if not BOT_TOKEN:
    logger.error("BOT_TOKEN missing in %s", ENV_FILE)
    raise SystemExit(1)

def days_left(expiry_iso:str)->int:
    try:
        exp = datetime.datetime.fromisoformat(expiry_iso).date()
        left = (exp - datetime.date.today()).days
        return max(left, 0)
    except:
        return 0

def user_online(password:str)->bool:
    try:
        with open("/etc/zivpn/config.json",'r') as fh:
            j=json.load(fh)
        arr=j.get("config",[])
        return password in arr
    except:
        return False

def run_create_script(username:str, days:int, password:str=None):
    cmd = [CREATE_SCRIPT, username, str(days)]
    if password:
        cmd.append(password)
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        raise RuntimeError(res.stderr or res.stdout or "create script failed")
    out = res.stdout.strip()
    pw, exp = None, None
    for token in out.split():
        if ":" in token:
            k,v = token.split(":",1)
            if k.lower()=="password": pw = v
            if k.lower()=="expires": exp = v
    return pw, exp

async def notify_admins(app, text):
    # send notification to ADMIN_IDS if any
    if not ADMIN_IDS:
        return
    for aid in ADMIN_IDS:
        try:
            await app.bot.send_message(chat_id=aid, text=text)
        except Exception as e:
            logger.warning("notify_admins failed for %s: %s", aid, e)

# Handlers
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    kb = [
        [InlineKeyboardButton("Create Account ➕", callback_data="menu_create")],
        [InlineKeyboardButton("User List 📋", callback_data="menu_list")],
        [InlineKeyboardButton("Help ❓", callback_data="menu_help")]
    ]
    await update.message.reply_text("Welcome to ZIVPN Bot — Menu:", reply_markup=InlineKeyboardMarkup(kb))

async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if q.data == "menu_create":
        await q.edit_message_text("✅ Create Account — Step 1:\nSend the *username* you want to add.", parse_mode=constants.ParseMode.MARKDOWN)
        return STATE_USERNAME
    if q.data == "menu_list":
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT username,password,created_at,expires_at,revoked FROM accounts ORDER BY id DESC")
        rows = cur.fetchall()
        conn.close()
        if not rows:
            await q.edit_message_text("No users found.")
            return
        for r in rows[:100]:
            username, password, created_at, expires_at, revoked = r
            left = days_left(expires_at)
            online = user_online(password) and (revoked==0) and left>0
            status_icon = "🟢" if online else "🔴"
            body = (f"👤 User Card\n\n"
                    f"🏷️ Username: `{username}`\n"
                    f"🔑 Password: `{password}`\n"
                    f"📡 Server IP: `{ZIVPN_SERVER_IP}`\n"
                    f"⏳ Expires: `{expires_at}` ({left} days left)\n"
                    f"🔋 Status: {status_icon} {'Online' if online else 'Offline'}")
            kb = [
                [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
                 InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
            ]
            await q.message.reply_text(body, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
        await q.edit_message_text("Displayed user cards.")
        return
    if q.data == "menu_help":
        await q.edit_message_text("Public bot: anyone can create, view, renew or delete accounts.\nUse Create Account to add users. Use User List to manage.", parse_mode=constants.ParseMode.MARKDOWN)
        return

# Create flow (public)
async def recv_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = update.message.text.strip()
    if not username:
        await update.message.reply_text("Username cannot be empty.")
        return STATE_USERNAME
    context.user_data['new_username'] = username
    await update.message.reply_text("Step 2: Send password you want or send /gen to generate.")
    return STATE_PASSWORD

async def recv_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = update.message.text.strip()
    if txt.lower() == "/gen":
        import secrets, string
        alphabet = string.ascii_letters + string.digits + "!@#$%_-"
        pwd = "".join(secrets.choice(alphabet) for _ in range(12))
        context.user_data['new_password'] = pwd
        await update.message.reply_text(f"Generated password: `{pwd}`", parse_mode=constants.ParseMode.MARKDOWN)
    else:
        context.user_data['new_password'] = txt
        await update.message.reply_text("Password saved.")
    kb = [
        [InlineKeyboardButton("5 days", callback_data="exp_5"),
         InlineKeyboardButton("10 days", callback_data="exp_10"),
         InlineKeyboardButton("15 days", callback_data="exp_15")],
        [InlineKeyboardButton("Custom (enter days)", callback_data="exp_custom")]
    ]
    await update.message.reply_text("Choose expiry:", reply_markup=InlineKeyboardMarkup(kb))
    return STATE_EXPIRY

async def expiry_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    if data == "exp_custom":
        await q.edit_message_text("Please send number of days (e.g., 30).")
        return STATE_EXPIRY
    days = int(data.split("_")[1])
    context.user_data['new_days'] = days
    username = context.user_data.get('new_username')
    password = context.user_data.get('new_password')
    expiry_date = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    context.user_data['new_expiry_date'] = expiry_date
    text = (f"Confirm:\n\nServer IP: `{ZIVPN_SERVER_IP}`\nUsername: `{username}`\nPassword: `{password}`\nExpires: `{expiry_date}`")
    kb = [
        [InlineKeyboardButton("Add Account ✅", callback_data="confirm_add"),
         InlineKeyboardButton("Cancel ❌", callback_data="confirm_cancel")]
    ]
    await q.edit_message_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
    return

async def recv_custom_days(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = update.message.text.strip()
    if not txt.isdigit():
        await update.message.reply_text("Send a numeric days value.")
        return STATE_EXPIRY
    days = int(txt)
    context.user_data['new_days'] = days
    expiry_date = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    context.user_data['new_expiry_date'] = expiry_date
    username = context.user_data.get('new_username')
    password = context.user_data.get('new_password')
    text = (f"Confirm:\n\nServer IP: `{ZIVPN_SERVER_IP}`\nUsername: `{username}`\nPassword: `{password}`\nExpires: `{expiry_date}`")
    kb = [
        [InlineKeyboardButton("Add Account ✅", callback_data="confirm_add"),
         InlineKeyboardButton("Cancel ❌", callback_data="confirm_cancel")]
    ]
    await update.message.reply_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
    return

async def confirm_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if q.data == "confirm_cancel":
        await q.edit_message_text("Cancelled.")
        context.user_data.clear()
        return ConversationHandler.END
    if q.data == "confirm_add":
        username = context.user_data.get('new_username')
        password = context.user_data.get('new_password')
        days = context.user_data.get('new_days', 7)
        try:
            pw, exp = run_create_script(username, days, password)
            if not pw: pw = password
            if not exp: exp = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("INSERT INTO accounts (username,password,created_by,created_at,expires_at) VALUES (?,?,?,?,?)",
                        (username, pw, 0, datetime.datetime.utcnow().isoformat(), exp))
            conn.commit()
            conn.close()
            text = (f"✅ Account created\n\nServer IP: `{ZIVPN_SERVER_IP}`\nUsername: `{username}`\nPassword: `{pw}`\nExpires: `{exp}`")
            await q.edit_message_text(text, parse_mode=constants.ParseMode.MARKDOWN)
            # notify admins asynchronously
            asyncio.create_task(notify_admins(context.application, f"New account created:\nUsername: {username}\nPassword: {pw}\nExpires: {exp}"))
        except sqlite3.IntegrityError:
            await q.edit_message_text("Username exists. Revoke first or choose different username.")
        except Exception as e:
            await q.edit_message_text(f"Error creating account: {e}")
        context.user_data.clear()
        return ConversationHandler.END

# Actions (public)
async def action_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    if "|" not in data:
        await q.edit_message_text("Invalid action.")
        return
    action, username = data.split("|",1)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password,revoked FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await q.edit_message_text("User not found in DB.")
        conn.close()
        return
    password, revoked = row
    if action == "act_delete":
        if revoked:
            await q.edit_message_text("Already revoked.")
            conn.close()
            return
        try:
            with open("/etc/zivpn/config.json",'r') as fh:
                j = json.load(fh)
            arr = j.get("config",[])
            if password in arr:
                arr = [p for p in arr if p != password]
                j["config"] = arr
                with open("/etc/zivpn/config.json",'w') as fh:
                    json.dump(j, fh, indent=2)
            cur.execute("UPDATE accounts SET revoked=1 WHERE username=?", (username,))
            conn.commit()
            conn.close()
            await q.edit_message_text(f"User `{username}` revoked and removed from config.", parse_mode=constants.ParseMode.MARKDOWN)
            asyncio.create_task(notify_admins(context.application, f"Account revoked:\nUsername: {username}"))
        except Exception as e:
            await q.edit_message_text(f"Failed to revoke: {e}")
    elif action == "act_renew":
        kb = [
            [InlineKeyboardButton("➕ 5 days", callback_data=f"renew_do|{username}|5"),
             InlineKeyboardButton("➕ 10 days", callback_data=f"renew_do|{username}|10"),
             InlineKeyboardButton("➕ 30 days", callback_data=f"renew_do|{username}|30")],
            [InlineKeyboardButton("Custom (enter days)", callback_data=f"renew_custom|{username}")]
        ]
        await q.edit_message_text(f"Renew `{username}` — choose extension:", parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))

async def renew_do_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    parts = q.data.split("|")
    if len(parts) != 3:
        await q.edit_message_text("Invalid renew command.")
        return
    _, username, add_days = parts
    add_days = int(add_days)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT expires_at FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await q.edit_message_text("User not found.")
        conn.close()
        return
    expires_at = row[0]
    try:
        curdate = datetime.date.today()
        curr = datetime.datetime.fromisoformat(expires_at).date() if expires_at else curdate
        new_exp = max(curr, curdate) + datetime.timedelta(days=add_days)
        cur.execute("UPDATE accounts SET expires_at=? WHERE username=?", (new_exp.isoformat(), username))
        conn.commit()
        conn.close()
        await q.edit_message_text(f"✅ `{username}` extended by {add_days} days. New expiry: {new_exp.isoformat()}", parse_mode=constants.ParseMode.MARKDOWN)
        asyncio.create_task(notify_admins(context.application, f"Account renewed:\nUsername: {username}\nNew expiry: {new_exp.isoformat()}"))
    except Exception as e:
        await q.edit_message_text(f"Failed to renew: {e}")

async def renew_custom_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    parts = q.data.split("|")
    if len(parts) != 2:
        await q.edit_message_text("Invalid command.")
        return
    username = parts[1]
    context.user_data['pending_renew_user'] = username
    await q.edit_message_text(f"Send number of days to extend `{username}` by (e.g., 30).", parse_mode=constants.ParseMode.MARKDOWN)

async def recv_renew_days(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if 'pending_renew_user' not in context.user_data:
        await update.message.reply_text("No pending renew operation.")
        return ConversationHandler.END
    txt = update.message.text.strip()
    if not txt.isdigit():
        await update.message.reply_text("Send a numeric days value.")
        return STATE_RENEW
    days = int(txt)
    username = context.user_data.pop('pending_renew_user')
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT expires_at FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await update.message.reply_text("User not found.")
        conn.close()
        return ConversationHandler.END
    expires_at = row[0]
    try:
        curr = datetime.datetime.fromisoformat(expires_at).date() if expires_at else datetime.date.today()
        new_exp = max(curr, datetime.date.today()) + datetime.timedelta(days=days)
        cur.execute("UPDATE accounts SET expires_at=? WHERE username=?", (new_exp.isoformat(), username))
        conn.commit()
        conn.close()
        await update.message.reply_text(f"✅ `{username}` extended by {days} days. New expiry: {new_exp.isoformat()}", parse_mode=constants.ParseMode.MARKDOWN)
        asyncio.create_task(notify_admins(context.application, f"Account renewed (custom):\nUsername: {username}\nNew expiry: {new_exp.isoformat()}"))
    except Exception as e:
        await update.message.reply_text(f"Failed to renew: {e}")
    return ConversationHandler.END

async def cmd_list_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, created_at, expires_at, revoked FROM accounts ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    if not rows:
        await update.message.reply_text("No users found.")
        return
    lines = []
    for r in rows[:200]:
        lines.append(f"{r[0]} — exp:{r[2]} — revoked:{r[3]}")
    await update.message.reply_text("User List:\n" + "\n".join(lines))

# CLI /create command (public)
async def cmd_create(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /create <username> <days> [password]")
        return
    username = context.args[0]
    try:
        days = int(context.args[1])
    except:
        await update.message.reply_text("Days must be integer.")
        return
    pwd = context.args[2] if len(context.args) >= 3 else None
    try:
        pw, exp = run_create_script(username, days, pwd)
        if not pw:
            pw = pwd or "unknown"
        if not exp:
            exp = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO accounts (username,password,created_by,created_at,expires_at,revoked) VALUES (?,?,?,?,0,0)",
                    (username, pw, 0, datetime.datetime.utcnow().isoformat(), exp))
        conn.commit(); conn.close()
        await update.message.reply_text(f"Created: {username}\nPassword: {pw}\nExpires: {exp}")
        asyncio.create_task(notify_admins(context.application, f"Account created (CLI):\nUsername: {username}\nPassword: {pw}\nExpires: {exp}"))
    except Exception as e:
        await update.message.reply_text(f"Error: {e}")

def build_conv():
    conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(menu_callback, pattern='^menu_')],
        states={
            STATE_USERNAME: [MessageHandler(filters.ALL & ~filters.COMMAND, recv_username)],
            STATE_PASSWORD: [MessageHandler(filters.ALL & ~filters.COMMAND, recv_password)],
            STATE_EXPIRY: [
                CallbackQueryHandler(expiry_callback, pattern='^exp_'),
                MessageHandler(filters.ALL & ~filters.COMMAND, recv_custom_days)
            ],
            STATE_RENEW: [MessageHandler(filters.ALL & ~filters.COMMAND, recv_renew_days)]
        },
        fallbacks=[],
        allow_reentry=True
    )
    return conv

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("list", cmd_list_text))
    app.add_handler(CommandHandler("create", cmd_create))
    app.add_handler(CallbackQueryHandler(action_callback, pattern='^act_'))
    app.add_handler(CallbackQueryHandler(renew_do_callback, pattern='^renew_do\\|'))
    app.add_handler(CallbackQueryHandler(renew_custom_callback, pattern='^renew_custom\\|'))
    app.add_handler(CallbackQueryHandler(confirm_callback, pattern='^confirm_'))
    app.add_handler(CallbackQueryHandler(menu_callback, pattern='^menu_'))
    app.add_handler(build_conv())
    logger.info("Public bot polling started")
    app.run_polling()

if __name__ == "__main__":
    main()
PY

sudo chmod +x /opt/zivpn_bot/bot.py
sudo chown -R "$(whoami):$(whoami)" /opt/zivpn_bot

# 9) systemd unit for bot
echo "-- Creating systemd service for zivpn_bot --"
sudo tee /etc/systemd/system/zivpn_bot.service > /dev/null <<'UNIT'
[Unit]
Description=ZIVPN Telegram Bot (PUBLIC MODE)
After=network.target

[Service]
User=root
WorkingDirectory=/opt/zivpn_bot
EnvironmentFile=/etc/default/zivpn_bot
ExecStart=/opt/zivpn_bot/venv/bin/python /opt/zivpn_bot/bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now zivpn_bot.service

# 10) expiry-check cron
echo "-- Adding daily expiry-check cron job --"
sudo tee /usr/local/bin/zivpn_expire_check.sh > /dev/null <<'SH'
#!/usr/bin/env bash
DB="/var/lib/zivpn_bot/accounts.db"
CFG="/etc/zivpn/config.json"
sqlite3 "$DB" "SELECT username,password FROM accounts WHERE revoked=0 AND date(expires_at) <= date('now');" | while IFS='|' read -r user pass; do
  if [ -n "$pass" ]; then
    python3 - <<PY
import json,sqlite3
CFG="$CFG"
DB="$DB"
pw="$pass"
try:
    with open(CFG,'r') as fh:
        j=json.load(fh)
    arr=j.get("config",[])
    arr=[p for p in arr if p!=pw]
    j["config"]=arr
    with open(CFG,'w') as fh:
        json.dump(j, fh, indent=2)
    conn=sqlite3.connect(DB)
    conn.execute("UPDATE accounts SET revoked=1 WHERE password=?", (pw,))
    conn.commit()
    conn.close()
except Exception as e:
    pass
PY
  fi
done
SH

sudo chmod +x /usr/local/bin/zivpn_expire_check.sh
( sudo crontab -l 2>/dev/null | cat; echo "0 3 * * * /usr/local/bin/zivpn_expire_check.sh >/dev/null 2>&1" ) | sudo crontab -

echo ""
echo "== INSTALL COMPLETE =="
echo "Public bot installed. Anyone can create/list/renew/delete accounts."
echo "Admin notifications will be sent to ADMIN_IDS if you set them in /etc/default/zivpn_bot."
echo "To test: delete bot chat (clear history), then open bot and send /start -> Create Account -> follow steps."
echo "Logs: sudo journalctl -u zivpn_bot.service -f"
echo "Security reminder: public mode exposes accounts and passwords to everyone."
echo "Done."
