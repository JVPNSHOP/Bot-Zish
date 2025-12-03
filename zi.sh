#!/usr/bin/env bash
# install_zivpn_public_fixed_v2.sh
# Fixed: ZIVPN authentication issue
set -euo pipefail
IFS=$'\n\t'

### ===== CONFIG (edit BEFORE running if needed) =====
BOT_TOKEN_DEFAULT="8409119937:AAGsRoqiyg-U_caPKsDUpnhzMN8SyG5Y0qw"
ADMIN_IDS_DEFAULT=""   # public mode = empty
ZIVPN_SERVER_IP_DEFAULT="$(curl -s https://ifconfig.co || echo "your.server.ip")"
### ==================================================

echo "== ZIVPN + Public Telegram Bot Installer (Fixed Authentication) =="
echo "Running as: $(whoami) on $(hostname)"
sleep 1

# Install packages
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install -y wget curl openssl python3 python3-venv python3-pip ufw iptables sqlite3 jq

# Install ZIVPN binary + config
sudo systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true
sudo wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn
sudo chmod +x /usr/local/bin/zivpn
sudo mkdir -p /etc/zivpn

# Create initial config
sudo tee /etc/zivpn/config.json > /dev/null <<'CONFIG'
{
  "config": [
    "zi"
  ],
  "listen": "0.0.0.0:5667"
}
CONFIG

sudo openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=ZIVPN/OU=IT/CN=zivpn" \
  -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt >/dev/null 2>&1 || true

sudo sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sudo sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

# systemd for zivpn
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

# Firewall / iptables
NETIF=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || echo "eth0")
sudo iptables -t nat -A PREROUTING -i "${NETIF}" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
sudo ufw allow 6000:19999/udp || true
sudo ufw allow 5667/udp || true

# Improved create script with better password handling
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
  # Generate secure password
  PASSWORD=$(tr -dc 'A-Za-z0-9!@#$%_-' </dev/urandom | head -c12 || echo "zi$(date +%s)")
fi

EXPIRES=$(date -d "+${DAYS} days" +%F 2>/dev/null || echo "$(date +%F)")
CFG_FILE="/etc/zivpn/config.json"
TMP_FILE="$(mktemp)"

# Ensure config file exists
if [ ! -f "$CFG_FILE" ]; then
  echo '{"config":["zi"], "listen":"0.0.0.0:5667"}' > "$CFG_FILE"
fi

# Add password to config.json
python3 -c "
import json, sys, os
cfg_file = '$CFG_FILE'
tmp_file = '$TMP_FILE'
password = '$PASSWORD'

try:
    with open(cfg_file, 'r') as f:
        config = json.load(f)
except Exception as e:
    config = {'config': ['zi'], 'listen': '0.0.0.0:5667'}

# Ensure config key exists
if 'config' not in config:
    config['config'] = []

# Add password if not already present
if password not in config['config']:
    config['config'].append(password)
    print(f'Password added to config: {password}')
else:
    print(f'Password already in config: {password}')

# Save to temporary file
with open(tmp_file, 'w') as f:
    json.dump(config, f, indent=2)
" || {
  echo "ERROR: Failed to update config.json"
  exit 1
}

# Replace config file
if [ -f "$TMP_FILE" ]; then
  sudo mv "$TMP_FILE" "$CFG_FILE"
  sudo chmod 644 "$CFG_FILE"
  
  # Restart zivpn to reload config
  echo "Restarting ZIVPN service to apply changes..."
  sudo systemctl restart zivpn.service || true
fi

echo "PASSWORD:${PASSWORD} EXPIRES:${EXPIRES}"
exit 0
BASH

sudo chmod +x /usr/local/bin/create_vpn_user.sh

# Python venv + deps
sudo mkdir -p /opt/zivpn_bot
sudo chown "$(whoami):$(whoami)" /opt/zivpn_bot
python3 -m venv /opt/zivpn_bot/venv
/opt/zivpn_bot/venv/bin/pip install --upgrade pip >/dev/null
/opt/zivpn_bot/venv/bin/pip install python-telegram-bot==20.3 >/dev/null

# SQLite DB
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

# Write env file
sudo tee /etc/default/zivpn_bot > /dev/null <<EOF
# BOT environment for zivpn_bot
BOT_TOKEN="${BOT_TOKEN_DEFAULT}"
ADMIN_IDS="${ADMIN_IDS_DEFAULT}"
ZIVPN_SERVER_IP="${ZIVPN_SERVER_IP_DEFAULT}"
EOF

sudo chmod 644 /etc/default/zivpn_bot
sudo chown root:root /etc/default/zivpn_bot

# Bot script with improved error handling
sudo tee /opt/zivpn_bot/bot.py > /dev/null <<'PY'
#!/usr/bin/env python3
# bot.py - Fixed authentication issue
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

logger.info("Started zivpn public bot (fixed authentication) admin_notify=%s", ADMIN_IDS)

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
    
    logger.info(f"Running create script: {cmd}")
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    
    if res.returncode != 0:
        logger.error(f"Create script failed: {res.stderr}")
        raise RuntimeError(res.stderr or res.stdout or "create script failed")
    
    out = res.stdout.strip()
    logger.info(f"Create script output: {out}")
    
    pw, exp = None, None
    for token in out.split():
        if ":" in token:
            k,v = token.split(":",1)
            if k.lower()=="password": pw = v
            if k.lower()=="expires": exp = v
    
    # Verify password is in config
    if pw:
        try:
            with open("/etc/zivpn/config.json",'r') as fh:
                config = json.load(fh)
            if pw not in config.get("config", []):
                logger.warning(f"Password {pw} not found in config.json, adding manually")
                config["config"].append(pw)
                with open("/etc/zivpn/config.json",'w') as fh:
                    json.dump(config, fh, indent=2)
                # Restart zivpn service
                subprocess.run(["sudo", "systemctl", "restart", "zivpn.service"], timeout=10)
        except Exception as e:
            logger.error(f"Failed to verify/config update: {e}")
    
    return pw, exp

async def notify_admins(app, text):
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

# Create flow
async def recv_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    if not text:
        await update.message.reply_text("Username cannot be empty.")
        return STATE_USERNAME
    context.user_data['new_username'] = text
    await update.message.reply_text("Step 2: Send password you want or send /gen to generate.")
    return STATE_PASSWORD

async def recv_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    if not text:
        await update.message.reply_text("Password cannot be empty or send /gen to generate.")
        return STATE_PASSWORD
    if text.lower() == "/gen":
        import secrets, string
        alphabet = string.ascii_letters + string.digits + "!@#$%_-"
        pwd = "".join(secrets.choice(alphabet) for _ in range(12))
        context.user_data['new_password'] = pwd
        await update.message.reply_text(f"Generated password: `{pwd}`", parse_mode=constants.ParseMode.MARKDOWN)
    else:
        context.user_data['new_password'] = text
        await update.message.reply_text("Password saved.")
    kb = [
        [InlineKeyboardButton("5 days", callback_data="exp_5"),
         InlineKeyboardButton("10 days", callback_data="exp_10"),
         InlineKeyboardButton("15 days", callback_data="exp_15")],
        [InlineKeyboardButton("Custom (enter days)", callback_data="exp_custom")]
    ]
    await update.message.reply_text("Choose expiry (or type a number like 30 or 60):", reply_markup=InlineKeyboardMarkup(kb))
    return STATE_EXPIRY

async def expiry_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    if data == "exp_custom":
        await q.edit_message_text("Please send number of days (e.g., 30).")
        return STATE_EXPIRY
    # preset buttons e.g. exp_5
    if data.startswith("exp_"):
        try:
            days = int(data.split("_")[1])
        except:
            days = 7
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
    txt = (update.message.text or "").strip()
    # Accept direct numeric input here (e.g., 30, 60) as days
    if not txt.isdigit():
        await update.message.reply_text("Send a numeric days value (e.g., 30).")
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
            text = (f"✅ Account created\n\n"
                    f"Server IP: `{ZIVPN_SERVER_IP}`\n"
                    f"Username: `{username}`\n"
                    f"Password: `{pw}`\n"
                    f"Expires: `{exp}`\n\n"
                    f"⚠️ Note: If connection fails, try restarting ZIVPN client.")
            await q.edit_message_text(text, parse_mode=constants.ParseMode.MARKDOWN)
            asyncio.create_task(notify_admins(context.application, f"New account created:\nUsername: {username}\nPassword: {pw}\nExpires: {exp}"))
        except sqlite3.IntegrityError:
            await q.edit_message_text("Username exists. Revoke first or choose different username.")
        except Exception as e:
            logger.error(f"Error creating account: {e}")
            await q.edit_message_text(f"Error creating account: {e}\nCheck server logs for details.")
        context.user_data.clear()
        return ConversationHandler.END

# Actions
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
                # Restart zivpn
                subprocess.run(["sudo", "systemctl", "restart", "zivpn.service"], timeout=10)
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
    txt = (update.message.text or "").strip()
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

async def cmd_check_config(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check current config.json"""
    try:
        with open("/etc/zivpn/config.json",'r') as fh:
            config = json.load(fh)
        passwords = config.get("config", [])
        await update.message.reply_text(f"Config has {len(passwords)} passwords: {', '.join(passwords[:10])}")
    except Exception as e:
        await update.message.reply_text(f"Error reading config: {e}")

def build_conv():
    conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(menu_callback, pattern='^menu_')],
        states={
            STATE_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_username)],
            STATE_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_password)],
            STATE_EXPIRY: [
                CallbackQueryHandler(expiry_callback, pattern='^exp_'),
                MessageHandler(filters.TEXT & ~filters.COMMAND, recv_custom_days),
                CallbackQueryHandler(confirm_callback, pattern='^confirm_')
            ],
            STATE_RENEW: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_renew_days)]
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
    app.add_handler(CommandHandler("checkconfig", cmd_check_config))
    app.add_handler(CallbackQueryHandler(action_callback, pattern='^act_'))
    app.add_handler(CallbackQueryHandler(renew_do_callback, pattern='^renew_do\\|'))
    app.add_handler(CallbackQueryHandler(renew_custom_callback, pattern='^renew_custom\\|'))
    # menu_ and confirm_ handlers are inside conversation handler
    app.add_handler(build_conv())
    logger.info("Public bot polling started (fixed authentication)")
    app.run_polling()

if __name__ == "__main__":
    main()
PY

sudo chmod +x /opt/zivpn_bot/bot.py
sudo chown -R "$(whoami):$(whoami)" /opt/zivpn_bot

# systemd service for bot
sudo tee /etc/systemd/system/zivpn_bot.service > /dev/null <<'UNIT'
[Unit]
Description=ZIVPN Telegram Bot (PUBLIC MODE)
After=network.target zivpn.service

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

# expiry-check cron
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
    if pw in arr:
        arr=[p for p in arr if p!=pw]
        j["config"]=arr
        with open(CFG,'w') as fh:
            json.dump(j, fh, indent=2)
        conn=sqlite3.connect(DB)
        conn.execute("UPDATE accounts SET revoked=1 WHERE password=?", (pw,))
        conn.commit()
        conn.close()
        print(f"Revoked expired account: {user}")
except Exception as e:
    pass
PY
  fi
done
SH

sudo chmod +x /usr/local/bin/zivpn_expire_check.sh
( sudo crontab -l 2>/dev/null | cat; echo "0 3 * * * /usr/local/bin/zivpn_expire_check.sh >/dev/null 2>&1" ) | sudo crontab -

# Test script to verify password in config
sudo tee /usr/local/bin/test_password.sh > /dev/null <<'SH'
#!/bin/bash
if [ -z "$1" ]; then
  echo "Usage: test_password.sh <password>"
  exit 1
fi
PASSWORD="$1"
if sudo grep -q "\"$PASSWORD\"" /etc/zivpn/config.json; then
  echo "✓ Password '$PASSWORD' found in config.json"
  exit 0
else
  echo "✗ Password '$PASSWORD' NOT found in config.json"
  exit 1
fi
SH

sudo chmod +x /usr/local/bin/test_password.sh

echo "== INSTALL COMPLETE =="
echo ""
echo "IMPORTANT FIXES APPLIED:"
echo "1. Improved create_vpn_user.sh script with better password handling"
echo "2. ZIVPN service restarts automatically when config changes"
echo "3. Bot verifies password is in config.json after creation"
echo "4. Added /checkconfig command to verify passwords in config"
echo ""
echo "To test the fix:"
echo "1. Create a new account via bot"
echo "2. Run: sudo /usr/local/bin/test_password.sh <your_password>"
echo "3. Check ZIVPN service: sudo systemctl status zivpn"
echo "4. Try connecting with ZIVPN client"
echo ""
echo "To watch logs:"
echo "Bot logs: sudo journalctl -u zivpn_bot.service -f"
echo "ZIVPN logs: sudo journalctl -u zivpn.service -f"
echo ""
echo "If still having issues, check:"
echo "1. sudo cat /etc/zivpn/config.json"
echo "2. sudo systemctl restart zivpn"
echo "3. Ensure firewall ports are open: 6000:19999/udp"
