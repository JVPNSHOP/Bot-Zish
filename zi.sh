#!/usr/bin/env bash
# install_zivpn_full_with_creds.sh
# Full installer: ZIVPN UDP + Telegram Bot (Menu, Create Account wizard, User List)
# NOTE: This version already embeds the BOT token and ADMIN ID you supplied.
set -euo pipefail
IFS=$'\n\t'

### ===== EMBEDDED CREDENTIALS (from user) =====
BOT_TOKEN_DEFAULT="8409119937:AAGsRoqiyg-U_caPKsDUpnhzMN8SyG5Y0qw"
ADMIN_IDS_DEFAULT="14944445684"
ZIVPN_SERVER_IP_DEFAULT="$(curl -s https://ifconfig.co || echo "your.server.ip")"
### =======================================================

echo "== ZIVPN + Telegram Bot Full Installer (with embedded creds) =="
echo "Running as: $(whoami) on $(hostname)"

# 1) System update & packages
echo "-- Updating & installing packages --"
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install -y wget curl openssl python3 python3-venv python3-pip ufw iptables sqlite3

# 2) Install ZIVPN binary + default config
echo "-- Installing ZIVPN binary and default config --"
sudo systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true
sudo wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn
sudo chmod +x /usr/local/bin/zivpn
sudo mkdir -p /etc/zivpn

if ! sudo wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json; then
  echo "-- Failed to download remote config.json — creating fallback --"
  sudo tee /etc/zivpn/config.json > /dev/null <<'EOF'
{
  "config": ["zi"],
  "listen": "0.0.0.0:5667"
}
EOF
fi

echo "-- Generating self-signed cert --"
sudo openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt

sudo sysctl -w net.core.rmem_max=16777216 1>/dev/null 2>/dev/null || true
sudo sysctl -w net.core.wmem_max=16777216 1>/dev/null 2>/dev/null || true

# systemd unit for zivpn
echo "-- Creating systemd service for zivpn --"
sudo tee /etc/systemd/system/zivpn.service > /dev/null <<'SYSTEMD'
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
SYSTEMD

sudo systemctl daemon-reload
sudo systemctl enable --now zivpn.service

# 3) Firewall / iptables rules
NETIF=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || echo "eth0")
echo "-- Configuring firewall for interface ${NETIF} --"
sudo iptables -t nat -A PREROUTING -i "${NETIF}" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
sudo ufw allow 6000:19999/udp || true
sudo ufw allow 5667/udp || true

sudo rm -f zi.* 1>/dev/null 2>/dev/null || true
echo "ZIVPN UDP installed and running (if no errors)."

# 4) Create helper script to create users (with optional password)
echo "-- Creating create_vpn_user.sh helper --"
sudo tee /usr/local/bin/create_vpn_user.sh > /dev/null <<'BASH'
#!/usr/bin/env bash
# /usr/local/bin/create_vpn_user.sh <username> <days> [password]
# Adds provided or generated password to /etc/zivpn/config.json and prints "PASSWORD:<pwd> EXPIRES:<YYYY-MM-DD>"

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

# Ensure config file exists
if [ ! -f "$CFG_FILE" ]; then
  echo '{"config":["zi"], "listen":"0.0.0.0:5667"}' > "$CFG_FILE"
fi

python3 - <<PY
import json,sys
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
print("OK")
PY

if [ -f "$TMP" ]; then
  sudo mv "$TMP" "$CFG_FILE"
fi

echo "PASSWORD:${PASSWORD} EXPIRES:${EXPIRES}"
exit 0
BASH

sudo chmod +x /usr/local/bin/create_vpn_user.sh

# 5) Prepare python environment for bot
echo "-- Setting up Telegram bot environment --"
sudo mkdir -p /opt/zivpn_bot
sudo chown "$(whoami):$(whoami)" /opt/zivpn_bot

python3 -m venv /opt/zivpn_bot/venv
/opt/zivpn_bot/venv/bin/pip install --upgrade pip
/opt/zivpn_bot/venv/bin/pip install python-telegram-bot==20.3

# 6) SQLite DB for accounts
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

# 7) Environment defaults file (safe perms) — using embedded creds above
echo "-- Writing /etc/default/zivpn_bot (with provided BOT token and ADMIN id) --"
sudo tee /etc/default/zivpn_bot > /dev/null <<EOF
# BOT environment for zivpn_bot
BOT_TOKEN="${BOT_TOKEN_DEFAULT}"
ADMIN_IDS="${ADMIN_IDS_DEFAULT}"
ZIVPN_SERVER_IP="${ZIVPN_SERVER_IP_DEFAULT}"
EOF

sudo chmod 600 /etc/default/zivpn_bot
sudo chown root:root /etc/default/zivpn_bot

# 8) Write bot.py (with Menu, Create wizard, User List)
echo "-- Writing bot script to /opt/zivpn_bot/bot.py --"
sudo tee /opt/zivpn_bot/bot.py > /dev/null <<'PY'
#!/usr/bin/env python3
# bot.py - ZIVPN Telegram bot with Menu, Create Account wizard, and User List
import os, sqlite3, subprocess, datetime, shlex, json
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, constants
from telegram.ext import ApplicationBuilder, CommandHandler, ConversationHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

ENV_FILE = "/etc/default/zivpn_bot"
DB_PATH = "/var/lib/zivpn_bot/accounts.db"
CREATE_SCRIPT = "/usr/local/bin/create_vpn_user.sh"
STATE_USERNAME, STATE_PASSWORD, STATE_EXPIRY, STATE_CONFIRM = range(4)

def load_env():
    env = {}
    try:
        with open(ENV_FILE,'r') as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('#') or '=' not in ln: continue
                k,v = ln.split('=',1)
                v = v.strip().strip('"').strip("'")
                env[k.strip()] = v
    except Exception as e:
        print("Failed to read env:", e)
    return env

env = load_env()
BOT_TOKEN = env.get("BOT_TOKEN")
ADMIN_IDS_RAW = env.get("ADMIN_IDS","")
ADMIN_IDS = set(int(x) for x in ADMIN_IDS_RAW.split(",") if x.strip().isdigit())
ZIVPN_SERVER_IP = env.get("ZIVPN_SERVER_IP","your.server.ip")

if not BOT_TOKEN:
    print("BOT_TOKEN not set in /etc/default/zivpn_bot. Exiting.")
    raise SystemExit(1)

def is_admin(user_id:int)->bool:
    return user_id in ADMIN_IDS

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    kb = [
        [InlineKeyboardButton("Create Account ➕", callback_data="menu_create")],
        [InlineKeyboardButton("User List 📋", callback_data="menu_list")],
        [InlineKeyboardButton("Help ❓", callback_data="menu_help")]
    ]
    await update.message.reply_text("Welcome to ZIVPN Bot — Menu:", reply_markup=InlineKeyboardMarkup(kb))

async def menu_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    user = q.from_user
    if data == "menu_create":
        if not is_admin(user.id):
            await q.edit_message_text("Unauthorized. You are not admin.")
            return
        await q.edit_message_text("✅ Create Account — Step 1:\nPlease send the *username* you want to add.", parse_mode=constants.ParseMode.MARKDOWN)
        return STATE_USERNAME
    elif data == "menu_list":
        if not is_admin(user.id):
            await q.answer("Unauthorized.", show_alert=True)
            return
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT username, created_at, expires_at, revoked FROM accounts ORDER BY id DESC")
        rows = cur.fetchall()
        conn.close()
        if not rows:
            await q.edit_message_text("No users found.")
            return
        lines = []
        for r in rows:
            lines.append(f"{r[0]} — exp: {r[2]} — revoked:{r[3]}")
        text = "User List:\n" + "\n".join(lines[:200])
        await q.edit_message_text(text)
        return
    elif data == "menu_help":
        await q.edit_message_text("Use *Create Account* to add users. Only ADMIN_IDS can manage accounts.", parse_mode=constants.ParseMode.MARKDOWN)
        return

async def recv_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.id):
        await update.message.reply_text("Unauthorized.")
        return ConversationHandler.END
    username = update.message.text.strip()
    if not username:
        await update.message.reply_text("Username cannot be empty. Send /cancel to stop.")
        return STATE_USERNAME
    context.user_data['new_username'] = username
    await update.message.reply_text("Step 2: Send password you want, or send /gen to generate a random password.")
    return STATE_PASSWORD

async def recv_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if text.lower() == "/gen":
        import secrets, string
        alphabet = string.ascii_letters + string.digits + "!@#$%_-"
        pwd = "".join(secrets.choice(alphabet) for _ in range(12))
        context.user_data['new_password'] = pwd
        await update.message.reply_text(f"Generated password: `{pwd}`\n\nNow choose expiry (5 / 10 / 15 days).", parse_mode=constants.ParseMode.MARKDOWN)
    else:
        context.user_data['new_password'] = text
        await update.message.reply_text("Password saved. Now choose expiry (5 / 10 / 15 days).")
    kb = [
        [InlineKeyboardButton("5 days", callback_data="exp_5"),
         InlineKeyboardButton("10 days", callback_data="exp_10"),
         InlineKeyboardButton("15 days", callback_data="exp_15")],
        [InlineKeyboardButton("Custom (enter days)", callback_data="exp_custom")]
    ]
    await update.message.reply_text("Select expiry:", reply_markup=InlineKeyboardMarkup(kb))
    return STATE_EXPIRY

async def expiry_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
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
    server = ZIVPN_SERVER_IP
    text = ("Please confirm adding account:\n\n"
            f"Server IP: {server}\nUsername: {username}\nPassword: {password}\nExpires: {expiry_date}")
    kb = [
        [InlineKeyboardButton("Add Account ✅", callback_data="confirm_add"),
         InlineKeyboardButton("Cancel ❌", callback_data="confirm_cancel")]
    ]
    await q.edit_message_text(text, reply_markup=InlineKeyboardMarkup(kb))
    return STATE_CONFIRM

async def recv_custom_days(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.id):
        await update.message.reply_text("Unauthorized.")
        return ConversationHandler.END
    txt = update.message.text.strip()
    if not txt.isdigit():
        await update.message.reply_text("Please send a numeric number of days (e.g., 30).")
        return STATE_EXPIRY
    days = int(txt)
    context.user_data['new_days'] = days
    expiry_date = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    context.user_data['new_expiry_date'] = expiry_date
    username = context.user_data.get('new_username')
    password = context.user_data.get('new_password')
    server = ZIVPN_SERVER_IP
    text = ("Please confirm adding account:\n\n"
            f"Server IP: {server}\nUsername: {username}\nPassword: {password}\nExpires: {expiry_date}")
    kb = [
        [InlineKeyboardButton("Add Account ✅", callback_data="confirm_add"),
         InlineKeyboardButton("Cancel ❌", callback_data="confirm_cancel")]
    ]
    await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(kb))
    return STATE_CONFIRM

async def confirm_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    if data == "confirm_cancel":
        await q.edit_message_text("Cancelled. Use /start to open Menu.")
        context.user_data.clear()
        return ConversationHandler.END
    if data == "confirm_add":
        username = context.user_data.get('new_username')
        password = context.user_data.get('new_password')
        days = context.user_data.get('new_days', 7)
        try:
            cmd = [CREATE_SCRIPT, username, str(days), password]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                await q.edit_message_text(f"Failed to run create script:\n{res.stderr or res.stdout}")
                context.user_data.clear()
                return ConversationHandler.END
            out = res.stdout.strip()
            pw = None
            exp = None
            for token in out.split():
                if ':' in token:
                    k,v = token.split(':',1)
                    if k.lower() == 'password': pw = v
                    if k.lower() == 'expires': exp = v
            if not pw:
                pw = password
            if not exp:
                exp = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("INSERT INTO accounts (username,password,created_by,created_at,expires_at) VALUES (?,?,?,?,?)",
                        (username, pw, q.from_user.id, datetime.datetime.utcnow().isoformat(), exp))
            conn.commit()
            conn.close()
            text = (f"✅ Account created\n\nServer IP: {ZIVPN_SERVER_IP}\nUsername: {username}\nPassword: {pw}\nExpires: {exp}")
            await q.edit_message_text(text)
        except sqlite3.IntegrityError:
            await q.edit_message_text("Username already exists in DB. Choose another username or /revoke first.")
        except Exception as e:
            await q.edit_message_text(f"Error creating account: {e}")
        context.user_data.clear()
        return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Operation cancelled.")
    context.user_data.clear()
    return ConversationHandler.END

async def cmd_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.id):
        await update.message.reply_text("Unauthorized.")
        return
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

def build_conv_handler():
    conv = ConversationHandler(
        entry_points=[CallbackQueryHandler(menu_cb, pattern='^menu_')],
        states={
            STATE_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_username)],
            STATE_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_password)],
            STATE_EXPIRY: [
                CallbackQueryHandler(expiry_cb, pattern='^exp_'),
                MessageHandler(filters.TEXT & ~filters.COMMAND, recv_custom_days)
            ],
            STATE_CONFIRM: [CallbackQueryHandler(confirm_cb, pattern='^confirm_')]
        },
        fallbacks=[CommandHandler('cancel', cancel)],
        allow_reentry=True
    )
    return conv

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("list", cmd_list))
    app.add_handler(build_conv_handler())
    print("Bot polling...")
    app.run_polling()

if __name__ == "__main__":
    main()
PY

sudo chmod +x /opt/zivpn_bot/bot.py
sudo chown -R "$(whoami):$(whoami)" /opt/zivpn_bot

# 9) systemd unit for bot
echo "-- Creating systemd service for the bot --"
sudo tee /etc/systemd/system/zivpn_bot.service > /dev/null <<'UNIT'
[Unit]
Description=ZIVPN Telegram Bot
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

# 10) Expiry-check cron script
echo "-- Adding daily cron job to revoke expired accounts --"
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
passw="$pass"
try:
    with open(CFG,'r') as fh:
        j=json.load(fh)
    arr=j.get("config",[])
    arr=[p for p in arr if p!=passw]
    j["config"]=arr
    with open(CFG,'w') as fh:
        json.dump(j, fh, indent=2)
    conn=sqlite3.connect(DB)
    conn.execute("UPDATE accounts SET revoked=1 WHERE password=?", (passw,))
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

# Final messages & instructions
echo ""
echo "== INSTALLER FINISHED =="
echo "1) /etc/default/zivpn_bot already set with the token and admin id you provided."
echo "2) If you want to change SERVER IP or admins, edit /etc/default/zivpn_bot and restart:"
echo "   sudo systemctl restart zivpn_bot.service"
echo ""
echo "3) Test create from CLI:"
echo "   /usr/local/bin/create_vpn_user.sh testuser 7"
echo ""
echo "4) Test bot in Telegram:"
echo "   - Send /start to the bot (make sure the token you embedded is the correct bot)"
echo "   - Use Menu -> Create Account -> follow steps"
echo ""
echo "5) Logs:"
echo "   sudo journalctl -u zivpn_bot.service -f"
echo "   sudo journalctl -u zivpn.service -f"
echo ""
echo "SECURITY REMINDER: If you accidentally published your bot token, rotate it now via @BotFather."
echo "Done."
