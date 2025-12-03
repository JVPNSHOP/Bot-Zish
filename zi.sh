#!/usr/bin/env bash
# install_zivpn_public_fixed.sh
# Full fixed installer for ZIVPN + Telegram bot (with server stats & blinking status A)
set -euo pipefail
IFS=$'\n\t'

### ===== CONFIG (edit BEFORE running if needed) =====
BOT_TOKEN_DEFAULT=""   # leave empty to be prompted at install time
ADMIN_IDS_DEFAULT=""   # comma separated Telegram IDs for admin notifications (optional)
ZIVPN_SERVER_IP_DEFAULT="$(curl -s https://ifconfig.co || echo "your.server.ip")"
### ==================================================

echo "== ZIVPN + Public Telegram Bot Installer (fixed, server stats + blink A) =="
echo "Running as: $(whoami) on $(hostname)"
sleep 1

# Prompt for BOT token and admin ids if not preset
if [ -z "${BOT_TOKEN_DEFAULT}" ]; then
  echo
  read -r -p "Enter your Telegram BOT TOKEN (or press Enter to skip): " BOT_TOKEN_INPUT
  if [ -n "$BOT_TOKEN_INPUT" ]; then
    BOT_TOKEN_DEFAULT="$BOT_TOKEN_INPUT"
  fi
fi

if [ -z "${ADMIN_IDS_DEFAULT}" ]; then
  echo
  read -r -p "Enter ADMIN_IDS (comma separated) or press Enter to leave empty: " ADMIN_IDS_INPUT
  if [ -n "$ADMIN_IDS_INPUT" ]; then
    ADMIN_IDS_DEFAULT="$ADMIN_IDS_INPUT"
  fi
fi

echo
read -r -p "Server IP to show (detected: ${ZIVPN_SERVER_IP_DEFAULT}) - press Enter to accept: " SERVER_IP_INPUT
if [ -n "$SERVER_IP_INPUT" ]; then
  ZIVPN_SERVER_IP_DEFAULT="$SERVER_IP_INPUT"
fi

# Update & install packages
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install -y wget curl openssl python3 python3-venv python3-pip ufw iptables sqlite3 jq

# Install ZIVPN binary + config dir
sudo systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true
sudo wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn
sudo chmod +x /usr/local/bin/zivpn
sudo mkdir -p /etc/zivpn

# Create a sane default config.json (ensure auth.config exists)
if ! sudo test -f /etc/zivpn/config.json; then
  sudo tee /etc/zivpn/config.json > /dev/null <<'JSON'
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": {
    "mode": "passwords",
    "config": [
      "zi"
    ]
  }
}
JSON
else
  # sanitize existing config.json: if root-level "config" exists, move to auth.config
  sudo python3 - <<'PY'
import json,sys,os
fn='/etc/zivpn/config.json'
try:
    with open(fn,'r') as f:
        j=json.load(f)
except:
    j={}
changed=False
if 'auth' not in j or not isinstance(j.get('auth'),dict):
    j['auth']={'mode':'passwords','config':[]}
# move root-level config into auth.config if present
if 'config' in j and isinstance(j.get('config'),list):
    for p in j['config']:
        if p not in j['auth'].get('config',[]):
            j['auth'].setdefault('config',[]).append(p)
    del j['config']
    changed=True
# ensure auth.config is list
if not isinstance(j['auth'].get('config',[]),list):
    j['auth']['config']=list(j['auth'].get('config',[])) if j['auth'].get('config') else []
    changed=True
if changed:
    with open(fn+'.tmp','w') as out:
        json.dump(j,out,indent=2)
    os.replace(fn+'.tmp',fn)
PY
fi

# create certificate if missing
if ! sudo test -f /etc/zivpn/zivpn.crt -o -f /etc/zivpn/zivpn.key; then
  sudo openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=US/ST=California/L=Los Angeles/O=ZIVPN/OU=IT/CN=zivpn" \
    -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt >/dev/null 2>&1 || true
fi

# sysctl tweaks
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

# Firewall / iptables
NETIF=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || echo "eth0")
sudo iptables -t nat -A PREROUTING -i "${NETIF}" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
sudo ufw allow 6000:19999/udp || true
sudo ufw allow 5667/udp || true

# create_vpn_user.sh - fixed to update auth.config and restart service
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

# Ensure file exists
if [ ! -f "$CFG_FILE" ]; then
  echo '{"listen":":5667","auth":{"mode":"passwords","config":[]}}' > "$CFG_FILE"
fi

# Use python to safely insert password into auth.config and remove any root-level config if present
python3 - <<PY
import json,sys,os
fn="$CFG_FILE"
out="$TMP"
pw="$PASSWORD"
try:
    with open(fn,'r') as f:
        j=json.load(f)
except:
    j={}
if 'auth' not in j or not isinstance(j.get('auth'),dict):
    j['auth']={'mode':'passwords','config':[]}
# ensure auth.config exists and is a list
if not isinstance(j['auth'].get('config',[]),list):
    j['auth']['config']=list(j['auth'].get('config',[])) if j['auth'].get('config') else []
# add password if missing
if pw not in j['auth']['config']:
    j['auth']['config'].append(pw)
# remove root-level 'config' if exists (avoid duplicate wrong key)
if 'config' in j:
    try:
        del j['config']
    except:
        pass
with open(out,'w') as fo:
    json.dump(j, fo, indent=2)
print("PASSWORD:%s EXPIRES:%s" % (pw, "$EXPIRES"))
PY

if [ -f "$TMP" ]; then
  sudo mv "$TMP" "$CFG_FILE"
  sudo chown root:root "$CFG_FILE"
  sudo chmod 644 "$CFG_FILE"
  # restart service so new password is active
  sudo systemctl restart zivpn.service || true
fi

echo "PASSWORD:${PASSWORD} EXPIRES:${EXPIRES}"
exit 0
BASH

sudo chmod +x /usr/local/bin/create_vpn_user.sh

# Python venv + bot (install psutil)
sudo mkdir -p /opt/zivpn_bot
sudo chown "$(whoami):$(whoami)" /opt/zivpn_bot
python3 -m venv /opt/zivpn_bot/venv
/opt/zivpn_bot/venv/bin/pip install --upgrade pip >/dev/null
/opt/zivpn_bot/venv/bin/pip install python-telegram-bot==20.3 psutil >/dev/null

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

# Bot script (public, server stats + blink A)
sudo tee /opt/zivpn_bot/bot.py > /dev/null <<'PY'
#!/usr/bin/env python3
# bot.py - Public ZIVPN bot (server stats + blinking status A)
import os, sqlite3, subprocess, datetime, json, logging, asyncio, shutil
import psutil
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

logger.info("Started zivpn public bot (fixed) admin_notify=%s", ADMIN_IDS)

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
        auth=j.get("auth",{})
        arr=auth.get("config",[])
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
    if not ADMIN_IDS:
        return
    for aid in ADMIN_IDS:
        try:
            await app.bot.send_message(chat_id=aid, text=text)
        except Exception as e:
            logger.warning("notify_admins failed for %s: %s", aid, e)

def total_users_count():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM accounts")
        n = cur.fetchone()[0]
        conn.close()
        return int(n)
    except:
        return 0

def get_server_stats():
    try:
        # CPU usage with interval for accuracy
        cpu = psutil.cpu_percent(interval=0.5)
        # RAM usage
        vm = psutil.virtual_memory()
        ram_percent = vm.percent
        # Disk usage
        total, used, free = shutil.disk_usage("/")
        disk_percent = round((used / total) * 100, 1)
        return {
            "cpu": cpu,
            "ram": ram_percent,
            "disk": disk_percent,
            "ram_total_gb": round(vm.total / (1024**3), 1),
            "ram_used_gb": round(vm.used / (1024**3), 1),
            "disk_total_gb": round(total / (1024**3), 1),
            "disk_used_gb": round(used / (1024**3), 1)
        }
    except Exception as e:
        logger.error("get_server_stats error: %s", e)
        return {"cpu": 0.0, "ram": 0.0, "disk": 0.0}

# blinking style A generator - GIF-style
def blink_for_status(status:str, days_left:int=0):
    if status == "online":
        if days_left > 3:
            return "🟢⚪🟢⚪"  # Green blinking
        else:
            return "🟡⚪🟡⚪"  # Yellow blinking (expiring soon)
    elif status == "expiring":
        return "🟡⚪🟡⚪"  # Yellow blinking
    else:
        return "🔴⚪🔴⚪"  # Red blinking

def get_status_info(password:str, expires_at:str, revoked:int):
    if revoked:
        return "offline", 0, "Revoked"
    
    left = days_left(expires_at)
    online = user_online(password)
    
    if not online:
        return "offline", left, "Offline"
    
    if left <= 0:
        return "expired", left, "Expired"
    elif left <= 3:
        return "expiring", left, f"Expiring in {left} days"
    else:
        return "online", left, "Online"

# Handlers
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    total = total_users_count()
    stats = get_server_stats()
    
    # Create stats message with emojis
    cpu_line = f"⚙️ CPU: {stats['cpu']:.1f}%"
    ram_line = f"🧠 RAM: {stats['ram']:.1f}% ({stats['ram_used_gb']:.1f}/{stats['ram_total_gb']:.1f} GB)"
    disk_line = f"💾 Disk: {stats['disk']:.1f}% ({stats['disk_used_gb']:.1f}/{stats['disk_total_gb']:.1f} GB)"
    
    body = (f"📊 *Server Status*\n"
            f"┌─────────────\n"
            f"│ {cpu_line}\n"
            f"│ {ram_line}\n"
            f"│ {disk_line}\n"
            f"│ 👥 Total Users: `{total}`\n"
            f"│ 🌐 Server IP: `{ZIVPN_SERVER_IP}`\n"
            f"└─────────────\n\n"
            f"*Status Indicators:*\n"
            f"• 🟢⚪🟢⚪ Online (Active)\n"
            f"• 🟡⚪🟡⚪ Expiring soon (<3 days)\n"
            f"• 🔴⚪🔴⚪ Offline/Expired\n\n"
            f"*Menu:*")
    
    kb = [
        [InlineKeyboardButton("➕ Create Account", callback_data="menu_create"),
         InlineKeyboardButton("📋 User List", callback_data="menu_list")],
        [InlineKeyboardButton("❓ Help", callback_data="menu_help"),
         InlineKeyboardButton("🔄 Refresh", callback_data="menu_refresh")]
    ]
    await update.message.reply_text(body, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))

async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    
    if q.data == "menu_create":
        await q.edit_message_text("✅ *Create Account — Step 1*\nSend the *username* you want to add.", parse_mode=constants.ParseMode.MARKDOWN)
        return STATE_USERNAME
    
    elif q.data == "menu_list":
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT username,password,created_at,expires_at,revoked FROM accounts ORDER BY id DESC")
        rows = cur.fetchall()
        conn.close()
        
        if not rows:
            await q.edit_message_text("No users found.")
            return
        
        # Display user cards
        for idx, r in enumerate(rows[:100]):
            username, password, created_at, expires_at, revoked = r
            status, left, status_text = get_status_info(password, expires_at, revoked)
            blink = blink_for_status(status, left)
            
            # Format dates nicely
            try:
                exp_date = datetime.datetime.fromisoformat(expires_at).strftime("%Y-%m-%d")
            except:
                exp_date = expires_at
            
            body = (f"*👤 User Card {idx+1}*\n"
                    f"┌─────────────\n"
                    f"│ 🏷️ Username: `{username}`\n"
                    f"│ 🔑 Password: `{password}`\n"
                    f"│ 📡 Server IP: `{ZIVPN_SERVER_IP}`\n"
                    f"│ ⏳ Expires: `{exp_date}`\n"
                    f"│ 📅 Days Left: `{left}`\n"
                    f"│ 🔋 Status: {blink} *{status_text}*\n"
                    f"└─────────────")
            
            kb = []
            if not revoked:
                kb.append([
                    InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
                    InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")
                ])
            else:
                kb.append([
                    InlineKeyboardButton("❌ Revoked", callback_data="no_action")
                ])
            
            await q.message.reply_text(body, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
        
        await q.edit_message_text(f"Displayed {len(rows[:100])} user cards.")
        return
    
    elif q.data == "menu_help":
        help_text = (
            "*Help Guide*\n\n"
            "*Status Indicators:*\n"
            "• 🟢⚪🟢⚪ = Online & Active\n"
            "• 🟡⚪🟡⚪ = Expiring soon (<3 days)\n"
            "• 🔴⚪🔴⚪ = Offline/Expired\n\n"
            "*Commands:*\n"
            "• Use menu buttons to create/view accounts\n"
            "• Click on user cards to renew/delete\n"
            "• Expired accounts are automatically disabled\n\n"
            "*Note:* Accounts expire at midnight on expiry date"
        )
        await q.edit_message_text(help_text, parse_mode=constants.ParseMode.MARKDOWN)
        return
    
    elif q.data == "menu_refresh":
        stats = get_server_stats()
        total = total_users_count()
        refresh_msg = (
            f"*Stats Refreshed*\n"
            f"• CPU: {stats['cpu']:.1f}%\n"
            f"• RAM: {stats['ram']:.1f}%\n"
            f"• Disk: {stats['disk']:.1f}%\n"
            f"• Total Users: {total}"
        )
        await q.edit_message_text(refresh_msg, parse_mode=constants.ParseMode.MARKDOWN)
        return

# Create flow
async def recv_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    if not text:
        await update.message.reply_text("Username cannot be empty.")
        return STATE_USERNAME
    if len(text) < 3:
        await update.message.reply_text("Username must be at least 3 characters.")
        return STATE_USERNAME
    context.user_data['new_username'] = text
    await update.message.reply_text("✅ *Step 2*\nSend password you want or send /gen to generate automatically.", parse_mode=constants.ParseMode.MARKDOWN)
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
        await update.message.reply_text(f"✅ Generated password: `{pwd}`", parse_mode=constants.ParseMode.MARKDOWN)
    else:
        if len(text) < 6:
            await update.message.reply_text("Password must be at least 6 characters.")
            return STATE_PASSWORD
        context.user_data['new_password'] = text
        await update.message.reply_text("✅ Password saved.")
    
    kb = [
        [InlineKeyboardButton("7 days", callback_data="exp_7"),
         InlineKeyboardButton("15 days", callback_data="exp_15"),
         InlineKeyboardButton("30 days", callback_data="exp_30")],
        [InlineKeyboardButton("Custom days", callback_data="exp_custom")]
    ]
    await update.message.reply_text("⏳ *Step 3*\nChoose expiry duration (or type a number like 60 for 60 days):", parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
    return STATE_EXPIRY

async def expiry_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    if data == "exp_custom":
        await q.edit_message_text("Please send number of days (e.g., 30).")
        return STATE_EXPIRY
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
        
        text = (f"*Confirm Account Creation*\n"
                f"┌─────────────\n"
                f"│ 🌐 Server IP: `{ZIVPN_SERVER_IP}`\n"
                f"│ 👤 Username: `{username}`\n"
                f"│ 🔑 Password: `{password}`\n"
                f"│ ⏳ Validity: `{days}` days\n"
                f"│ 📅 Expires: `{expiry_date}`\n"
                f"└─────────────")
        
        kb = [
            [InlineKeyboardButton("✅ Create Account", callback_data="confirm_add"),
            InlineKeyboardButton("❌ Cancel", callback_data="confirm_cancel")]
        ]
        await q.edit_message_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
    return

async def recv_custom_days(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (update.message.text or "").strip()
    if not txt.isdigit():
        await update.message.reply_text("Please send a numeric days value (e.g., 30).")
        return STATE_EXPIRY
    days = int(txt)
    if days < 1:
        await update.message.reply_text("Days must be at least 1.")
        return STATE_EXPIRY
    context.user_data['new_days'] = days
    expiry_date = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    context.user_data['new_expiry_date'] = expiry_date
    username = context.user_data.get('new_username')
    password = context.user_data.get('new_password')
    
    text = (f"*Confirm Account Creation*\n"
            f"┌─────────────\n"
            f"│ 🌐 Server IP: `{ZIVPN_SERVER_IP}`\n"
            f"│ 👤 Username: `{username}`\n"
            f"│ 🔑 Password: `{password}`\n"
            f"│ ⏳ Validity: `{days}` days\n"
            f"│ 📅 Expires: `{expiry_date}`\n"
            f"└─────────────")
    
    kb = [
        [InlineKeyboardButton("✅ Create Account", callback_data="confirm_add"),
         InlineKeyboardButton("❌ Cancel", callback_data="confirm_cancel")]
    ]
    await update.message.reply_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
    return

async def confirm_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if q.data == "confirm_cancel":
        await q.edit_message_text("❌ Creation cancelled.")
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
            # Check if username exists
            cur.execute("SELECT username FROM accounts WHERE username=?", (username,))
            if cur.fetchone():
                await q.edit_message_text(f"❌ Username `{username}` already exists. Please choose a different username.", parse_mode=constants.ParseMode.MARKDOWN)
                conn.close()
                context.user_data.clear()
                return ConversationHandler.END
            
            cur.execute("INSERT INTO accounts (username,password,created_by,created_at,expires_at) VALUES (?,?,?,?,?)",
                        (username, pw, 0, datetime.datetime.utcnow().isoformat(), exp))
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM accounts")
            total_users = cur.fetchone()[0] or 0
            conn.close()
            
            status, left, status_text = get_status_info(pw, exp, 0)
            blink = blink_for_status(status, left)
            
            text = (f"✅ *Account Created Successfully*\n"
                    f"┌─────────────\n"
                    f"│ 👤 Username: `{username}`\n"
                    f"│ 🔑 Password: `{pw}`\n"
                    f"│ 🌐 Server IP: `{ZIVPN_SERVER_IP}`\n"
                    f"│ ⏳ Valid for: `{days}` days\n"
                    f"│ 📅 Expires: `{exp}`\n"
                    f"│ 🔋 Status: {blink} *{status_text}*\n"
                    f"│ 👥 Total Users: `{total_users}`\n"
                    f"└─────────────\n\n"
                    f"*Share these details with the user.*")
            
            await q.edit_message_text(text, parse_mode=constants.ParseMode.MARKDOWN)
            asyncio.create_task(notify_admins(context.application, f"📝 New account created:\nUsername: {username}\nPassword: {pw}\nExpires: {exp}\nTotal Users: {total_users}"))
        except Exception as e:
            await q.edit_message_text(f"❌ Error creating account: {str(e)}")
        
        context.user_data.clear()
        return ConversationHandler.END

# Actions
async def action_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    
    if data == "no_action":
        await q.edit_message_text("This account is already revoked.")
        return
    
    if "|" not in data:
        await q.edit_message_text("Invalid action.")
        return
    
    action, username = data.split("|",1)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password,expires_at,revoked FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    
    if not row:
        await q.edit_message_text("❌ User not found in database.")
        conn.close()
        return
    
    password, expires_at, revoked = row
    
    if action == "act_delete":
        if revoked:
            await q.edit_message_text("❌ Account already revoked.")
            conn.close()
            return
        
        try:
            # Remove password from config
            with open("/etc/zivpn/config.json",'r') as fh:
                j = json.load(fh)
            auth = j.get("auth",{})
            arr = auth.get("config",[])
            if password in arr:
                arr = [p for p in arr if p != password]
                j.setdefault("auth",{})["config"] = arr
                with open("/etc/zivpn/config.json",'w') as fh:
                    json.dump(j, fh, indent=2)
                subprocess.run(["sudo","systemctl","restart","zivpn.service"], check=False, timeout=10)
            
            # Mark as revoked in DB
            cur.execute("UPDATE accounts SET revoked=1 WHERE username=?", (username,))
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM accounts")
            total_users = cur.fetchone()[0] or 0
            conn.close()
            
            await q.edit_message_text(f"✅ Account `{username}` has been revoked and removed from active users.\nTotal Users: `{total_users}`", parse_mode=constants.ParseMode.MARKDOWN)
            asyncio.create_task(notify_admins(context.application, f"🗑️ Account revoked:\nUsername: {username}\nTotal Users: {total_users}"))
        except Exception as e:
            await q.edit_message_text(f"❌ Failed to revoke account: {str(e)}")
    
    elif action == "act_renew":
        kb = [
            [InlineKeyboardButton("➕ 7 days", callback_data=f"renew_do|{username}|7"),
             InlineKeyboardButton("➕ 15 days", callback_data=f"renew_do|{username}|15")],
            [InlineKeyboardButton("➕ 30 days", callback_data=f"renew_do|{username}|30"),
             InlineKeyboardButton("Custom days", callback_data=f"renew_custom|{username}")]
        ]
        status, left, status_text = get_status_info(password, expires_at, revoked)
        blink = blink_for_status(status, left)
        
        await q.edit_message_text(f"🔄 *Renew Account*\nUsername: `{username}`\nCurrent expiry: `{expires_at}`\nStatus: {blink} {status_text}\n\nChoose extension duration:", parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))

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
    cur.execute("SELECT expires_at,password,revoked FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    
    if not row:
        await q.edit_message_text("❌ User not found.")
        conn.close()
        return
    
    expires_at, password, revoked = row
    
    if revoked:
        # If revoked, reactivate by adding password back to config
        try:
            with open("/etc/zivpn/config.json",'r') as fh:
                j = json.load(fh)
            auth = j.get("auth",{})
            arr = auth.get("config",[])
            if password not in arr:
                arr.append(password)
                j.setdefault("auth",{})["config"] = arr
                with open("/etc/zivpn/config.json",'w') as fh:
                    json.dump(j, fh, indent=2)
                subprocess.run(["sudo","systemctl","restart","zivpn.service"], check=False, timeout=10)
        except Exception as e:
            logger.error("Failed to reactivate revoked account: %s", e)
    
    try:
        curdate = datetime.date.today()
        curr = datetime.datetime.fromisoformat(expires_at).date() if expires_at else curdate
        # If expired, start from today
        if curr < curdate:
            curr = curdate
        new_exp = curr + datetime.timedelta(days=add_days)
        
        cur.execute("UPDATE accounts SET expires_at=?, revoked=0 WHERE username=?", (new_exp.isoformat(), username))
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM accounts")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        
        status, left, status_text = get_status_info(password, new_exp.isoformat(), 0)
        blink = blink_for_status(status, left)
        
        await q.edit_message_text(f"✅ *Account Renewed*\n"
                                 f"Username: `{username}`\n"
                                 f"Extended by: `{add_days}` days\n"
                                 f"New expiry: `{new_exp.isoformat()}`\n"
                                 f"Status: {blink} *{status_text}*\n"
                                 f"Total Users: `{total_users}`", parse_mode=constants.ParseMode.MARKDOWN)
        asyncio.create_task(notify_admins(context.application, f"🔄 Account renewed:\nUsername: {username}\nNew expiry: {new_exp.isoformat()}\nTotal Users: {total_users}"))
    except Exception as e:
        await q.edit_message_text(f"❌ Failed to renew account: {str(e)}")

async def renew_custom_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    parts = q.data.split("|")
    if len(parts) != 2:
        await q.edit_message_text("Invalid command.")
        return
    
    username = parts[1]
    context.user_data['pending_renew_user'] = username
    await q.edit_message_text(f"Send number of days to extend `{username}` by (e.g., 30):", parse_mode=constants.ParseMode.MARKDOWN)

async def recv_renew_days(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if 'pending_renew_user' not in context.user_data:
        await update.message.reply_text("No pending renew operation.")
        return ConversationHandler.END
    
    txt = (update.message.text or "").strip()
    if not txt.isdigit():
        await update.message.reply_text("Please send a numeric days value.")
        return STATE_RENEW
    
    days = int(txt)
    if days < 1:
        await update.message.reply_text("Days must be at least 1.")
        return STATE_RENEW
    
    username = context.user_data.pop('pending_renew_user')
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT expires_at,password,revoked FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    
    if not row:
        await update.message.reply_text("❌ User not found.")
        conn.close()
        return ConversationHandler.END
    
    expires_at, password, revoked = row
    
    if revoked:
        # Reactivate if revoked
        try:
            with open("/etc/zivpn/config.json",'r') as fh:
                j = json.load(fh)
            auth = j.get("auth",{})
            arr = auth.get("config",[])
            if password not in arr:
                arr.append(password)
                j.setdefault("auth",{})["config"] = arr
                with open("/etc/zivpn/config.json",'w') as fh:
                    json.dump(j, fh, indent=2)
                subprocess.run(["sudo","systemctl","restart","zivpn.service"], check=False, timeout=10)
        except Exception as e:
            logger.error("Failed to reactivate: %s", e)
    
    try:
        curdate = datetime.date.today()
        curr = datetime.datetime.fromisoformat(expires_at).date() if expires_at else curdate
        if curr < curdate:
            curr = curdate
        new_exp = curr + datetime.timedelta(days=days)
        
        cur.execute("UPDATE accounts SET expires_at=?, revoked=0 WHERE username=?", (new_exp.isoformat(), username))
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM accounts")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        
        status, left, status_text = get_status_info(password, new_exp.isoformat(), 0)
        blink = blink_for_status(status, left)
        
        await update.message.reply_text(f"✅ *Account Renewed*\n"
                                       f"Username: `{username}`\n"
                                       f"Extended by: `{days}` days\n"
                                       f"New expiry: `{new_exp.isoformat()}`\n"
                                       f"Status: {blink} *{status_text}*\n"
                                       f"Total Users: `{total_users}`", parse_mode=constants.ParseMode.MARKDOWN)
        asyncio.create_task(notify_admins(context.application, f"🔄 Account renewed (custom):\nUsername: {username}\nNew expiry: {new_exp.isoformat()}\nTotal Users: {total_users}"))
    except Exception as e:
        await update.message.reply_text(f"❌ Failed to renew: {str(e)}")
    
    return ConversationHandler.END

# Command handlers
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
        username, created_at, expires_at, revoked = r
        status, left, status_text = get_status_info("", expires_at, revoked)
        blink = blink_for_status(status, left)
        
        # Format date
        try:
            exp_date = datetime.datetime.fromisoformat(expires_at).strftime("%Y-%m-%d")
        except:
            exp_date = expires_at
        
        lines.append(f"{blink} `{username}` - Exp: {exp_date} ({left}d) - {'❌ Revoked' if revoked else '✅ Active'}")
    
    total = total_users_count()
    await update.message.reply_text(f"*User List (Total: {total})*\n" + "\n".join(lines), parse_mode=constants.ParseMode.MARKDOWN)

async def cmd_create(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("Usage: `/create <username> <days> [password]`", parse_mode=constants.ParseMode.MARKDOWN)
        return
    
    username = context.args[0]
    try:
        days = int(context.args[1])
    except:
        await update.message.reply_text("Days must be an integer.")
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
        # Check if exists
        cur.execute("SELECT username FROM accounts WHERE username=?", (username,))
        if cur.fetchone():
            await update.message.reply_text(f"Username `{username}` already exists.", parse_mode=constants.ParseMode.MARKDOWN)
            conn.close()
            return
        
        cur.execute("INSERT OR REPLACE INTO accounts (username,password,created_by,created_at,expires_at,revoked) VALUES (?,?,?,?,?,0)",
                    (username, pw, 0, datetime.datetime.utcnow().isoformat(), exp))
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM accounts")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        
        status, left, status_text = get_status_info(pw, exp, 0)
        blink = blink_for_status(status, left)
        
        await update.message.reply_text(f"✅ *Account Created*\n"
                                       f"Username: `{username}`\n"
                                       f"Password: `{pw}`\n"
                                       f"Expires: `{exp}`\n"
                                       f"Status: {blink} {status_text}\n"
                                       f"Total Users: `{total_users}`", parse_mode=constants.ParseMode.MARKDOWN)
        asyncio.create_task(notify_admins(context.application, f"📝 Account created (CLI):\nUsername: {username}\nPassword: {pw}\nExpires: {exp}\nTotal Users: {total_users}"))
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

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
    app.add_handler(CallbackQueryHandler(action_callback, pattern='^act_'))
    app.add_handler(CallbackQueryHandler(renew_do_callback, pattern='^renew_do\\|'))
    app.add_handler(CallbackQueryHandler(renew_custom_callback, pattern='^renew_custom\\|'))
    app.add_handler(build_conv())
    logger.info("Public bot polling started with blinking status indicators")
    app.run_polling()

if __name__ == "__main__":
    main()
PY

sudo chmod +x /opt/zivpn_bot/bot.py
sudo chown -R "$(whoami):$(whoami)" /opt/zivpn_bot

# systemd for bot
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
sudo systemctl enable --now zivpn_bot.service || true

# expiry-check script: removes expired passwords from auth.config and revokes DB
sudo tee /usr/local/bin/zivpn_expire_check.sh > /dev/null <<'SH'
#!/usr/bin/env bash
DB="/var/lib/zivpn_bot/accounts.db"
CFG="/etc/zivpn/config.json"
LOG="/var/log/zivpn_expire.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | sudo tee -a "$LOG" >/dev/null
}

log "Starting expiry check..."

sqlite3 "$DB" "SELECT username,password FROM accounts WHERE revoked=0 AND date(expires_at) <= date('now');" | while IFS='|' read -r user pass; do
    if [ -n "$pass" ]; then
        log "Expiring account: $user"
        python3 - <<PY
import json,sqlite3,subprocess
CFG="$CFG"
DB="$DB"
pw="$pass"
try:
    # Remove from config
    with open(CFG,'r') as fh:
        j=json.load(fh)
    auth=j.get("auth",{})
    arr=auth.get("config",[])
    arr=[p for p in arr if p!=pw]
    j.setdefault("auth",{})["config"]=arr
    with open(CFG,'w') as fh:
        json.dump(j, fh, indent=2)
    # Restart service
    subprocess.run(["sudo","systemctl","restart","zivpn.service"], check=False, timeout=10)
    # Mark as revoked in DB
    conn=sqlite3.connect(DB)
    conn.execute("UPDATE accounts SET revoked=1 WHERE password=?", (pw,))
    conn.commit()
    conn.close()
    print(f"Expired account: {user}")
except Exception as e:
    print(f"Error expiring {user}: {e}")
PY
    fi
done

log "Expiry check completed."
SH

sudo chmod +x /usr/local/bin/zivpn_expire_check.sh
( sudo crontab -l 2>/dev/null | cat; echo "0 3 * * * /usr/local/bin/zivpn_expire_check.sh >/dev/null 2>&1" ) | sudo crontab -

# Create log file
sudo touch /var/log/zivpn_expire.log
sudo chmod 644 /var/log/zivpn_expire.log

echo "== INSTALL COMPLETE =="
echo ""
echo "✅ ZIVPN Server installed and running"
echo "✅ Telegram Bot installed and running"
echo "✅ Expiry check cron job installed"
echo ""
echo "📝 *Configuration:*"
echo "   Bot settings: /etc/default/zivpn_bot"
echo "   ZIVPN config: /etc/zivpn/config.json"
echo "   User database: /var/lib/zivpn_bot/accounts.db"
echo ""
echo "🔧 *Management Commands:*"
echo "   sudo systemctl status zivpn.service"
echo "   sudo systemctl status zivpn_bot.service"
echo "   sudo journalctl -u zivpn_bot.service -f"
echo ""
echo "🤖 *Bot Usage:*"
echo "   1. Open your Telegram bot"
echo "   2. Send /start command"
echo "   3. Use menu to create/manage accounts"
echo ""
echo "⚠️  If you skipped BOT_TOKEN during install:"
echo "   Edit /etc/default/zivpn_bot and set BOT_TOKEN"
echo "   Then run: sudo systemctl restart zivpn_bot.service"
echo ""
echo "🎉 Done! The bot now features:"
echo "   • 🟢⚪🟢⚪ Online blinking status (>3 days left)"
echo "   • 🟡⚪🟡⚪ Expiring blinking status (≤3 days left)"
echo "   • 🔴⚪🔴⚪ Offline/Expired blinking status"
echo "   • 📊 Accurate CPU/RAM/Storage stats"
echo "   • 📋 User cards with status indicators"
echo "   • 🔄 Renew/Delete functionality"
echo ""
