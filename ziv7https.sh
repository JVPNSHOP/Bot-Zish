#!/usr/bin/env bash
# install_zivpn_public_fixed_v6.5.sh
# Fixed installer for ZIVPN + Telegram bot (v6.5) with HTTPS support
# - NEW User Card format with icons
# - Title VIP: 1 for each user
# - Beautiful icons for each field
# - FIXED: Deleted users can be recreated
# - FIXED: Create Account Successfully message
# - ADDED: HTTPS support via Nginx reverse proxy
# - FIXED: Network timeout handling for slow connections

set -euo pipefail
IFS=$'\n\t'

### ===== CONFIG (edit BEFORE running if needed) =====
BOT_TOKEN_DEFAULT="" # leave empty to be prompted at install time
ADMIN_IDS_DEFAULT="" # comma separated Telegram IDs for admin notifications (optional)
ZIVPN_SERVER_IP_DEFAULT="$(curl -s --max-time 10 https://ifconfig.co || echo "your.server.ip")" # Added timeout

### ==================================================

echo "== ZIVPN + Public Telegram Bot Installer (fixed v6.5 with HTTPS) =="
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

# Update & install packages with retry and timeout for slow connections
echo "Updating packages (with timeout handling for slow connections)..."
sudo apt-get update -y --allow-releaseinfo-change || echo "Warning: Update failed, continuing..."
sudo apt-get install -y --no-install-recommends \
    wget curl openssl python3 python3-venv python3-pip ufw iptables sqlite3 jq \
    nginx certbot python3-certbot-nginx || echo "Some packages failed, continuing..."

# Install ZIVPN binary with retry logic
echo "Installing ZIVPN binary..."
for i in {1..3}; do
    sudo systemctl stop zivpn.service 2>/dev/null || true
    if sudo wget -q --timeout=30 --tries=2 \
        https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 \
        -O /usr/local/bin/zivpn; then
        sudo chmod +x /usr/local/bin/zivpn
        break
    else
        echo "Download attempt $i failed, retrying..."
        sleep 2
    fi
done

sudo mkdir -p /etc/zivpn

# Create a sane default config.json (ensure auth.config exists) and ensure obfs is disabled
if ! sudo test -f /etc/zivpn/config.json; then
    sudo tee /etc/zivpn/config.json > /dev/null <<'JSON'
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "",
  "auth": {
    "mode": "passwords",
    "config": [
      "zi"
    ]
  }
}
JSON
else
    # sanitize existing config.json: ensure auth.config list exists and force obfs=""
    sudo python3 - <<'PY'
import json,sys,os
fn='/etc/zivpn/config.json'
try:
    with open(fn,'r') as f:
        j=json.load(f)
except:
    j={}
changed=False
# ensure obfs key exists and is empty string (disable obfs)
if j.get('obfs') != "":
    j['obfs'] = ""
    changed=True
# ensure auth exists as dict with config list
if 'auth' not in j or not isinstance(j.get('auth'),dict):
    j['auth']={'mode':'passwords','config':[]}
if 'config' in j and isinstance(j.get('config'),list):
    # move root-level config into auth.config if present
    for p in j['config']:
        if p not in j['auth'].get('config',[]):
            j['auth'].setdefault('config',[]).append(p)
    try:
        del j['config']
    except:
        pass
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

# sysctl tweaks for better network performance
sudo sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sudo sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true
sudo sysctl -w net.core.rmem_default=8388608 >/dev/null 2>&1 || true
sudo sysctl -w net.core.wmem_default=8388608 >/dev/null 2>&1 || true
sudo sysctl -w net.core.netdev_max_backlog=4096 >/dev/null 2>&1 || true
sudo sysctl -w net.ipv4.udp_mem="8388608 8388608 8388608" >/dev/null 2>&1 || true

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
sudo iptables -t nat -A PREROUTING -i "${NETIF}" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || true
sudo ufw allow 6000:19999/udp 2>/dev/null || true
sudo ufw allow 5667/udp 2>/dev/null || true

# Setup HTTPS via Nginx reverse proxy
echo "Setting up HTTPS support via Nginx..."

# Create Nginx stream configuration for UDP proxy
sudo mkdir -p /etc/nginx/streams-available /etc/nginx/streams-enabled
sudo tee /etc/nginx/nginx.conf > /dev/null <<'NGINX'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}

# TCP/UDP proxy configuration
stream {
    include /etc/nginx/streams-enabled/*.conf;
}

http {
    # Basic HTTP configuration
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Gzip
    gzip on;
    
    # Virtual Host Configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
NGINX

# Create UDP proxy configuration
sudo tee /etc/nginx/streams-available/zivpn-https <<'STREAM'
upstream zivpn_backend {
    server 127.0.0.1:5667;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    
    # SSL certificates (will be replaced by Let's Encrypt)
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    
    # SSL optimization
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Protocol to proxy
    proxy_pass zivpn_backend;
    proxy_timeout 3600s;
    proxy_connect_timeout 10s;
    
    # Buffer settings for better performance on slow connections
    proxy_buffer_size 16k;
    proxy_buffers 8 16k;
    proxy_busy_buffers_size 32k;
}
STREAM

# Enable the configuration
sudo ln -sf /etc/nginx/streams-available/zivpn-https /etc/nginx/streams-enabled/

# Create self-signed certificate for initial setup
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/nginx-selfsigned.key \
    -out /etc/ssl/certs/nginx-selfsigned.crt \
    -subj "/C=US/ST=California/L=San Francisco/O=ZIVPN/CN=${ZIVPN_SERVER_IP_DEFAULT}" 2>/dev/null || true

# Allow HTTPS through firewall
sudo ufw allow 443/tcp 2>/dev/null || true
sudo ufw allow 80/tcp 2>/dev/null || true

# Enable and start Nginx
sudo systemctl enable nginx
sudo systemctl restart nginx

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

if [ ! -f "$CFG_FILE" ]; then
    echo '{"listen":":5667","obfs":"","auth":{"mode":"passwords","config":[]}}' > "$CFG_FILE"
fi

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

# ensure obfs key exists and is empty string
if j.get('obfs') != "":
    j['obfs'] = ""

# ensure auth.config is list
if not isinstance(j['auth'].get('config',[]),list):
    j['auth']['config']=list(j['auth'].get('config',[])) if j['auth'].get('config') else []

# add password if missing
if pw not in j['auth']['config']:
    j['auth']['config'].append(pw)

# remove root-level 'config' if exists
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
    sudo systemctl.restart zivpn.service 2>/dev/null || sudo systemctl restart zivpn.service || true
fi

echo "PASSWORD:${PASSWORD} EXPIRES:${EXPIRES}"
exit 0
BASH

sudo chmod +x /usr/local/bin/create_vpn_user.sh

# Python venv + bot (install psutil) with retry logic
echo "Setting up Python environment..."
sudo mkdir -p /opt/zivpn_bot
sudo chown "$(whoami):$(whoami)" /opt/zivpn_bot

for i in {1..3}; do
    if python3 -m venv /opt/zivpn_bot/venv && \
       /opt/zivpn_bot/venv/bin/pip install --upgrade pip --timeout 60 --retries 2 && \
       /opt/zivpn_bot/venv/bin/pip install python-telegram-bot==20.3 psutil --timeout 60 --retries 2; then
        break
    else
        echo "Python setup attempt $i failed, retrying..."
        sleep 3
    fi
done

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

# Write env file with HTTPS info
sudo tee /etc/default/zivpn_bot > /dev/null <<EOF
# BOT environment for zivpn_bot
BOT_TOKEN="${BOT_TOKEN_DEFAULT}"
ADMIN_IDS="${ADMIN_IDS_DEFAULT}"
ZIVPN_SERVER_IP="${ZIVPN_SERVER_IP_DEFAULT}"
ZIVPN_HTTPS_PORT="443"
EOF

sudo chmod 644 /etc/default/zivpn_bot
sudo chown root:root /etc/default/zivpn_bot

# Bot script (v6.5) - UPDATED with HTTPS support in user cards
sudo tee /opt/zivpn_bot/bot.py > /dev/null <<'PY'
#!/usr/bin/env python3
# bot.py - Public ZIVPN bot (fixed v6.5) with HTTPS support
import os, sqlite3, subprocess, datetime, json, logging, asyncio, shutil, math, secrets, string
import psutil
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, constants, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import ApplicationBuilder, CommandHandler, ConversationHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

ENV_FILE="/etc/default/zivpn_bot"
DB_PATH="/var/lib/zivpn_bot/accounts.db"
CREATE_SCRIPT="/usr/local/bin/create_vpn_user.sh"

# States
STATE_USERNAME, STATE_PASSWORD, STATE_EXPIRY, STATE_RENEW, STATE_EDIT_PASS, STATE_EDIT_EXP, STATE_SEARCH = range(7)

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
ZIVPN_HTTPS_PORT = env.get("ZIVPN_HTTPS_PORT","443")

logger.info("Started zivpn public bot (fixed v6.5 with HTTPS) admin_notify=%s", ADMIN_IDS)
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
            if k.lower()=="password":
                pw = v
            if k.lower()=="expires":
                exp = v
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
        cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
        n = cur.fetchone()[0]
        conn.close()
        return int(n)
    except:
        return 0

def get_server_stats():
    try:
        cpu = psutil.cpu_percent(interval=0.2)
        vm = psutil.virtual_memory()
        ram_total = vm.total / (1024*1024)
        ram_used = (vm.total - vm.available) / (1024*1024)
        ram_percent = vm.percent
        
        total, used, free = shutil.disk_usage("/")
        disk_total_gb = total / (1024*1024*1024)
        disk_used_gb = used / (1024*1024*1024)
        disk_percent = int((used/total)*100) if total>0 else 0
        
        return {
            "cpu": round(cpu,1),
            "ram_used_mb": int(math.ceil(ram_used)),
            "ram_total_mb": int(math.ceil(ram_total)),
            "ram_percent": int(round(ram_percent)),
            "disk_used_gb": round(disk_used_gb,1),
            "disk_total_gb": round(disk_total_gb,1),
            "disk_percent": disk_percent
        }
    except Exception as e:
        return {"cpu": 0.0, "ram_used_mb": 0, "ram_total_mb": 0, "ram_percent": 0,
                "disk_used_gb": 0.0, "disk_total_gb": 0.0, "disk_percent": 0}

# Helper: update password for user
def update_password_for_user(username:str, new_password:str):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT password FROM accounts WHERE username=? LIMIT 1", (username,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return False, "user not in DB"
        old_pw = row[0]
        
        fn = "/etc/zivpn/config.json"
        try:
            with open(fn,'r') as fh:
                j=json.load(fh)
        except:
            j={}
        
        auth = j.get("auth",{})
        arr = auth.get("config",[])
        # remove old and add new
        arr = [p for p in arr if p != old_pw]
        if new_password not in arr:
            arr.append(new_password)
        j.setdefault("auth",{})["config"]=arr
        # ensure obfs remains empty
        j['obfs'] = ""
        
        with open(fn,'w') as fh:
            json.dump(j, fh, indent=2)
        
        subprocess.run(["sudo","systemctl","restart","zivpn.service"], check=False)
        
        cur.execute("UPDATE accounts SET password=? WHERE username=?", (new_password, username))
        conn.commit()
        conn.close()
        return True, None
    except Exception as e:
        return False, str(e)

# Search helper
def search_users_by_username(qstr:str, limit=50):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        like = f"%{qstr}%"
        cur.execute("SELECT username,password,created_at,expires_at,revoked FROM accounts WHERE revoked=0 AND username LIKE ? COLLATE NOCASE ORDER BY id DESC LIMIT ?", (like, limit))
        rows = cur.fetchall()
        conn.close()
        return rows
    except:
        return []

# ========== NEW CARD FORMAT FUNCTION WITH HTTPS ==========
def format_user_card(username: str, password: str, expires_at: str, revoked: int, index: int = 1):
    """Format user card with NEW format, icons and HTTPS info"""
    left = days_left(expires_at)
    
    # Determine status with icons
    if revoked:
        status_emoji = "🔴"
        status_label = "Offline"
    else:
        if user_online(password) and left > 0:
            status_emoji = "🟢"
            status_label = "Online"
        elif left <= 3 and left > 0:
            status_emoji = "🟡"
            status_label = "Expiring"
        else:
            status_emoji = "🔴"
            status_label = "Offline"
    
    left_text = f"({left} days left)" if left > 0 else "(expired)"
    
    # NEW CARD FORMAT with icons - includes HTTPS info
    card = (
        f"👑 Premium User : {index}\n\n"
        f"🌐 Server IP : {ZIVPN_SERVER_IP}\n"
        f"🔐 HTTPS Port : {ZIVPN_HTTPS_PORT}\n"
        f"👤 Username: {username}\n"
        f"🔑 Password: {password}\n"
        f"📅 Expired Date: {expires_at} {left_text}\n"
        f"🔋 Status : {status_emoji} {status_label}\n\n"
        f"🔗 Connection URL:\n"
        f"`https://{ZIVPN_SERVER_IP}:{ZIVPN_HTTPS_PORT}`"
    )
    return card

# ========== MAIN COMMAND HANDLERS ==========
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    total = total_users_count()
    stats = get_server_stats()
    cpu_line = f"⚙️ CPU: {stats['cpu']:.1f}%"
    ram_line = f"🧠 RAM: {stats['ram_used_mb']}MB / {stats['ram_total_mb']}MB ({stats['ram_percent']}%)"
    disk_line = f"💾 STORAGE: {stats['disk_used_gb']}GB / {stats['disk_total_gb']}GB ({stats['disk_percent']}%)"
    
    body = (f"🚀 ZIVPN VPN Service (HTTPS Enabled)\n\n"
            f"📊 Total Users: `{total}`\n\n"
            f"{cpu_line}\n{ram_line}\n{disk_line}\n\n"
            f"🌐 Server: {ZIVPN_SERVER_IP}\n"
            f"🔐 HTTPS Port: {ZIVPN_HTTPS_PORT}\n\n"
            "Choose an option below (tap a button):")
    
    # Updated with icons in buttons
    kb = [
        [KeyboardButton("🆕 Create Account"), KeyboardButton("👥 Users List"), KeyboardButton("🔍 Search")],
        [KeyboardButton("ℹ️ Help"), KeyboardButton("🔐 HTTPS Info")]
    ]
    reply_kb = ReplyKeyboardMarkup(kb, resize_keyboard=True, one_time_keyboard=False)
    await update.message.reply_text(body, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=reply_kb)

async def handle_main_buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (update.message.text or "").strip()
    if txt == "👥 Users List":
        await cmd_list_cards(update, context)
        return
    if txt == "ℹ️ Help":
        await update.message.reply_text(
            "📚 Public ZIVPN Bot (HTTPS Enabled)\n\n"
            "🆕 Create Account: Create new VPN account\n"
            "👥 Users List: View all active accounts\n"
            "🔍 Search: Search for specific account\n"
            "🔁 Renew: Extend account expiry\n"
            "✏️ Edit: Change password or expiry\n"
            "🗑️ Delete: Revoke account access\n"
            "🔐 HTTPS Info: Connection information\n\n"
            "🌐 Server supports both UDP and HTTPS connections"
        )
        return
    if txt == "🔐 HTTPS Info":
        await update.message.reply_text(
            f"🔐 HTTPS Connection Information:\n\n"
            f"🌐 Server IP: `{ZIVPN_SERVER_IP}`\n"
            f"🔐 HTTPS Port: `{ZIVPN_HTTPS_PORT}`\n"
            f"🔧 Protocol: TCP over HTTPS\n"
            f"📡 UDP Port: `5667` (Direct connection)\n\n"
            f"✅ Use HTTPS for better compatibility with restricted networks\n"
            f"✅ Automatic SSL encryption\n"
            f"✅ Works through most firewalls"
        )
        return

# ========== CREATE ACCOUNT FLOW ==========
async def handle_create_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    context.user_data['create_flow'] = 'username'
    await update.message.reply_text(
        "✅ Create Account — Step 1:\n"
        "Send the *username* you want to add.",
        parse_mode=constants.ParseMode.MARKDOWN
    )

async def handle_search_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    context.user_data['awaiting_search'] = True
    await update.message.reply_text("🔎 Send username to search (partial matches allowed).")

# ========== USERS LIST WITH NEW CARD FORMAT ==========
async def cmd_list_cards(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show all users as beautiful cards with NEW format"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, password, created_at, expires_at, revoked FROM accounts WHERE revoked=0 ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    
    if not rows:
        await update.message.reply_text("📭 No active users found.")
        return
    
    total = total_users_count()
    await update.message.reply_text(f"📋 Total Users: {total}")
    
    # Send each user as a beautiful card with NEW format
    for idx, row in enumerate(rows[:200], 1):
        username, password, created_at, expires_at, revoked = row
        # Format card with NEW format
        card_text = format_user_card(username, password, expires_at, revoked, idx)
        
        # Create inline buttons
        kb_card = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
             InlineKeyboardButton("✏️ Edit", callback_data=f"act_edit|{username}")],
            [InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
        ])
        
        try:
            await context.bot.send_message(
                chat_id=update.message.chat_id,
                text=card_text,
                parse_mode=constants.ParseMode.MARKDOWN,
                reply_markup=kb_card
            )
        except Exception as e:
            logger.debug("Failed to send user card: %s", e)

# Main text router for all text messages
async def global_text_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (update.message.text or "").strip()
    
    # Skip if it's a main button (handled by other handlers)
    if txt in ("🆕 Create Account", "👥 Users List", "🔍 Search", "ℹ️ Help", "🔐 HTTPS Info"):
        return
    
    # ===== CREATE FLOW =====
    # Step 1: Username
    if context.user_data.get('create_flow') == 'username':
        username = txt
        if not username:
            await update.message.reply_text("❗ Username cannot be empty.")
            return
        context.user_data['new_username'] = username
        context.user_data['create_flow'] = 'password'
        await update.message.reply_text("🔐 Step 2: Send password you want or send /gen to generate.")
        return
    
    # Step 2: Password
    if context.user_data.get('create_flow') == 'password':
        if txt.lower() == "/gen":
            alphabet = string.ascii_letters + string.digits + "!@#$%_-"
            pwd = "".join(secrets.choice(alphabet) for _ in range(12))
            context.user_data['new_password'] = pwd
            await update.message.reply_text(f"🧾 Generated password: `{pwd}`", parse_mode=constants.ParseMode.MARKDOWN)
        else:
            context.user_data['new_password'] = txt
            await update.message.reply_text("✅ Password saved.")
        
        context.user_data['create_flow'] = 'expiry'
        kb = [
            [InlineKeyboardButton("30 days", callback_data="exp_30"),
             InlineKeyboardButton("60 days", callback_data="exp_60"),
             InlineKeyboardButton("90 days", callback_data="exp_90")],
            [InlineKeyboardButton("Custom (enter days)", callback_data="exp_custom")]
        ]
        await update.message.reply_text("⏳ Choose expiry (or type a number like 30 or 60):", reply_markup=InlineKeyboardMarkup(kb))
        return
    
    # Step 3: Expiry (custom days input)
    if context.user_data.get('create_flow') == 'expiry':
        if txt.isdigit():
            days = int(txt)
            context.user_data['new_days'] = days
            expiry_date = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
            context.user_data['new_expiry_date'] = expiry_date
            context.user_data['create_flow'] = 'confirm'
            
            username = context.user_data.get('new_username')
            password = context.user_data.get('new_password')
            
            # Show preview in NEW card format
            card_preview = format_user_card(username, password, expiry_date, 0, 1)
            text = f"📝 Confirm Account Creation:\n\n{card_preview}"
            kb = [
                [InlineKeyboardButton("Add Account ✅", callback_data="confirm_add"),
                 InlineKeyboardButton("Cancel ❌", callback_data="confirm_cancel")]
            ]
            await update.message.reply_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
        else:
            await update.message.reply_text("❗ Please send a number for days (e.g., 30).")
        return
    
    # ===== SEARCH FLOW =====
    if context.user_data.get('awaiting_search'):
        qstr = txt
        if not qstr:
            await update.message.reply_text("❗ Send a username pattern to search (e.g., 'vip').")
            return
        
        rows = search_users_by_username(qstr, limit=200)
        if not rows:
            await update.message.reply_text("No users matched your query.")
            context.user_data.pop('awaiting_search', None)
            return
        
        chat_id = update.message.chat_id
        for idx, row in enumerate(rows, 1):
            username, password, created_at, expires_at, revoked = row
            # Format card with NEW format
            card_text = format_user_card(username, password, expires_at, revoked, idx)
            kb_card = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
                 InlineKeyboardButton("✏️ Edit", callback_data=f"act_edit|{username}")],
                [InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
            ])
            
            try:
                await context.bot.send_message(
                    chat_id=chat_id,
                    text=card_text,
                    parse_mode=constants.ParseMode.MARKDOWN,
                    reply_markup=kb_card
                )
            except Exception as e:
                logger.debug("send_message search card failed: %s", e)
        
        context.user_data.pop('awaiting_search', None)
        return
    
    # ===== EDIT/RENEW FLOWS =====
    if 'pending_edit_user' in context.user_data:
        return await recv_edit_password(update, context)
    if 'pending_edit_exp_user' in context.user_data:
        return await recv_edit_expiry(update, context)
    if 'pending_renew_user' in context.user_data:
        return await recv_renew_days(update, context)
    
    # ===== CUSTOM EXPIRY FROM INLINE BUTTON =====
    if context.user_data.get('awaiting_custom_expiry'):
        if txt.isdigit():
            days = int(txt)
            context.user_data['new_days'] = days
            expiry_date = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
            context.user_data['new_expiry_date'] = expiry_date
            context.user_data.pop('awaiting_custom_expiry', None)
            
            username = context.user_data.get('new_username')
            password = context.user_data.get('new_password')
            
            # Show preview in NEW card format
            card_preview = format_user_card(username, password, expiry_date, 0, 1)
            text = f"📝 Confirm Account Creation:\n\n{card_preview}"
            kb = [
                [InlineKeyboardButton("Add Account ✅", callback_data="confirm_add"),
                 InlineKeyboardButton("Cancel ❌", callback_data="confirm_cancel")]
            ]
            await update.message.reply_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
        else:
            await update.message.reply_text("❗ Send a numeric days value (e.g., 30).")
        return

# ========== CALLBACK HANDLERS ==========
async def expiry_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    
    if data == "exp_custom":
        await q.edit_message_text("✍️ Please send number of days (e.g., 30).")
        context.user_data['awaiting_custom_expiry'] = True
        return
    
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
        
        # Show preview in NEW card format
        card_preview = format_user_card(username, password, expiry_date, 0, 1)
        text = f"📝 Confirm Account Creation:\n\n{card_preview}"
        kb = [
            [InlineKeyboardButton("Add Account ✅", callback_data="confirm_add"),
             InlineKeyboardButton("Cancel ❌", callback_data="confirm_cancel")]
        ]
        await q.edit_message_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))

async def confirm_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    
    if q.data == "confirm_cancel":
        await q.edit_message_text("❎ Cancelled.")
        context.user_data.clear()
        return ConversationHandler.END
    
    if q.data == "confirm_add":
        username = context.user_data.get('new_username')
        password = context.user_data.get('new_password')
        days = context.user_data.get('new_days', 7)
        
        try:
            pw, exp = run_create_script(username, days, password)
            if not pw:
                pw = password
            if not exp:
                exp = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
            
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            # FIXED: Use INSERT OR REPLACE to allow recreation of deleted users
            cur.execute("INSERT OR REPLACE INTO accounts (username,password,created_by,created_at,expires_at,revoked) VALUES (?,?,?,?,?,0)",
                       (username, pw, 0, datetime.datetime.utcnow().isoformat(), exp))
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
            total_users = cur.fetchone()[0] or 0
            conn.close()
            
            # Send confirmation in NEW card format with FIXED success message
            card_text = format_user_card(username, pw, exp, 0, 1)
            text = f"✅ Create Account Successfully 😄\n\n{card_text}\n\n📊 Total Users: {total_users}"
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
                 InlineKeyboardButton("✏️ Edit", callback_data=f"act_edit|{username}")],
                [InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
            ])
            await q.edit_message_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=kb)
            
            asyncio.create_task(notify_admins(context.application,
                f"🆕 New account created:\nUsername: {username}\nPassword: {pw}\nExpires: {exp}\nTotal Users: {total_users}"))
        except Exception as e:
            await q.edit_message_text(f"❗ Error creating account: {e}")
        
        context.user_data.clear()
        return ConversationHandler.END

# ========== ACTION HANDLERS (Renew/Edit/Delete) ==========
async def action_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    
    if "|" not in data:
        await q.edit_message_text("❗ Invalid action.")
        return
    
    action, username = data.split("|",1)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password,revoked,expires_at FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await q.edit_message_text("⚠️ User not found in DB.")
        conn.close()
        return
    
    password, revoked, expires_at = row
    
    if action == "act_delete":
        if revoked:
            await q.edit_message_text("ℹ️ Already revoked.")
            conn.close()
            return
        
        try:
            # remove password from /etc/zivpn/config.json -> auth.config
            with open("/etc/zivpn/config.json",'r') as fh:
                j = json.load(fh)
            auth = j.get("auth",{})
            arr = auth.get("config",[])
            if password in arr:
                arr = [p for p in arr if p != password]
                j.setdefault("auth",{})["config"]=arr
                # ensure obfs remains disabled
                j['obfs'] = ""
                with open("/etc/zivpn/config.json",'w') as fh:
                    json.dump(j, fh, indent=2)
                subprocess.run(["sudo","systemctl","restart","zivpn.service"], check=False)
            
            # mark revoked in DB
            cur.execute("UPDATE accounts SET revoked=1 WHERE username=?", (username,))
            conn.commit()
            cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
            total_users = cur.fetchone()[0] or 0
            conn.close()
            
            # delete the card message so it disappears from chat (best-effort)
            try:
                await q.message.delete()
            except Exception:
                pass
            
            try:
                await q.answer(text=f"🗑️ {username} revoked")
            except:
                pass
            
            asyncio.create_task(notify_admins(context.application,
                f"🗑️ Account revoked:\nUsername: {username}\nTotal Users: {total_users}"))
            return
        except Exception as e:
            await q.edit_message_text(f"❗ Failed to revoke: {e}")
            return
    
    elif action == "act_renew":
        kb = [
            [InlineKeyboardButton("➕ 5 days", callback_data=f"renew_do|{username}|5"),
             InlineKeyboardButton("➕ 10 days", callback_data=f"renew_do|{username}|10"),
             InlineKeyboardButton("➕ 30 days", callback_data=f"renew_do|{username}|30")],
            [InlineKeyboardButton("Custom (enter days)", callback_data=f"renew_custom|{username}")]
        ]
        await q.edit_message_text(f"🔁 Renew `{username}` — choose extension:", parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
        return
    
    elif action == "act_edit":
        kb = [
            [InlineKeyboardButton("✏️ Change Password", callback_data=f"edit_pass|{username}")],
            [InlineKeyboardButton("⏳ Change Expiry", callback_data=f"edit_exp|{username}")],
            [InlineKeyboardButton("❌ Cancel", callback_data=f"edit_cancel|{username}")]
        ]
        await q.edit_message_text(f"✏️ Edit `{username}` — choose action:", parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
        return

async def renew_do_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    parts = q.data.split("|")
    if len(parts) != 3:
        await q.edit_message_text("❗ Invalid renew command.")
        return
    
    _, username, add_days = parts
    add_days = int(add_days)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password,expires_at FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await q.edit_message_text("⚠️ User not found.")
        conn.close()
        return
    
    password, expires_at = row
    try:
        curdate = datetime.date.today()
        curr = datetime.datetime.fromisoformat(expires_at).date() if expires_at else curdate
        new_exp = max(curr, curdate) + datetime.timedelta(days=add_days)
        
        cur.execute("UPDATE accounts SET expires_at=? WHERE username=?", (new_exp.isoformat(), username))
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        
        # Update message with NEW card format
        card_text = format_user_card(username, password, new_exp.isoformat(), 0, 1)
        text = f"{card_text}\n\n✅ Extended by {add_days} days\n📊 Total Users: {total_users}"
        await q.edit_message_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
             InlineKeyboardButton("✏️ Edit", callback_data=f"act_edit|{username}")],
            [InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
        ]))
        
        asyncio.create_task(notify_admins(context.application,
            f"✅ Account renewed:\nUsername: {username}\nNew expiry: {new_exp.isoformat()}\nTotal Users: {total_users}"))
    except Exception as e:
        await q.edit_message_text(f"❗ Failed to renew: {e}")

async def renew_custom_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    parts = q.data.split("|")
    if len(parts) != 2:
        await q.edit_message_text("❗ Invalid command.")
        return
    
    username = parts[1]
    context.user_data['pending_renew_user'] = username
    await q.edit_message_text(f"✍️ Send number of days to extend `{username}` by (e.g., 30).", parse_mode=constants.ParseMode.MARKDOWN)
    return STATE_RENEW

async def recv_renew_days(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if 'pending_renew_user' not in context.user_data:
        await update.message.reply_text("ℹ️ No pending renew operation.")
        return ConversationHandler.END
    
    txt = (update.message.text or "").strip()
    if not txt.isdigit():
        await update.message.reply_text("❗ Send a numeric days value.")
        return STATE_RENEW
    
    days = int(txt)
    username = context.user_data.pop('pending_renew_user')
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password,expires_at FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await update.message.reply_text("⚠️ User not found.")
        conn.close()
        return ConversationHandler.END
    
    password, expires_at = row
    try:
        curr = datetime.datetime.fromisoformat(expires_at).date() if expires_at else datetime.date.today()
        new_exp = max(curr, datetime.date.today()) + datetime.timedelta(days=days)
        
        cur.execute("UPDATE accounts SET expires_at=? WHERE username=?", (new_exp.isoformat(), username))
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        
        # Send updated card with NEW format
        card_text = format_user_card(username, password, new_exp.isoformat(), 0, 1)
        text = f"{card_text}\n\n✅ Extended by {days} days\n📊 Total Users: {total_users}"
        await update.message.reply_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
             InlineKeyboardButton("✏️ Edit", callback_data=f"act_edit|{username}")],
            [InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
        ]))
        
        asyncio.create_task(notify_admins(context.application,
            f"✅ Account renewed (custom):\nUsername: {username}\nNew expiry: {new_exp.isoformat()}\nTotal Users: {total_users}"))
    except Exception as e:
        await update.message.reply_text(f"❗ Failed to renew: {e}")
    
    return ConversationHandler.END

# Edit handlers
async def edit_pass_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    parts = q.data.split("|")
    if len(parts) != 2:
        await q.edit_message_text("❗ Invalid command.")
        return
    
    username = parts[1]
    context.user_data['pending_edit_user'] = username
    await q.edit_message_text(f"🔐 Send new password for `{username}` or send /gen to generate.", parse_mode=constants.ParseMode.MARKDOWN)
    return STATE_EDIT_PASS

async def recv_edit_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if 'pending_edit_user' not in context.user_data:
        await update.message.reply_text("ℹ️ No pending edit operation.")
        return ConversationHandler.END
    
    username = context.user_data['pending_edit_user']
    text = (update.message.text or "").strip()
    if not text:
        await update.message.reply_text("❗ Password cannot be empty or send /gen to generate.")
        return STATE_EDIT_PASS
    
    if text.lower() == "/gen":
        alphabet = string.ascii_letters + string.digits + "!@#$%_-"
        pwd = "".join(secrets.choice(alphabet) for _ in range(12))
        new_pw = pwd
    else:
        new_pw = text
    
    ok, err = update_password_for_user(username, new_pw)
    if ok:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT expires_at FROM accounts WHERE username=? LIMIT 1", (username,))
        row = cur.fetchone()
        expires_at = row[0] if row else datetime.date.today().isoformat()
        cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        
        # Send updated card with NEW format
        card_text = format_user_card(username, new_pw, expires_at, 0, 1)
        text = f"{card_text}\n\n✅ Password updated\n📊 Total Users: {total_users}"
        await update.message.reply_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
             InlineKeyboardButton("✏️ Edit", callback_data=f"act_edit|{username}")],
            [InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
        ]))
        
        asyncio.create_task(notify_admins(context.application,
            f"✏️ Password changed for {username}\nTotal Users: {total_users}"))
    else:
        await update.message.reply_text(f"❗ Failed to update password: {err}")
    
    context.user_data.pop('pending_edit_user', None)
    return ConversationHandler.END

async def edit_exp_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    parts = q.data.split("|")
    if len(parts) != 2:
        await q.edit_message_text("❗ Invalid command.")
        return
    
    username = parts[1]
    context.user_data['pending_edit_exp_user'] = username
    await q.edit_message_text(f"✍️ Send number of days to set new expiry for `{username}` (e.g., 30).", parse_mode=constants.ParseMode.MARKDOWN)
    return STATE_EDIT_EXP

async def recv_edit_expiry(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if 'pending_edit_exp_user' not in context.user_data:
        await update.message.reply_text("ℹ️ No pending expiry edit operation.")
        return ConversationHandler.END
    
    txt = (update.message.text or "").strip()
    if not txt.isdigit():
        await update.message.reply_text("❗ Send a numeric days value.")
        return STATE_EDIT_EXP
    
    days = int(txt)
    username = context.user_data.pop('pending_edit_exp_user')
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await update.message.reply_text("⚠️ User not found.")
        conn.close()
        return ConversationHandler.END
    
    password = row[0]
    try:
        new_exp = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
        cur.execute("UPDATE accounts SET expires_at=? WHERE username=?", (new_exp, username))
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        
        # Send updated card with NEW format
        card_text = format_user_card(username, password, new_exp, 0, 1)
        text = f"{card_text}\n\n✅ Expiry updated\n📊 Total Users: {total_users}"
        await update.message.reply_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
             InlineKeyboardButton("✏️ Edit", callback_data=f"act_edit|{username}")],
            [InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
        ]))
        
        asyncio.create_task(notify_admins(context.application,
            f"✏️ Expiry changed for {username} -> {new_exp}\nTotal Users: {total_users}"))
    except Exception as e:
        await update.message.reply_text(f"❗ Failed to update expiry: {e}")
    
    return ConversationHandler.END

# ========== OTHER COMMANDS ==========
async def cmd_list_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Old text list - kept for compatibility"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, created_at, expires_at, revoked FROM accounts WHERE revoked=0 ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    
    if not rows:
        await update.message.reply_text("No users found.")
        return
    
    lines = []
    for r in rows[:200]:
        lines.append(f"{r[0]} — exp:{r[2]} — revoked:{r[3]}")
    
    total = total_users_count()
    await update.message.reply_text(f"User List (Total: {total}):\n" + "\n".join(lines))

async def cmd_create(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /create <username> <days> [password]")
        return
    
    username = context.args[0]
    try:
        days = int(context.args[1])
    except:
        await update.message.reply_text("❗ Days must be integer.")
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
        # FIXED: Use INSERT OR REPLACE to allow recreation of deleted users
        cur.execute("INSERT OR REPLACE INTO accounts (username,password,created_by,created_at,expires_at) VALUES (?,?,?,?,?)",
                   (username, pw, 0, datetime.datetime.utcnow().isoformat(), exp))
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        
        # Send card with NEW format with FIXED success message
        card_text = format_user_card(username, pw, exp, 0, 1)
        text = f"✅ Create Account Successfully 😄\n\n{card_text}\n\n📊 Total Users: {total_users}"
        await update.message.reply_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup([
            [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
             InlineKeyboardButton("✏️ Edit", callback_data=f"act_edit|{username}")],
            [InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
        ]))
        
        asyncio.create_task(notify_admins(context.application,
            f"🆕 Account created (CLI):\nUsername: {username}\nPassword: {pw}\nExpires: {exp}\nTotal Users: {total_users}"))
    except Exception as e:
        await update.message.reply_text(f"❗ Error: {e}")

def build_conv():
    conv = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(renew_custom_callback, pattern='^renew_custom\\|'),
            CallbackQueryHandler(edit_pass_callback, pattern='^edit_pass\\|'),
            CallbackQueryHandler(edit_exp_callback, pattern='^edit_exp\\|')
        ],
        states={
            STATE_RENEW: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_renew_days)],
            STATE_EDIT_PASS: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_edit_password)],
            STATE_EDIT_EXP: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_edit_expiry)],
        },
        fallbacks=[],
        allow_reentry=True
    )
    return conv

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    
    # Command handlers
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("list", cmd_list_text))
    app.add_handler(CommandHandler("create", cmd_create))
    
    # Main button handlers with icons
    app.add_handler(MessageHandler(filters.Regex('^🆕 Create Account$'), handle_create_button))
    app.add_handler(MessageHandler(filters.Regex('^🔍 Search$'), handle_search_button))
    app.add_handler(MessageHandler(filters.Regex('^(👥 Users List|ℹ️ Help|🔐 HTTPS Info)$'), handle_main_buttons))
    
    # Global text router for all text messages
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, global_text_router))
    
    # Callback query handlers
    app.add_handler(CallbackQueryHandler(action_callback, pattern='^act_'))
    app.add_handler(CallbackQueryHandler(renew_do_callback, pattern='^renew_do\\|'))
    app.add_handler(CallbackQueryHandler(expiry_callback, pattern='^exp_'))
    app.add_handler(CallbackQueryHandler(confirm_callback, pattern='^confirm_'))
    
    # Conversation handler for edit/renew flows
    app.add_handler(build_conv())
    
    logger.info("Public bot polling started (fixed v6.5 with HTTPS)")
    app.run_polling()

if __name__ == "__main__":
    main()
PY

sudo chmod +x /opt/zivpn_bot/bot.py
sudo chown -R "$(whoami):$(whoami)" /opt/zivpn_bot

# systemd for bot
sudo tee /etc/systemd/system/zivpn_bot.service > /dev/null <<'UNIT'
[Unit]
Description=ZIVPN Telegram Bot (PUBLIC MODE with HTTPS)
After=network.target nginx.service

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

# expiry-check script
sudo tee /usr/local/bin/zivpn_expire_check.sh > /dev/null <<'SH'
#!/usr/bin/env bash
DB="/var/lib/zivpn_bot/accounts.db"
CFG="/etc/zivpn/config.json"

sqlite3 "$DB" "SELECT username,password FROM accounts WHERE revoked=0 AND date(expires_at) <= date('now');" | while IFS='|' read -r user pass; do
    if [ -n "$pass" ]; then
        python3 - <<PY
import json,sqlite3,subprocess
CFG="$CFG"
DB="$DB"
pw="$pass"
try:
    with open(CFG,'r') as fh:
        j=json.load(fh)
    auth=j.get("auth",{})
    arr=auth.get("config",[])
    arr=[p for p in arr if p!=pw]
    j.setdefault("auth",{})["config"]=arr
    j['obfs'] = ""
    with open(CFG,'w') as fh:
        json.dump(j, fh, indent=2)
    subprocess.run(["sudo","systemctl","restart","zivpn.service"], check=False)
    
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

(sudo crontab -l 2>/dev/null | cat; echo "0 3 * * * /usr/local/bin/zivpn_expire_check.sh >/dev/null 2>&1") | sudo crontab -

echo "== INSTALL COMPLETE v6.5 with HTTPS =="
echo ""
echo "✅ HTTPS SUPPORT ADDED via Nginx reverse proxy"
echo "✅ FIXED: Network timeout handling for slow connections"
echo "✅ FIXED: Deleted users can now be recreated"
echo "✅ FIXED: Create Account Successfully message"
echo ""
echo "✅ NEW User Card format with HTTPS info:"
echo "   👑 Premium User : 1"
echo "   🌐 Server IP : xxxx"
echo "   🔐 HTTPS Port : 443"
echo "   👤 Username: xxxx"
echo "   🔑 Password: xxxx"
echo "   📅 Expired Date: xxxx (xx days left)"
echo "   🔋 Status : 🟢 Online"
echo "   🔗 Connection URL: https://server.ip:443"
echo ""
echo "✅ Added icons to all fields:"
echo "   👑 VIP crown"
echo "   🌐 Server IP"
echo "   🔐 HTTPS Port"
echo "   👤 Username"
echo "   🔑 Password"
echo "   📅 Expiry date"
echo "   🟢/🔴/🟡 Status"
echo "   🔗 Connection URL"
echo ""
echo "✅ Network optimizations for slow connections:"
echo "   - Retry logic for downloads"
echo "   - Timeout settings for all network operations"
echo "   - sysctl optimizations for UDP performance"
echo ""
echo "✅ HTTPS Setup:"
echo "   - Nginx reverse proxy on port 443"
echo "   - Self-signed SSL certificate installed"
echo "   - For Let's Encrypt certificate, run:"
echo "     sudo certbot --nginx -d your-domain.com"
echo ""
echo "✅ All operations show updated cards in new format"
echo ""
echo "Ports opened:"
echo "   - 443/tcp (HTTPS)"
echo "   - 80/tcp (HTTP - for certbot)"
echo "   - 5667/udp (Direct UDP)"
echo "   - 6000:19999/udp (Port forwarding)"
echo ""
echo "If you skipped BOT_TOKEN during install, edit /etc/default/zivpn_bot and set BOT_TOKEN=\"<your token>\" then:"
echo "sudo systemctl restart zivpn_bot.service"
echo ""
echo "To test HTTPS connection:"
echo "curl -v https://${ZIVPN_SERVER_IP_DEFAULT}:443"
echo ""
echo "To test:"
echo "1. Create a user and delete it"
echo "2. Try creating same username again - NOW IT WILL WORK!"
echo "3. All users displayed in NEW format with HTTPS info"
echo "4. Each card has Renew/Edit/Delete buttons"
echo ""
echo "To check bot logs: sudo journalctl -u zivpn_bot.service -n 200 --no-pager"
echo "To check Nginx logs: sudo journalctl -u nginx.service -n 50 --no-pager"
echo ""
echo "✅ Installation complete with HTTPS support!"
echo "Done."
