#!/usr/bin/env bash
# install_zivpn_public_fixed_v3.sh
# Full fixed installer for ZIVPN + Telegram bot (Edit password fix + Search in Menu)
set -euo pipefail
IFS=$'\n\t'

### ===== CONFIG (edit BEFORE running if needed) =====
BOT_TOKEN_DEFAULT=""   # leave empty to be prompted at install time
ADMIN_IDS_DEFAULT=""   # comma separated Telegram IDs for admin notifications (optional)
ZIVPN_SERVER_IP_DEFAULT="$(curl -s https://ifconfig.co || echo "your.server.ip")"
### ==================================================

echo "== ZIVPN + Public Telegram Bot Installer (fixed v3) =="
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
if 'config' in j and isinstance(j.get('config'),list):
    for p in j['config']:
        if p not in j['auth'].get('config',[]):
            j['auth'].setdefault('config',[]).append(p)
    del j['config']
    changed=True
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

if [ ! -f "$CFG_FILE" ]; then
  echo '{"listen":":5667","auth":{"mode":"passwords","config":[]}}' > "$CFG_FILE"
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
if not isinstance(j['auth'].get('config',[]),list):
    j['auth']['config']=list(j['auth'].get('config',[])) if j['auth'].get('config') else []
if pw not in j['auth']['config']:
    j['auth']['config'].append(pw)
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
  sudo systemctl.restart zivpn.service >/dev/null 2>&1 || true || sudo systemctl restart zivpn.service || true
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

# Bot script (fixed v3)
sudo tee /opt/zivpn_bot/bot.py > /dev/null <<'PY'
#!/usr/bin/env python3
# bot.py - Public ZIVPN bot (fixed v3: Edit password fixed + Search)
import os, sqlite3, subprocess, datetime, json, logging, asyncio, shutil, math, secrets, string
import psutil
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, constants
from telegram.ext import ApplicationBuilder, CommandHandler, ConversationHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

ENV_FILE="/etc/default/zivpn_bot"
DB_PATH="/var/lib/zivpn_bot/accounts.db"
CREATE_SCRIPT="/usr/local/bin/create_vpn_user.sh"

# States: add STATE_SEARCH for search conversations
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

logger.info("Started zivpn public bot (fixed v3) admin_notify=%s", ADMIN_IDS)

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
        return {"cpu": 0.0, "ram_used_mb": 0, "ram_total_mb": 0, "ram_percent": 0, "disk_used_gb": 0.0, "disk_total_gb": 0.0, "disk_percent": 0}

# Helper: update password for user (remove old pw, add new pw, update DB, restart zivpn)
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
        with open(fn,'w') as fh:
            json.dump(j, fh, indent=2)
        subprocess.run(["sudo","systemctl","restart","zivpn.service"], check=False)
        cur.execute("UPDATE accounts SET password=? WHERE username=?", (new_password, username))
        conn.commit()
        conn.close()
        return True, None
    except Exception as e:
        return False, str(e)

# Search helper: returns list of rows matching username pattern (case-insensitive)
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

# Handlers
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    total = total_users_count()
    stats = get_server_stats()
    cpu_line = f"⚙️ CPU: {stats['cpu']:.1f}%"
    ram_line = f"🧠 RAM: {stats['ram_used_mb']}MB / {stats['ram_total_mb']}MB ({stats['ram_percent']}%)"
    disk_line = f"💾 STORAGE: {stats['disk_used_gb']}GB / {stats['disk_total_gb']}GB ({stats['disk_percent']}%)"
    body = (f"📊 Total Users: `{total}`\n\n"
            f"{cpu_line}\n{ram_line}\n{disk_line}\n\n"
            "Menu:")
    kb = [
        [InlineKeyboardButton("Create Account ➕", callback_data="menu_create"),
         InlineKeyboardButton("User List 📋", callback_data="menu_list")],
        [InlineKeyboardButton("Search 🔎", callback_data="menu_search"),
         InlineKeyboardButton("Help ❓", callback_data="menu_help")]
    ]
    await update.message.reply_text(body, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))

async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    if q.data == "menu_create":
        await q.edit_message_text("✅ Create Account — Step 1:\nSend the *username* you want to add.", parse_mode=constants.ParseMode.MARKDOWN)
        return STATE_USERNAME
    if q.data == "menu_list":
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT username,password,created_at,expires_at,revoked FROM accounts WHERE revoked=0 ORDER BY id DESC")
        rows = cur.fetchall()
        conn.close()
        if not rows:
            await q.edit_message_text("No users found.")
            return
        chat_id = q.message.chat_id
        for r in rows[:200]:
            username, password, created_at, expires_at, revoked = r
            left = days_left(expires_at)
            # determine status emoji & label
            if revoked:
                status_emoji = "🔴"
                status_label = "Expired"
            else:
                if user_online(password) and left > 0:
                    status_emoji = "🟢"
                    status_label = "Online"
                elif left <= 3 and left > 0:
                    status_emoji = "🟡"
                    status_label = "Expiring"
                else:
                    status_emoji = "🔴"
                    status_label = "Expired"
            left_text = f"{left} days left" if left>0 else "expired"
            body = (
                f"👤 *User Card*\n\n"
                f"🏷️ Username: `{username}`\n"
                f"🔑 Password: `{password}`\n"
                f"📡 Server IP: `{ZIVPN_SERVER_IP}`\n"
                f"⏳ Expires: `{expires_at}` ({left_text})\n"
                f"Status: {status_emoji} {status_label}"
            )
            kb_card = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
                 InlineKeyboardButton("✏️ Edit", callback_data=f"act_edit|{username}")],
                [InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
            ])
            try:
                await context.bot.send_message(chat_id=chat_id, text=body, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=kb_card)
            except Exception as e:
                logger.debug("send_message card failed: %s", e)
        try:
            await q.edit_message_text("Displayed user cards.")
        except:
            pass
        return
    if q.data == "menu_search":
        # prompt user to send username query
        await q.edit_message_text("🔎 Send username to search (partial matches allowed).", parse_mode=constants.ParseMode.MARKDOWN)
        # set pending search marker in user_data and return STATE_SEARCH
        context.user_data['awaiting_search'] = True
        return STATE_SEARCH
    if q.data == "menu_help":
        await q.edit_message_text("Public bot: anyone can create, view, renew, edit or delete accounts.\nUse Create Account to add users. Use User List / Search to manage.", parse_mode=constants.ParseMode.MARKDOWN)
        return

# Create flow (unchanged)
async def recv_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    if not text:
        await update.message.reply_text("❗ Username cannot be empty.")
        return STATE_USERNAME
    context.user_data['new_username'] = text
    await update.message.reply_text("🔐 Step 2: Send password you want or send /gen to generate.")
    return STATE_PASSWORD

async def recv_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    if not text:
        await update.message.reply_text("❗ Password cannot be empty or send /gen to generate.")
        return STATE_PASSWORD
    if text.lower() == "/gen":
        alphabet = string.ascii_letters + string.digits + "!@#$%_-"
        pwd = "".join(secrets.choice(alphabet) for _ in range(12))
        context.user_data['new_password'] = pwd
        await update.message.reply_text(f"🧾 Generated password: `{pwd}`", parse_mode=constants.ParseMode.MARKDOWN)
    else:
        context.user_data['new_password'] = text
        await update.message.reply_text("✅ Password saved.")
    kb = [
        [InlineKeyboardButton("5 days", callback_data="exp_5"),
         InlineKeyboardButton("10 days", callback_data="exp_10"),
         InlineKeyboardButton("15 days", callback_data="exp_15")],
        [InlineKeyboardButton("Custom (enter days)", callback_data="exp_custom")]
    ]
    await update.message.reply_text("⏳ Choose expiry (or type a number like 30 or 60):", reply_markup=InlineKeyboardMarkup(kb))
    return STATE_EXPIRY

async def expiry_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    if data == "exp_custom":
        await q.edit_message_text("✍️ Please send number of days (e.g., 30).")
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
        text = (f"📝 Confirm:\n\nServer IP: `{ZIVPN_SERVER_IP}`\nUsername: `{username}`\nPassword: `{password}`\nExpires: `{expiry_date}`")
        kb = [
            [InlineKeyboardButton("Add Account ✅", callback_data="confirm_add"),
             InlineKeyboardButton("Cancel ❌", callback_data="confirm_cancel")]
        ]
        await q.edit_message_text(text, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=InlineKeyboardMarkup(kb))
    return

async def recv_custom_days(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (update.message.text or "").strip()
    if not txt.isdigit():
        await update.message.reply_text("❗ Send a numeric days value (e.g., 30).")
        return STATE_EXPIRY
    days = int(txt)
    context.user_data['new_days'] = days
    expiry_date = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    context.user_data['new_expiry_date'] = expiry_date
    username = context.user_data.get('new_username')
    password = context.user_data.get('new_password')
    text = (f"📝 Confirm:\n\nServer IP: `{ZIVPN_SERVER_IP}`\nUsername: `{username}`\nPassword: `{password}`\nExpires: `{expiry_date}`")
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
        await q.edit_message_text("❎ Cancelled.")
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
            cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
            total_users = cur.fetchone()[0] or 0
            conn.close()
            text = (f"✅ Account created\n\nServer IP: `{ZIVPN_SERVER_IP}`\nUsername: `{username}`\nPassword: `{pw}`\nExpires: `{exp}`\n\nTotal Users: `{total_users}`")
            await q.edit_message_text(text, parse_mode=constants.ParseMode.MARKDOWN)
            asyncio.create_task(notify_admins(context.application, f"🆕 New account created:\nUsername: {username}\nPassword: {pw}\nExpires: {exp}\nTotal Users: {total_users}"))
        except sqlite3.IntegrityError:
            await q.edit_message_text("⚠️ Username exists. Revoke first or choose different username.")
        except Exception as e:
            await q.edit_message_text(f"❗ Error creating account: {e}")
        context.user_data.clear()
        return ConversationHandler.END

# Actions: renew / delete / edit
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
    cur.execute("SELECT password,revoked FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await q.edit_message_text("⚠️ User not found in DB.")
        conn.close()
        return
    password, revoked = row
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
            # reply a small ack to the user
            try:
                await q.answer(text=f"🗑️ {username} revoked")
            except:
                pass
            asyncio.create_task(notify_admins(context.application, f"🗑️ Account revoked:\nUsername: {username}\nTotal Users: {total_users}"))
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

# Renew handlers
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
    cur.execute("SELECT expires_at FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await q.edit_message_text("⚠️ User not found.")
        conn.close()
        return
    expires_at = row[0]
    try:
        curdate = datetime.date.today()
        curr = datetime.datetime.fromisoformat(expires_at).date() if expires_at else curdate
        new_exp = max(curr, curdate) + datetime.timedelta(days=add_days)
        cur.execute("UPDATE accounts SET expires_at=? WHERE username=?", (new_exp.isoformat(), username))
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        await q.edit_message_text(f"✅ `{username}` extended by {add_days} days. New expiry: {new_exp.isoformat()}\nTotal Users: `{total_users}`", parse_mode=constants.ParseMode.MARKDOWN)
        asyncio.create_task(notify_admins(context.application, f"✅ Account renewed:\nUsername: {username}\nNew expiry: {new_exp.isoformat()}\nTotal Users: {total_users}"))
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
    cur.execute("SELECT expires_at FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await update.message.reply_text("⚠️ User not found.")
        conn.close()
        return ConversationHandler.END
    expires_at = row[0]
    try:
        curr = datetime.datetime.fromisoformat(expires_at).date() if expires_at else datetime.date.today()
        new_exp = max(curr, datetime.date.today()) + datetime.timedelta(days=days)
        cur.execute("UPDATE accounts SET expires_at=? WHERE username=?", (new_exp.isoformat(), username))
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        await update.message.reply_text(f"✅ `{username}` extended by {days} days. New expiry: {new_exp.isoformat()}\nTotal Users: `{total_users}`", parse_mode=constants.ParseMode.MARKDOWN)
        asyncio.create_task(notify_admins(context.application, f"✅ Account renewed (custom):\nUsername: {username}\nNew expiry: {new_exp.isoformat()}\nTotal Users: {total_users}"))
    except Exception as e:
        await update.message.reply_text(f"❗ Failed to renew: {e}")
    return ConversationHandler.END

# Edit handlers (fixed)
async def edit_pass_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    parts = q.data.split("|")
    if len(parts) != 2:
        await q.edit_message_text("❗ Invalid command.")
        return
    username = parts[1]
    # Store pending edit username in user_data for this chat
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
        await update.message.reply_text(f"✅ Password for `{username}` updated to `{new_pw}`", parse_mode=constants.ParseMode.MARKDOWN)
        asyncio.create_task(notify_admins(context.application, f"✏️ Password changed for {username}"))
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
    cur.execute("SELECT expires_at FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await update.message.reply_text("⚠️ User not found.")
        conn.close()
        return ConversationHandler.END
    try:
        new_exp = (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
        cur.execute("UPDATE accounts SET expires_at=? WHERE username=?", (new_exp, username))
        conn.commit()
        conn.close()
        await update.message.reply_text(f"✅ `{username}` expiry set to {new_exp}", parse_mode=constants.ParseMode.MARKDOWN)
        asyncio.create_task(notify_admins(context.application, f"✏️ Expiry changed for {username} -> {new_exp}"))
    except Exception as e:
        await update.message.reply_text(f"❗ Failed to update expiry: {e}")
    return ConversationHandler.END

# Search handlers
async def recv_search_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if 'awaiting_search' not in context.user_data:
        await update.message.reply_text("ℹ️ No pending search. Use the Search 🔎 button in the Menu.")
        return ConversationHandler.END
    qstr = (update.message.text or "").strip()
    if not qstr:
        await update.message.reply_text("❗ Send a username pattern to search (e.g., 'vip').")
        return STATE_SEARCH
    # perform search
    rows = search_users_by_username(qstr, limit=200)
    if not rows:
        await update.message.reply_text("No users matched your query.")
        context.user_data.pop('awaiting_search', None)
        return ConversationHandler.END
    chat_id = update.message.chat_id
    for r in rows:
        username, password, created_at, expires_at, revoked = r
        left = days_left(expires_at)
        if revoked:
            status_emoji = "🔴"
            status_label = "Expired"
        else:
            if user_online(password) and left > 0:
                status_emoji = "🟢"
                status_label = "Online"
            elif left <= 3 and left > 0:
                status_emoji = "🟡"
                status_label = "Expiring"
            else:
                status_emoji = "🔴"
                status_label = "Expired"
        left_text = f"{left} days left" if left>0 else "expired"
        body = (
            f"👤 *User Card*\n\n"
            f"🏷️ Username: `{username}`\n"
            f"🔑 Password: `{password}`\n"
            f"📡 Server IP: `{ZIVPN_SERVER_IP}`\n"
            f"⏳ Expires: `{expires_at}` ({left_text})\n"
            f"Status: {status_emoji} {status_label}"
        )
        kb_card = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔁 Renew", callback_data=f"act_renew|{username}"),
             InlineKeyboardButton("✏️ Edit", callback_data=f"act_edit|{username}")],
            [InlineKeyboardButton("🗑️ Delete", callback_data=f"act_delete|{username}")]
        ])
        try:
            await context.bot.send_message(chat_id=chat_id, text=body, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=kb_card)
        except Exception as e:
            logger.debug("send_message search card failed: %s", e)
    context.user_data.pop('awaiting_search', None)
    return ConversationHandler.END

async def cmd_list_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
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
        cur.execute("INSERT OR REPLACE INTO accounts (username,password,created_by,created_at,expires_at,revoked) VALUES (?,?,?,?,0,0)",
                    (username, pw, 0, datetime.datetime.utcnow().isoformat(), exp))
        conn.commit()
        cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
        total_users = cur.fetchone()[0] or 0
        conn.close()
        await update.message.reply_text(f"✅ Created: {username}\n🔑 Password: {pw}\n⏳ Expires: {exp}\n📊 Total Users: {total_users}")
        asyncio.create_task(notify_admins(context.application, f"🆕 Account created (CLI):\nUsername: {username}\nPassword: {pw}\nExpires: {exp}\nTotal Users: {total_users}"))
    except Exception as e:
        await update.message.reply_text(f"❗ Error: {e}")

def build_conv():
    # Conversation handler entry_points include menu + renew_custom + edit handlers + search start
    conv = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(menu_callback, pattern='^menu_'),
            CallbackQueryHandler(renew_custom_callback, pattern='^renew_custom\\|'),
            CallbackQueryHandler(edit_pass_callback, pattern='^edit_pass\\|'),
            CallbackQueryHandler(edit_exp_callback, pattern='^edit_exp\\|')
        ],
        states={
            STATE_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_username)],
            STATE_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_password)],
            STATE_EXPIRY: [
                CallbackQueryHandler(expiry_callback, pattern='^exp_'),
                MessageHandler(filters.TEXT & ~filters.COMMAND, recv_custom_days),
                CallbackQueryHandler(confirm_callback, pattern='^confirm_')
            ],
            STATE_RENEW: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_renew_days)],
            STATE_EDIT_PASS: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_edit_password)],
            STATE_EDIT_EXP: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_edit_expiry)],
            STATE_SEARCH: [MessageHandler(filters.TEXT & ~filters.COMMAND, recv_search_query)]
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
    # core action handler
    app.add_handler(CallbackQueryHandler(action_callback, pattern='^act_'))
    # renew/do handlers
    app.add_handler(CallbackQueryHandler(renew_do_callback, pattern='^renew_do\\|'))
    # We DO NOT register edit_pass/edit_exp here to avoid duplicate handlers — they are in conv entry_points
    # search uses conv STATE_SEARCH
    app.add_handler(build_conv())
    logger.info("Public bot polling started (fixed v3)")
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
( sudo crontab -l 2>/dev/null | cat; echo "0 3 * * * /usr/local/bin/zivpn_expire_check.sh >/dev/null 2>&1" ) | sudo crontab -

echo "== INSTALL COMPLETE =="
echo "If you skipped BOT_TOKEN during install, edit /etc/default/zivpn_bot and set BOT_TOKEN=\"<your token>\" then: sudo systemctl restart zivpn_bot.service"
echo "To test: open bot and send /start -> Create Account -> User List / Search -> use Renew (Custom), Edit (change pw/expiry), Delete (card removed)"
echo "To check zivpn logs: sudo journalctl -u zivpn.service -f"
echo "Done."
