#!/usr/bin/env bash
# install_zivpn_with_bot.sh
# Full installer: ZIVPN UDP + create_vpn_user helper + Telegram bot integration
# AUTHOR: generated for you
set -euo pipefail
IFS=$'\n\t'

### --- CONFIG (edit if needed) ---
# If you want the installer to embed the BOT token automatically, set BOT_TOKEN below.
# You provided a token in your message — it's included by default here. It's highly recommended
# to rotate the token after testing and instead export BOT_TOKEN and ADMIN_IDS in /etc/default/zivpn_bot
BOT_TOKEN_DEFAULT="8409119937:AAGsRoqiyg-U_caPKsDUpnhzMN8SyG5Y0qw"

# Comma-separated Telegram admin IDs (e.g. "12345678,87654321")
# Please replace with your Telegram numeric user id(s) if you know them
ADMIN_IDS_DEFAULT=""

# Server IP to show to users (optional)
ZIVPN_SERVER_IP_DEFAULT="$(curl -s https://ifconfig.co || echo "your.server.ip")"

### --- END CONFIG ---

echo "== Starting ZIVPN + Telegram bot installer =="

# 1) Basic system update and required packages
echo "-- Updating system and installing dependencies --"
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install -y wget curl openssl python3 python3-venv python3-pip ufw iptables sqlite3

# 2) Install ZIVPN binary + config (from your snippet)
echo "-- Installing ZIVPN binary and default config --"
sudo systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true
sudo wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn
sudo chmod +x /usr/local/bin/zivpn
sudo mkdir -p /etc/zivpn
sudo wget -q https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json || {
  echo "Failed to download default config.json — creating basic fallback."
  cat > /etc/zivpn/config.json <<'EOF'
{
  "config": ["zi"],
  "listen": "0.0.0.0:5667"
}
EOF
}

echo "-- Generating TLS certs (self-signed) --"
sudo openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt

sudo sysctl -w net.core.rmem_max=16777216 1>/dev/null 2>/dev/null || true
sudo sysctl -w net.core.wmem_max=16777216 1>/dev/null 2>/dev/null || true

echo "-- Writing systemd service for zivpn --"
sudo bash -c 'cat > /etc/systemd/system/zivpn.service <<EOF
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
EOF'

sudo systemctl daemon-reload
sudo systemctl enable --now zivpn.service

# 3) Default iptables/ufw rules as in your snippet (port mapping)
NETIF=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || echo "eth0")
echo "-- Configuring firewall/iptables for interface ${NETIF} --"
sudo iptables -t nat -A PREROUTING -i "${NETIF}" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
sudo ufw allow 6000:19999/udp || true
sudo ufw allow 5667/udp || true

echo "-- Cleaning temporary files --"
sudo rm -f zi.* 1>/dev/null 2>/dev/null || true

echo "ZIVPN UDP Installed"

# 4) Create helper script to create account/password and update config.json
echo "-- Creating helper script: /usr/local/bin/create_vpn_user.sh --"
sudo tee /usr/local/bin/create_vpn_user.sh > /dev/null <<'BASH'
#!/usr/bin/env bash
# create_vpn_user.sh <username> <days>
# Adds a generated password to /etc/zivpn/config.json and outputs PASSWORD:<pwd> EXPIRES:<YYYY-MM-DD>

set -euo pipefail
USERNAME="${1:-}"
DAYS="${2:-7}"

if [ -z "$USERNAME" ]; then
  echo "ERROR: username required" >&2
  exit 2
fi

# normalize days
if ! [[ "$DAYS" =~ ^[0-9]+$ ]]; then
  DAYS=7
fi

# generate password (12 chars)
PASSWORD=$(tr -dc 'A-Za-z0-9!@#$%_-' </dev/urandom | head -c12 || echo "zi$(date +%s)" )
EXPIRES=$(date -d "+${DAYS} days" +%F)

# add to /etc/zivpn/config.json (if not already present)
CFG_FILE="/etc/zivpn/config.json"
if ! grep -Fq "\"$PASSWORD\"" "$CFG_FILE"; then
  # insert into JSON array "config"
  TMP="$(mktemp)"
  python3 - <<PY
import json
f = "$CFG_FILE"
with open(f,'r') as fh:
    j = json.load(fh)
arr = j.get("config", [])
if "$PASSWORD" not in arr:
    arr.append("$PASSWORD")
j["config"] = arr
with open("$TMP",'w') as fo:
    json.dump(j, fo, indent=2)
print("$TMP")
PY
  sudo mv "$TMP" "$CFG_FILE"
fi

# PRINT machine-parsable output for the bot
echo "PASSWORD:${PASSWORD} EXPIRES:${EXPIRES}"
BASH

sudo chmod +x /usr/local/bin/create_vpn_user.sh

# 5) Create directory for bot and a python virtualenv
echo "-- Setting up Telegram bot in /opt/zivpn_bot --"
sudo mkdir -p /opt/zivpn_bot
sudo chown "$(whoami):$(whoami)" /opt/zivpn_bot

python3 -m venv /opt/zivpn_bot/venv
/opt/zivpn_bot/venv/bin/pip install --upgrade pip
/opt/zivpn_bot/venv/bin/pip install python-telegram-bot==20.3

# 6) Create sqlite DB location and schema
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

# 7) Write environment defaults file
echo "-- Writing /etc/default/zivpn_bot (edit to change token/admins/server ip) --"
sudo tee /etc/default/zivpn_bot > /dev/null <<EOF
# BOT environment for zivpn_bot
BOT_TOKEN="${BOT_TOKEN_DEFAULT}"
ADMIN_IDS="${ADMIN_IDS_DEFAULT}"
ZIVPN_SERVER_IP="${ZIVPN_SERVER_IP_DEFAULT}"
EOF

sudo chown root:root /etc/default/zivpn_bot
sudo chmod 600 /etc/default/zivpn_bot

# 8) Create the python bot
echo "-- Writing Python bot: /opt/zivpn_bot/bot.py --"
sudo tee /opt/zivpn_bot/bot.py > /dev/null <<'PY'
#!/usr/bin/env python3
# bot.py - Telegram bot for creating ZIVPN passwords
import os, sqlite3, subprocess, datetime, shlex
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

ENV_FILE = "/etc/default/zivpn_bot"

# load env file (simple KEY="VAL" parse)
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
DB_PATH = "/var/lib/zivpn_bot/accounts.db"

if not BOT_TOKEN:
    print("BOT_TOKEN not configured in /etc/default/zivpn_bot. Exiting.")
    raise SystemExit(1)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("ZIVPN bot online. Use /create <username> <days> (admin only)")

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

def run_create_script(username: str, days: int):
    # returns dict(password, expires) or raises
    res = subprocess.run(["/usr/local/bin/create_vpn_user.sh", username, str(days)], capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        raise RuntimeError(res.stderr or res.stdout or "create script failed")
    out = res.stdout.strip()
    parts = {}
    for token in out.split():
        if ":" in token:
            k,v = token.split(":",1)
            parts[k.lower()] = v
    return parts

async def create(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.id):
        await update.message.reply_text("Unauthorized. Your Telegram id is not in ADMIN_IDS.")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /create <username> <days>")
        return
    username = context.args[0].strip()
    try:
        days = int(context.args[1])
        if days <= 0: days = 7
    except:
        days = 7
    try:
        parts = run_create_script(username, days)
    except Exception as e:
        await update.message.reply_text(f"Failed to create VPN user: {e}")
        return
    password = parts.get("password")
    expires = parts.get("expires") or (datetime.date.today() + datetime.timedelta(days=days)).isoformat()
    created_at = datetime.datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO accounts (username,password,created_by,created_at,expires_at) VALUES (?,?,?,?,?)",
                    (username, password, user.id, created_at, expires))
        conn.commit()
    except sqlite3.IntegrityError:
        await update.message.reply_text("Username already exists in DB. Use /revoke then create again or choose another username.")
        conn.close()
        return
    conn.close()

    msg = (f"✅ Account created\n\nUsername: {username}\nPassword: {password}\nExpires: {expires}\nServer: {ZIVPN_SERVER_IP}")
    await update.message.reply_text(msg)

async def list_accounts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.id):
        await update.message.reply_text("Unauthorized.")
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, created_at, expires_at, revoked FROM accounts ORDER BY id DESC LIMIT 50")
    rows = cur.fetchall()
    conn.close()
    if not rows:
        await update.message.reply_text("No accounts.")
        return
    lines = []
    for r in rows:
        lines.append(f"{r[0]} | created {r[1]} | expires {r[2]} | revoked:{r[3]}")
    # chunk message if too long
    chunk = "\n".join(lines)
    await update.message.reply_text("Recent accounts:\n" + chunk)

async def revoke(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not is_admin(user.id):
        await update.message.reply_text("Unauthorized.")
        return
    if len(context.args) < 1:
        await update.message.reply_text("Usage: /revoke <username>")
        return
    username = context.args[0].strip()
    # find password in DB
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT password,revoked FROM accounts WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    if not row:
        await update.message.reply_text("Username not found.")
        conn.close()
        return
    password, revoked = row
    if revoked:
        await update.message.reply_text("Already revoked.")
        conn.close()
        return

    # remove password from /etc/zivpn/config.json
    try:
        import json
        cfg_file = "/etc/zivpn/config.json"
        with open(cfg_file,'r') as fh:
            j = json.load(fh)
        arr = j.get("config", [])
        if password in arr:
            arr = [x for x in arr if x != password]
            j["config"] = arr
            with open(cfg_file,'w') as fh:
                json.dump(j, fh, indent=2)
    except Exception as e:
        await update.message.reply_text(f"Failed to modify config.json: {e}")
        conn.close()
        return

    cur.execute("UPDATE accounts SET revoked=1 WHERE username=?", (username,))
    conn.commit()
    conn.close()
    await update.message.reply_text(f"Revoked {username} (password removed from config)")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("create", create))
    app.add_handler(CommandHandler("list", list_accounts))
    app.add_handler(CommandHandler("revoke", revoke))
    print("Bot polling...")
    app.run_polling()

if __name__ == "__main__":
    main()
PY

sudo chmod +x /opt/zivpn_bot/bot.py
sudo chown -R "$(whoami):$(whoami)" /opt/zivpn_bot

# 9) Create systemd service for the bot
echo "-- Creating systemd service for zivpn_bot --"
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

echo "-- Setup done. zivpn and zivpn_bot services are running (if no errors) --"

# 10) Create daily cron job to revoke expired accounts (runs a small sqlite + config cleanup)
echo "-- Adding daily cron job to revoke expired accounts --"
sudo tee /usr/local/bin/zivpn_expire_check.sh > /dev/null <<'SH'
#!/usr/bin/env bash
DB="/var/lib/zivpn_bot/accounts.db"
CFG="/etc/zivpn/config.json"
date_today=$(date +%F)
# find expired and not yet revoked
sqlite3 "$DB" "SELECT username,password FROM accounts WHERE revoked=0 AND date(expires_at) <= date('now');" | while IFS='|' read -r user pass; do
  if [ -n "$pass" ]; then
    # remove from config.json
    python3 - <<PY
import json
f="$CFG"
try:
    with open(f,'r') as fh:
        j=json.load(fh)
    arr=j.get("config",[])
    arr=[p for p in arr if p!="$pass"]
    j["config"]=arr
    with open(f,'w') as fh:
        json.dump(j, fh, indent=2)
    import sqlite3
    conn=sqlite3.connect("$DB")
    conn.execute("UPDATE accounts SET revoked=1 WHERE password=?",("$pass",))
    conn.commit()
    conn.close()
except Exception as e:
    pass
PY
  fi
done
SH

sudo chmod +x /usr/local/bin/zivpn_expire_check.sh
# install cron (daily)
( sudo crontab -l 2>/dev/null | cat; echo "0 3 * * * /usr/local/bin/zivpn_expire_check.sh >/dev/null 2>&1" ) | sudo crontab -

echo ""
echo "== IMPORTANT NEXT STEPS =="
echo "1) Edit /etc/default/zivpn_bot and set:"
echo "   BOT_TOKEN=\"<your-token>\""
echo "   ADMIN_IDS=\"12345678,87654321\"   # comma-separated Telegram numeric IDs allowed to use admin commands"
echo "   ZIVPN_SERVER_IP=\"$(echo ${ZIVPN_SERVER_IP_DEFAULT})\""
echo ""
echo "2) Restart the bot service after editing the file:"
echo "   sudo systemctl restart zivpn_bot.service"
echo ""
echo "3) To create an account from CLI (test):"
echo "   /usr/local/bin/create_vpn_user.sh testuser 7"
echo ""
echo "4) Test bot by sending /start then (if ADMIN_IDS set properly):"
echo "   /create alice 7"
echo ""
echo "5) Rotate your bot token if you accidentally published it. Do NOT keep the token in public place."
echo ""
echo "Logs:"
echo "  sudo journalctl -u zivpn_bot.service -f"
echo ""
echo "Installer finished."
