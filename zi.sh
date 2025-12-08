#!/usr/bin/env bash
# install_zivpn_public_fixed_v6.5.1.sh
# Fixed installer for ZIVPN + Telegram bot (v6.5.1) with WORKING Backup/Restore/Uninstall
# - FIXED: Restore function now works properly
# - FIXED: Permission issues resolved
# - NEW User Card format with icons
# - Title VIP: 1 for each user
# - Beautiful icons for each field
# - FIXED: Deleted users can be recreated
# - FIXED: Create Account Successfully message
# - ADDED: Working Backup, Restore, and Uninstall functions via Telegram Bot
# - ADDED: Domain/DNS support with icon

set -euo pipefail
IFS=$'\n\t'

### ===== CONFIG (edit BEFORE running if needed) =====
BOT_TOKEN_DEFAULT="" # leave empty to be prompted at install time
ADMIN_IDS_DEFAULT="" # comma separated Telegram IDs for admin notifications (optional)
ZIVPN_SERVER_IP_DEFAULT="$(curl -s https://ifconfig.co || echo "your.server.ip")"
ZIVPN_DOMAIN_DEFAULT="" # leave empty to be prompted
BACKUP_DIR="/opt/zivpn_backups"

### ==================================================

echo "== ZIVPN + Public Telegram Bot Installer (fixed v6.5.1 - Working Restore) =="
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

echo
read -r -p "Enter your Domain/DNS (e.g., ex.jvpn.shop) or press Enter to skip: " DOMAIN_INPUT
if [ -n "$DOMAIN_INPUT" ]; then
    ZIVPN_DOMAIN_DEFAULT="$DOMAIN_INPUT"
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

# Create backup/restore scripts
sudo mkdir -p "$BACKUP_DIR"
sudo chmod 755 "$BACKUP_DIR"

# ===== FIXED BACKUP SCRIPT =====
sudo tee /usr/local/bin/zivpn_backup.py > /dev/null <<'PY'
#!/usr/bin/env python3
# ZIVPN Backup Script for Telegram Bot - FIXED VERSION
import os, sqlite3, tarfile, tempfile, shutil, json, datetime, subprocess, sys
from pathlib import Path

BACKUP_DIR = "/opt/zivpn_backups"

def create_backup():
    """Create a backup of ZIVPN system"""
    # Create backup directory if not exists
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    # Generate backup filename
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"zivpn_backup_{timestamp}.tar.gz")
    
    # Create temporary directory for backup
    temp_dir = tempfile.mkdtemp()
    backup_content = os.path.join(temp_dir, "zivpn_backup")
    os.makedirs(backup_content, exist_ok=True)
    
    try:
        print(f"Creating backup in {backup_file}")
        
        # 1. Backup database
        db_path = "/var/lib/zivpn_bot/accounts.db"
        if os.path.exists(db_path):
            shutil.copy2(db_path, os.path.join(backup_content, "accounts.db"))
            print(f"  ✓ Database backed up")
        
        # 2. Backup config
        config_dir = "/etc/zivpn"
        if os.path.exists(config_dir):
            # Copy all config files
            for item in os.listdir(config_dir):
                s = os.path.join(config_dir, item)
                d = os.path.join(backup_content, "zivpn_config", item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, symlinks=True, ignore_dangling_symlinks=True)
                else:
                    shutil.copy2(s, d)
            print(f"  ✓ Config directory backed up")
        
        # 3. Backup environment file
        env_file = "/etc/default/zivpn_bot"
        if os.path.exists(env_file):
            shutil.copy2(env_file, os.path.join(backup_content, "zivpn_bot.env"))
            print(f"  ✓ Environment file backed up")
        
        # 4. Backup systemd service files
        service_files = ["/etc/systemd/system/zivpn.service", "/etc/systemd/system/zivpn_bot.service"]
        for svc in service_files:
            if os.path.exists(svc):
                shutil.copy2(svc, os.path.join(backup_content, os.path.basename(svc)))
        print(f"  ✓ Service files backed up")
        
        # 5. Create info file
        info_file = os.path.join(backup_content, "backup_info.txt")
        with open(info_file, 'w') as f:
            f.write(f"Backup created: {datetime.datetime.now()}\n")
            f.write(f"Server: {os.uname().nodename}\n")
            f.write(f"ZIVPN Version: 1.4.9\n")
            f.write(f"Backup Script Version: 6.5.1\n")
            
            # Try to get IP
            try:
                import socket
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                f.write(f"IP: {ip}\n")
            except:
                pass
            
            # Count users
            if os.path.exists(db_path):
                try:
                    conn = sqlite3.connect(db_path)
                    cur = conn.cursor()
                    cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
                    user_count = cur.fetchone()[0]
                    conn.close()
                    f.write(f"Active Users: {user_count}\n")
                except:
                    pass
        
        # 6. Create tar.gz archive
        with tarfile.open(backup_file, "w:gz") as tar:
            tar.add(backup_content, arcname="zivpn_backup")
        
        # Get file size
        file_size = os.path.getsize(backup_file)
        size_kb = file_size / 1024
        
        print(f"\n✅ Backup completed successfully!")
        print(f"📁 Backup file: {backup_file}")
        print(f"📦 Size: {size_kb:.1f} KB")
        
        return backup_file, size_kb
        
    except Exception as e:
        print(f"❌ Backup failed: {e}")
        import traceback
        traceback.print_exc()
        return None, 0
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    backup_file, size_kb = create_backup()
    if backup_file:
        print(f"BACKUP_FILE:{backup_file}")
        print(f"BACKUP_SIZE_KB:{size_kb:.1f}")
    else:
        sys.exit(1)
PY

sudo chmod +x /usr/local/bin/zivpn_backup.py

# ===== FIXED RESTORE SCRIPT =====
sudo tee /usr/local/bin/zivpn_restore.py > /dev/null <<'PY'
#!/usr/bin/env python3
# ZIVPN Restore Script for Telegram Bot - FIXED VERSION
import os, tarfile, tempfile, shutil, sqlite3, json, subprocess, sys, datetime, time
from pathlib import Path

def restore_backup(backup_file_path):
    """Restore ZIVPN from backup file - FIXED VERSION"""
    
    if not os.path.exists(backup_file_path):
        print(f"❌ Backup file not found: {backup_file_path}")
        return False
    
    # Extract to temp directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        print(f"🔄 Restoring from backup: {backup_file_path}")
        
        # Test if tar.gz is valid
        try:
            with tarfile.open(backup_file_path, "r:gz") as test_tar:
                test_tar.getmembers()
        except Exception as e:
            print(f"❌ Invalid backup file (corrupt or not tar.gz): {e}")
            return False
        
        # Extract backup
        print("📂 Extracting backup files...")
        with tarfile.open(backup_file_path, "r:gz") as tar:
            tar.extractall(temp_dir)
        
        backup_content = os.path.join(temp_dir, "zivpn_backup")
        
        if not os.path.exists(backup_content):
            print(f"❌ Backup content not found in archive")
            return False
        
        # Check backup info
        info_file = os.path.join(backup_content, "backup_info.txt")
        if os.path.exists(info_file):
            with open(info_file, 'r') as f:
                print("📋 Backup Information:")
                print(f.read())
        
        # 1. Stop services
        print("🛑 Stopping services...")
        subprocess.run(["systemctl", "stop", "zivpn_bot.service"], capture_output=True, check=False)
        time.sleep(2)
        subprocess.run(["systemctl", "stop", "zivpn.service"], capture_output=True, check=False)
        time.sleep(2)
        
        # 2. Restore database
        db_backup = os.path.join(backup_content, "accounts.db")
        if os.path.exists(db_backup):
            print("💾 Restoring database...")
            os.makedirs("/var/lib/zivpn_bot", exist_ok=True)
            shutil.copy2(db_backup, "/var/lib/zivpn_bot/accounts.db")
            # Set proper permissions
            os.chmod("/var/lib/zivpn_bot/accounts.db", 0o644)
            print("  ✅ Database restored")
        else:
            print("  ⚠️ No database in backup")
        
        # 3. Restore config
        config_backup = os.path.join(backup_content, "zivpn_config")
        if os.path.exists(config_backup):
            print("⚙️ Restoring config...")
            # Remove existing config
            shutil.rmtree("/etc/zivpn", ignore_errors=True)
            # Copy backup config
            shutil.copytree(config_backup, "/etc/zivpn")
            # Set permissions
            os.chmod("/etc/zivpn", 0o755)
            for root, dirs, files in os.walk("/etc/zivpn"):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o755)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o644)
            print("  ✅ Config restored")
        else:
            print("  ⚠️ No config in backup")
        
        # 4. Restore environment file
        env_backup = os.path.join(backup_content, "zivpn_bot.env")
        if os.path.exists(env_backup):
            print("🔧 Restoring environment...")
            shutil.copy2(env_backup, "/etc/default/zivpn_bot")
            os.chmod("/etc/default/zivpn_bot", 0o644)
            print("  ✅ Environment restored")
        else:
            print("  ⚠️ No environment file in backup")
        
        # 5. Restore systemd service files
        for service in ["zivpn.service", "zivpn_bot.service"]:
            svc_backup = os.path.join(backup_content, service)
            if os.path.exists(svc_backup):
                shutil.copy2(svc_backup, f"/etc/systemd/system/{service}")
                os.chmod(f"/etc/systemd/system/{service}", 0o644)
        
        # 6. Start services
        print("🚀 Starting services...")
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, check=False)
        time.sleep(1)
        
        # Start zivpn first
        print("  Starting zivpn service...")
        result = subprocess.run(["systemctl", "start", "zivpn.service"], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  ⚠️ zivpn start may have issues: {result.stderr}")
        time.sleep(3)
        
        # Start bot
        print("  Starting bot service...")
        result = subprocess.run(["systemctl", "start", "zivpn_bot.service"], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  ⚠️ bot start may have issues: {result.stderr}")
        
        # Check services status
        print("🔍 Checking service status...")
        time.sleep(2)
        zivpn_status = subprocess.run(["systemctl", "is-active", "zivpn.service"], capture_output=True, text=True).stdout.strip()
        bot_status = subprocess.run(["systemctl", "is-active", "zivpn_bot.service"], capture_output=True, text=True).stdout.strip()
        
        print(f"\n✅ Restore completed!")
        print(f"📊 Services Status:")
        print(f"  zivpn.service: {'🟢 Active' if zivpn_status == 'active' else '🔴 Inactive'}")
        print(f"  zivpn_bot.service: {'🟢 Active' if bot_status == 'active' else '🔴 Inactive'}")
        
        # Count restored users
        if os.path.exists("/var/lib/zivpn_bot/accounts.db"):
            try:
                conn = sqlite3.connect("/var/lib/zivpn_bot/accounts.db")
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
                active_users = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM accounts")
                total_users = cur.fetchone()[0]
                conn.close()
                print(f"📈 Restored Users:")
                print(f"  Active: {active_users}")
                print(f"  Total: {total_users}")
            except:
                pass
        
        return True
        
    except Exception as e:
        print(f"❌ Restore failed with error: {e}")
        import traceback
        traceback.print_exc()
        
        # Try to restart services even if restore failed
        print("\n🔄 Attempting to restart services after error...")
        subprocess.run(["systemctl", "start", "zivpn.service"], check=False)
        subprocess.run(["systemctl", "start", "zivpn_bot.service"], check=False)
        return False
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)
        print("🧹 Cleanup completed")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: zivpn_restore.py <backup_file_path>")
        sys.exit(1)
    
    success = restore_backup(sys.argv[1])
    sys.exit(0 if success else 1)
PY

sudo chmod +x /usr/local/bin/zivpn_restore.py

# ===== UNINSTALL SCRIPT =====
sudo tee /usr/local/bin/zivpn_uninstall.py > /dev/null <<'PY'
#!/usr/bin/env python3
# ZIVPN Uninstall Script for Telegram Bot
import os, subprocess, shutil, sys, time

def uninstall_zivpn(remove_data=True, remove_config=True, remove_binary=True):
    """Uninstall ZIVPN system"""
    
    print("=== ZIVPN Uninstall ===")
    
    # 1. Stop services
    print("Stopping services...")
    subprocess.run(["systemctl", "stop", "zivpn_bot.service"], check=False)
    subprocess.run(["systemctl", "stop", "zivpn.service"], check=False)
    time.sleep(2)
    
    # 2. Disable services
    print("Disabling services...")
    subprocess.run(["systemctl", "disable", "zivpn_bot.service"], check=False)
    subprocess.run(["systemctl", "disable", "zivpn.service"], check=False)
    
    # 3. Remove systemd services
    print("Removing systemd services...")
    subprocess.run(["rm", "-f", "/etc/systemd/system/zivpn.service"], check=False)
    subprocess.run(["rm", "-f", "/etc/systemd/system/zivpn_bot.service"], check=False)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    
    # 4. Remove scripts
    print("Removing scripts...")
    subprocess.run(["rm", "-f", "/usr/local/bin/create_vpn_user.sh"], check=False)
    subprocess.run(["rm", "-f", "/usr/local/bin/zivpn_expire_check.sh"], check=False)
    subprocess.run(["rm", "-f", "/usr/local/bin/zivpn_backup.py"], check=False)
    subprocess.run(["rm", "-f", "/usr/local/bin/zivpn_restore.py"], check=False)
    subprocess.run(["rm", "-f", "/usr/local/bin/zivpn_uninstall.py"], check=False)
    
    # 5. Remove config if requested
    if remove_config:
        print("Removing config files...")
        subprocess.run(["rm", "-rf", "/etc/zivpn"], check=False)
    
    # 6. Remove data if requested
    if remove_data:
        print("Removing data files...")
        subprocess.run(["rm", "-rf", "/var/lib/zivpn_bot"], check=False)
        subprocess.run(["rm", "-rf", "/opt/zivpn_bot"], check=False)
    
    # 7. Remove environment file
    print("Removing environment file...")
    subprocess.run(["rm", "-f", "/etc/default/zivpn_bot"], check=False)
    
    # 8. Remove binary if requested
    if remove_binary:
        print("Removing binary...")
        subprocess.run(["rm", "-f", "/usr/local/bin/zivpn"], check=False)
    
    # 9. Remove crontab entry
    print("Removing cron job...")
    try:
        # Get current crontab, remove zivpn entry, write back
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            new_lines = [line for line in lines if "zivpn_expire_check.sh" not in line]
            new_cron = '\n'.join(new_lines)
            subprocess.run(["crontab", "-"], input=new_cron, text=True, check=False)
    except:
        pass
    
    print("\n✅ Uninstall completed!")
    print("\nNote: Backup files are kept in /opt/zivpn_backups/")
    print("You can delete them manually if needed.")
    
    return True

if __name__ == "__main__":
    # For command line use, ask for confirmation
    print("⚠️  WARNING: This will uninstall ZIVPN and remove all data!")
    response = input("Are you sure? (yes/no): ").strip().lower()
    
    if response == 'yes':
        uninstall_zivpn(
            remove_data=True,
            remove_config=True,
            remove_binary=True
        )
    else:
        print("Uninstall cancelled.")
        sys.exit(0)
PY

sudo chmod +x /usr/local/bin/zivpn_uninstall.py

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

# Write env file with domain
sudo tee /etc/default/zivpn_bot > /dev/null <<EOF
# BOT environment for zivpn_bot
BOT_TOKEN="${BOT_TOKEN_DEFAULT}"
ADMIN_IDS="${ADMIN_IDS_DEFAULT}"
ZIVPN_SERVER_IP="${ZIVPN_SERVER_IP_DEFAULT}"
ZIVPN_DOMAIN="${ZIVPN_DOMAIN_DEFAULT}"
BACKUP_DIR="${BACKUP_DIR}"
EOF

sudo chmod 644 /etc/default/zivpn_bot
sudo chown root:root /etc/default/zivpn_bot

# ===== FIXED BOT SCRIPT (v6.5.1) - WITH WORKING RESTORE =====
sudo tee /opt/zivpn_bot/bot.py > /dev/null <<'PY'
#!/usr/bin/env python3
# bot.py - Public ZIVPN bot (fixed v6.5.1) with WORKING Restore
import os, sqlite3, subprocess, datetime, json, logging, asyncio, shutil, math, secrets, string, tempfile, tarfile, io, sys
import psutil
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, constants, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import ApplicationBuilder, CommandHandler, ConversationHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from telegram.error import BadRequest

ENV_FILE="/etc/default/zivpn_bot"
DB_PATH="/var/lib/zivpn_bot/accounts.db"
CREATE_SCRIPT="/usr/local/bin/create_vpn_user.sh"
BACKUP_SCRIPT="/usr/local/bin/zivpn_backup.py"
RESTORE_SCRIPT="/usr/local/bin/zivpn_restore.py"
UNINSTALL_SCRIPT="/usr/local/bin/zivpn_uninstall.py"
BACKUP_DIR="/opt/zivpn_backups"

# States
STATE_USERNAME, STATE_PASSWORD, STATE_EXPIRY, STATE_RENEW, STATE_EDIT_PASS, STATE_EDIT_EXP, STATE_SEARCH = range(7)
# Admin states
STATE_CONFIRM_UNINSTALL, STATE_CONFIRM_RESTORE, STATE_WAITING_BACKUP_FILE = range(7, 10)

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
ZIVPN_DOMAIN = env.get("ZIVPN_DOMAIN","")

logger.info("Started zivpn public bot (fixed v6.5.1 with Working Restore) admin_notify=%s", ADMIN_IDS)
if not BOT_TOKEN:
    logger.error("BOT_TOKEN missing in %s", ENV_FILE)
    raise SystemExit(1)

# Admin check decorator
def admin_only(func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if user_id not in ADMIN_IDS:
            await update.message.reply_text("🚫 This command is for admins only.")
            return
        return await func(update, context)
    return wrapper

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
        
        subprocess.run(["systemctl","restart","zivpn.service"], check=False)
        
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

# ========== NEW CARD FORMAT FUNCTION WITH DOMAIN ==========
def format_user_card(username: str, password: str, expires_at: str, revoked: int, index: int = 1):
    """Format user card with NEW format and DOMAIN"""
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
    
    # NEW CARD FORMAT with icons - includes DOMAIN if available
    card_lines = [
        f"👑 Premium User : {index}",
        "",
        f"📡 Server IP : {ZIVPN_SERVER_IP}"
    ]
    
    # Add domain if available
    if ZIVPN_DOMAIN:
        card_lines.append(f"🌐 Server DNS : {ZIVPN_DOMAIN}")
    
    card_lines.extend([
        f"👤 Username: {username}",
        f"🔑 Password: {password}",
        f"📅 Expired Date: {expires_at} {left_text}",
        f"🔋 Status : {status_emoji} {status_label}"
    ])
    
    return "\n".join(card_lines)

# ========== ADMIN COMMANDS ==========
@admin_only
async def cmd_backup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Create backup of ZIVPN system"""
    msg = await update.message.reply_text("🔄 Creating backup... Please wait (up to 1 minute).")
    
    try:
        # Run backup script
        result = subprocess.run(
            [BACKUP_SCRIPT],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            await msg.edit_text(f"❌ Backup failed:\n```\n{error_msg[:500]}\n```", parse_mode=constants.ParseMode.MARKDOWN)
            return
        
        # Parse output
        backup_file = None
        backup_size = 0
        for line in result.stdout.split('\n'):
            if line.startswith("BACKUP_FILE:"):
                backup_file = line.split(":", 1)[1].strip()
            elif line.startswith("BACKUP_SIZE_KB:"):
                backup_size = float(line.split(":", 1)[1].strip())
        
        if not backup_file or not os.path.exists(backup_file):
            await msg.edit_text("❌ Backup created but file not found.")
            return
        
        # Send backup file
        with open(backup_file, 'rb') as f:
            await context.bot.send_document(
                chat_id=update.message.chat_id,
                document=f,
                filename=os.path.basename(backup_file),
                caption=f"✅ Backup created successfully!\n📁 File: {os.path.basename(backup_file)}\n📦 Size: {backup_size:.1f} KB"
            )
        
        await msg.delete()
        
        # Notify other admins
        await notify_admins(context.application, f"📦 Backup created by admin\nSize: {backup_size:.1f} KB")
        
    except subprocess.TimeoutExpired:
        await msg.edit_text("❌ Backup timed out (took too long).")
    except Exception as e:
        await msg.edit_text(f"❌ Backup error: {str(e)}")

@admin_only
async def cmd_restore(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start restore process - ask for backup file"""
    await update.message.reply_text(
        "📥 Please send me the backup file (.tar.gz)\n"
        "⚠️ **WARNING**: This will overwrite current ZIVPN data!\n"
        "Type /cancel to cancel."
    )
    return STATE_WAITING_BACKUP_FILE

@admin_only
async def cmd_uninstall(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start uninstall process - ask for confirmation"""
    keyboard = [
        [InlineKeyboardButton("✅ Yes, Uninstall", callback_data="uninstall_yes")],
        [InlineKeyboardButton("❌ Cancel", callback_data="uninstall_no")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "⚠️ **DANGER: UNINSTALL ZIVPN** ⚠️\n\n"
        "This will:\n"
        "• Stop and remove all services\n"
        "• Remove database and user accounts\n"
        "• Remove configuration files\n"
        "• Remove scripts and binaries\n\n"
        "**Backup files will be kept** in /opt/zivpn_backups/\n\n"
        "Are you absolutely sure?",
        reply_markup=reply_markup
    )
    return STATE_CONFIRM_UNINSTALL

@admin_only
async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show admin commands"""
    admin_commands = (
        "👑 **Admin Commands**\n\n"
        "📦 /backup - Create system backup\n"
        "📥 /restore - Restore from backup\n"
        "🗑️ /uninstall - Uninstall ZIVPN\n"
        "📊 /stats - System statistics\n"
        "👥 /listall - List all users (including deleted)\n"
        "🔄 /restart - Restart ZIVPN services\n\n"
        f"**Server Info:**\n"
        f"IP: {ZIVPN_SERVER_IP}\n"
        f"Domain: {ZIVPN_DOMAIN if ZIVPN_DOMAIN else 'Not set'}\n"
        f"Users: {total_users_count()}\n"
    )
    await update.message.reply_text(admin_commands, parse_mode=constants.ParseMode.MARKDOWN)

@admin_only
async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show detailed system statistics"""
    stats = get_server_stats()
    
    # Database stats
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=0")
    active_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM accounts WHERE revoked=1")
    deleted_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM accounts")
    total_users = cur.fetchone()[0]
    conn.close()
    
    # Services status
    services = []
    for service in ["zivpn.service", "zivpn_bot.service"]:
        try:
            result = subprocess.run(["systemctl", "is-active", service], 
                                  capture_output=True, text=True)
            status = "🟢 Active" if result.stdout.strip() == "active" else "🔴 Inactive"
            services.append(f"{service}: {status}")
        except:
            services.append(f"{service}: ❓ Unknown")
    
    # Backup info
    backup_count = 0
    backup_size = 0
    if os.path.exists(BACKUP_DIR):
        for file in os.listdir(BACKUP_DIR):
            if file.endswith(".tar.gz"):
                backup_count += 1
                filepath = os.path.join(BACKUP_DIR, file)
                backup_size += os.path.getsize(filepath)
    
    stats_text = (
        "📊 **System Statistics**\n\n"
        "💻 **Hardware:**\n"
        f"CPU: {stats['cpu']}%\n"
        f"RAM: {stats['ram_used_mb']}/{stats['ram_total_mb']}MB ({stats['ram_percent']}%)\n"
        f"Disk: {stats['disk_used_gb']}/{stats['disk_total_gb']}GB ({stats['disk_percent']}%)\n\n"
        "👥 **Users:**\n"
        f"Active: {active_users}\n"
        f"Deleted: {deleted_users}\n"
        f"Total: {total_users}\n\n"
        "🛠️ **Services:**\n" + "\n".join(services) + "\n\n"
        "💾 **Backups:**\n"
        f"Count: {backup_count}\n"
        f"Total Size: {backup_size/(1024*1024):.2f} MB\n"
        f"Location: {BACKUP_DIR}\n\n"
        "🌐 **Network:**\n"
        f"Server IP: {ZIVPN_SERVER_IP}\n"
        f"Domain: {ZIVPN_DOMAIN if ZIVPN_DOMAIN else 'Not set'}"
    )
    
    await update.message.reply_text(stats_text, parse_mode=constants.ParseMode.MARKDOWN)

@admin_only
async def cmd_listall(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """List all users including deleted"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT username, expires_at, revoked FROM accounts ORDER BY id DESC LIMIT 100")
    rows = cur.fetchall()
    conn.close()
    
    if not rows:
        await update.message.reply_text("No users found.")
        return
    
    lines = []
    active_count = 0
    deleted_count = 0
    
    for username, expires_at, revoked in rows:
        status = "🟢" if not revoked else "🔴"
        left = days_left(expires_at) if expires_at else 0
        lines.append(f"{status} {username} - exp:{expires_at} (days left: {left})")
        if revoked:
            deleted_count += 1
        else:
            active_count += 1
    
    text = (
        f"👥 **All Users** ({len(rows)} total)\n"
        f"Active: {active_count} | Deleted: {deleted_count}\n\n" +
        "\n".join(lines[:50])
    )
    
    await update.message.reply_text(text, parse_mode=constants.ParseMode.MARKDOWN)
    
    if len(lines) > 50:
        await update.message.reply_text(
            f"... and {len(lines)-50} more users.",
            parse_mode=constants.ParseMode.MARKDOWN
        )

@admin_only
async def cmd_restart(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Restart ZIVPN services"""
    msg = await update.message.reply_text("🔄 Restarting services...")
    
    try:
        # Restart zivpn
        result1 = subprocess.run(["systemctl", "restart", "zivpn.service"], 
                               capture_output=True, text=True)
        # Restart bot
        result2 = subprocess.run(["systemctl", "restart", "zivpn_bot.service"], 
                               capture_output=True, text=True)
        
        if result1.returncode == 0 and result2.returncode == 0:
            await msg.edit_text("✅ Services restarted successfully!")
            await notify_admins(context.application, "🔄 Services restarted by admin")
        else:
            error_msg = ""
            if result1.returncode != 0:
                error_msg += f"zivpn: {result1.stderr}\n"
            if result2.returncode != 0:
                error_msg += f"bot: {result2.stderr}\n"
            await msg.edit_text(f"❌ Failed to restart services:\n```\n{error_msg[:500]}\n```", 
                              parse_mode=constants.ParseMode.MARKDOWN)
    except Exception as e:
        await msg.edit_text(f"❌ Error: {str(e)}")

# ========== HANDLE BACKUP FILE UPLOAD ==========
async def handle_backup_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle backup file upload for restore"""
    if update.message.document:
        # Check if it's a backup file
        file_name = update.message.document.file_name
        if not file_name or not file_name.endswith('.tar.gz'):
            await update.message.reply_text("❌ Please send a .tar.gz backup file.")
            return STATE_WAITING_BACKUP_FILE
        
        # Download file
        msg = await update.message.reply_text("📥 Downloading backup file...")
        
        try:
            # Create temp directory
            temp_dir = tempfile.mkdtemp()
            file_path = os.path.join(temp_dir, file_name)
            
            # Download file
            file = await context.bot.get_file(update.message.document.file_id)
            await file.download_to_drive(file_path)
            
            # Get file size
            file_size = os.path.getsize(file_path)
            file_size_kb = file_size / 1024
            
            # Ask for confirmation
            keyboard = [
                [InlineKeyboardButton("✅ Yes, Restore", callback_data=f"restore_yes:{file_path}")],
                [InlineKeyboardButton("❌ Cancel", callback_data="restore_no")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await msg.edit_text(
                f"📁 **Backup File Received**\n\n"
                f"File: {file_name}\n"
                f"Size: {file_size_kb:.1f} KB\n\n"
                f"⚠️ **WARNING:** This will overwrite current ZIVPN data!\n"
                f"• All current users will be replaced\n"
                f"• Current settings will be lost\n"
                f"• Services will restart automatically\n\n"
                f"Proceed with restore?",
                reply_markup=reply_markup
            )
            
            # Store file path in context
            context.user_data['restore_file'] = file_path
            
            return STATE_CONFIRM_RESTORE
            
        except Exception as e:
            await msg.edit_text(f"❌ Error downloading file: {str(e)}")
            # Cleanup temp dir
            shutil.rmtree(temp_dir, ignore_errors=True)
            return STATE_WAITING_BACKUP_FILE
    
    await update.message.reply_text("❌ Please send a backup file (.tar.gz)")
    return STATE_WAITING_BACKUP_FILE

# ========== HANDLE CONFIRMATION CALLBACKS ==========
async def handle_uninstall_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle uninstall confirmation callback"""
    query = update.callback_query
    await query.answer()
    
    if query.data == "uninstall_no":
        await query.edit_message_text("❌ Uninstall cancelled.")
        return ConversationHandler.END
    
    elif query.data == "uninstall_yes":
        await query.edit_message_text("🗑️ Starting uninstall... This may take a moment.")
        
        try:
            # Run uninstall script
            result = subprocess.run(
                [UNINSTALL_SCRIPT],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                await query.edit_message_text(
                    "✅ Uninstall completed!\n\n"
                    "ZIVPN has been removed from the system.\n"
                    "You can reinstall by running the installer again.\n\n"
                    "⚠️ Bot will stop working now."
                )
                
                # Stop the bot
                await context.application.stop()
                
            else:
                error_msg = result.stderr or result.stdout or "Unknown error"
                await query.edit_message_text(
                    f"❌ Uninstall failed:\n```\n{error_msg[:500]}\n```",
                    parse_mode=constants.ParseMode.MARKDOWN
                )
                
        except subprocess.TimeoutExpired:
            await query.edit_message_text("❌ Uninstall timed out.")
        except Exception as e:
            await query.edit_message_text(f"❌ Uninstall error: {str(e)}")
        
        return ConversationHandler.END

async def handle_restore_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle restore confirmation callback - FIXED VERSION"""
    query = update.callback_query
    await query.answer()
    
    if query.data == "restore_no":
        # Cleanup temp file
        if 'restore_file' in context.user_data:
            temp_file = context.user_data['restore_file']
            temp_dir = os.path.dirname(temp_file)
            shutil.rmtree(temp_dir, ignore_errors=True)
            del context.user_data['restore_file']
        
        await query.edit_message_text("❌ Restore cancelled.")
        return ConversationHandler.END
    
    elif query.data.startswith("restore_yes:"):
        file_path = query.data.split(":", 1)[1]
        
        await query.edit_message_text("🔄 Restoring from backup... This may take up to 2 minutes.")
        
        try:
            # Run restore script with timeout
            result = subprocess.run(
                [RESTORE_SCRIPT, file_path],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Cleanup temp file
            temp_dir = os.path.dirname(file_path)
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            if result.returncode == 0:
                final_text = (
                    "✅ Restore completed successfully!\n\n"
                    "All users and settings have been restored.\n"
                    "Services have been restarted.\n\n"
                    "You may need to /start the bot again to refresh."
                )
                
                # Add any important output from restore script
                if result.stdout:
                    # Extract key information
                    lines = result.stdout.split('\n')
                    important_lines = [line for line in lines if '✅' in line or '📊' in line or '📈' in line]
                    if important_lines:
                        final_text += "\n\n" + "\n".join(important_lines[-5:])
                
                await query.edit_message_text(final_text)
                
                # Notify other admins
                await notify_admins(context.application, "📥 System restored from backup by admin")
                
            else:
                error_msg = result.stderr or result.stdout or "Unknown error"
                await query.edit_message_text(
                    f"❌ Restore failed:\n```\n{error_msg[:1000]}\n```",
                    parse_mode=constants.ParseMode.MARKDOWN
                )
                
        except subprocess.TimeoutExpired:
            await query.edit_message_text("❌ Restore timed out (2 minutes).")
        except Exception as e:
            await query.edit_message_text(f"❌ Restore error: {str(e)}")
        
        return ConversationHandler.END

# ========== MAIN COMMAND HANDLERS ==========
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    total = total_users_count()
    stats = get_server_stats()
    cpu_line = f"⚙️ CPU: {stats['cpu']:.1f}%"
    ram_line = f"🧠 RAM: {stats['ram_used_mb']}MB / {stats['ram_total_mb']}MB ({stats['ram_percent']}%)"
    disk_line = f"💾 STORAGE: {stats['disk_used_gb']}GB / {stats['disk_total_gb']}GB ({stats['disk_percent']}%)"
    
    body_lines = [
        f"📊 Total Users: `{total}`",
        "",
        cpu_line,
        ram_line,
        disk_line,
        "",
        f"📡 Server IP: {ZIVPN_SERVER_IP}"
    ]
    
    if ZIVPN_DOMAIN:
        body_lines.append(f"🌐 Server DNS: {ZIVPN_DOMAIN}")
    
    # Add admin note if user is admin
    if update.effective_user.id in ADMIN_IDS:
        body_lines.append("")
        body_lines.append("👑 You are an admin! Use /admin for admin commands")
    
    body_lines.append("")
    body_lines.append("Choose an option below (tap a button):")
    
    body = "\n".join(body_lines)
    
    # Updated with icons in buttons
    kb = [
        [KeyboardButton("🆕 Create Account"), KeyboardButton("👥 Users List"), KeyboardButton("🔍 Search")],
        [KeyboardButton("ℹ️ Help")]
    ]
    reply_kb = ReplyKeyboardMarkup(kb, resize_keyboard=True, one_time_keyboard=False)
    await update.message.reply_text(body, parse_mode=constants.ParseMode.MARKDOWN, reply_markup=reply_kb)

async def handle_main_buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (update.message.text or "").strip()
    if txt == "👥 Users List":
        await cmd_list_cards(update, context)
        return
    if txt == "ℹ️ Help":
        help_text = "📚 Public ZIVPN Bot\n\n"
        help_text += "🆕 Create Account: Create new VPN account\n"
        help_text += "👥 Users List: View all active accounts\n"
        help_text += "🔍 Search: Search for specific account\n"
        help_text += "🔁 Renew: Extend account expiry\n"
        help_text += "✏️ Edit: Change password or expiry\n"
        help_text += "🗑️ Delete: Revoke account access\n\n"
        help_text += f"📡 Server: {ZIVPN_SERVER_IP}\n"
        if ZIVPN_DOMAIN:
            help_text += f"🌐 Domain: {ZIVPN_DOMAIN}\n"
        
        # Add admin commands if user is admin
        if update.effective_user.id in ADMIN_IDS:
            help_text += "\n👑 Admin Commands:\n"
            help_text += "/admin - Show admin commands\n"
            help_text += "/backup - Create backup\n"
            help_text += "/restore - Restore from backup\n"
            help_text += "/stats - System statistics\n"
        
        await update.message.reply_text(help_text)
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

# ========== CANCEL COMMAND ==========
async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cancel any ongoing operation"""
    await update.message.reply_text("❌ Operation cancelled.")
    return ConversationHandler.END

# Main text router for all text messages
async def global_text_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = (update.message.text or "").strip()
    
    # Skip if it's a main button (handled by other handlers)
    if txt in ("🆕 Create Account", "👥 Users List", "🔍 Search", "ℹ️ Help"):
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
            text = f"✅✅ Create Account Successfully 😄\n\n{card_text}\n\n📊 Total Users: {total_users}"
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
                subprocess.run(["systemctl","restart","zivpn.service"], check=False)
            
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
        text = f"✅✅ Create Account Successfully 😄\n\n{card_text}\n\n📊 Total Users: {total_users}"
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
            CommandHandler("restore", cmd_restore),
            CommandHandler("uninstall", cmd_uninstall),
            CallbackQueryHandler(renew_custom_callback, pattern='^renew_custom\\|'),
            CallbackQueryHandler(edit_pass_callback, pattern='^edit_pass\\|'),
            CallbackQueryHandler(edit_exp_callback, pattern='^edit_exp\\|'),
            CallbackQueryHandler(handle_uninstall_callback, pattern='^(uninstall_yes|uninstall_no)$'),
            CallbackQueryHandler(handle_restore_callback, pattern='^(restore_yes|restore_no)')
        ],
        states={
            STATE_WAITING_BACKUP_FILE: [
                MessageHandler(filters.Document.ALL & ~filters.COMMAND, handle_backup_file),
                CommandHandler("cancel", cmd_cancel)
            ],
            STATE_CONFIRM_RESTORE: [
                CallbackQueryHandler(handle_restore_callback, pattern='^(restore_yes|restore_no)'),
                CommandHandler("cancel", cmd_cancel)
            ],
            STATE_CONFIRM_UNINSTALL: [
                CallbackQueryHandler(handle_uninstall_callback, pattern='^(uninstall_yes|uninstall_no)$'),
                CommandHandler("cancel", cmd_cancel)
            ],
            STATE_RENEW: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, recv_renew_days),
                CommandHandler("cancel", cmd_cancel)
            ],
            STATE_EDIT_PASS: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, recv_edit_password),
                CommandHandler("cancel", cmd_cancel)
            ],
            STATE_EDIT_EXP: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, recv_edit_expiry),
                CommandHandler("cancel", cmd_cancel)
            ],
        },
        fallbacks=[CommandHandler("cancel", cmd_cancel)],
        allow_reentry=True
    )
    return conv

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    
    # Command handlers
    app.add_handler(CommandHandler("start", start_cmd))
    app.add_handler(CommandHandler("list", cmd_list_text))
    app.add_handler(CommandHandler("create", cmd_create))
    
    # Admin command handlers
    app.add_handler(CommandHandler("admin", cmd_admin))
    app.add_handler(CommandHandler("backup", cmd_backup))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("listall", cmd_listall))
    app.add_handler(CommandHandler("restart", cmd_restart))
    
    # Main button handlers with icons
    app.add_handler(MessageHandler(filters.Regex('^🆕 Create Account$'), handle_create_button))
    app.add_handler(MessageHandler(filters.Regex('^🔍 Search$'), handle_search_button))
    app.add_handler(MessageHandler(filters.Regex('^(👥 Users List|ℹ️ Help)$'), handle_main_buttons))
    
    # Global text router for all text messages
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, global_text_router))
    
    # Callback query handlers
    app.add_handler(CallbackQueryHandler(action_callback, pattern='^act_'))
    app.add_handler(CallbackQueryHandler(renew_do_callback, pattern='^renew_do\\|'))
    app.add_handler(CallbackQueryHandler(expiry_callback, pattern='^exp_'))
    app.add_handler(CallbackQueryHandler(confirm_callback, pattern='^confirm_'))
    
    # Conversation handler for edit/renew/admin flows
    app.add_handler(build_conv())
    
    logger.info("Public bot polling started (fixed v6.5.1 with Working Restore)")
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
Wants=zivpn.service

[Service]
User=root
WorkingDirectory=/opt/zivpn_bot
EnvironmentFile=/etc/default/zivpn_bot
ExecStart=/opt/zivpn_bot/venv/bin/python /opt/zivpn_bot/bot.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now zivpn_bot.service

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
    subprocess.run(["systemctl","restart","zivpn.service"], check=False)
    
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

(sudo crontab -l 2>/dev/null | grep -v "zivpn_expire_check.sh" | cat; echo "0 3 * * * /usr/local/bin/zivpn_expire_check.sh >/dev/null 2>&1") | sudo crontab -

# Set proper permissions
sudo chown -R root:root /var/lib/zivpn_bot
sudo chmod 755 /var/lib/zivpn_bot
sudo chmod 644 /var/lib/zivpn_bot/accounts.db 2>/dev/null || true

sudo chown -R root:root /etc/zivpn
sudo chmod -R 755 /etc/zivpn

# Create test backup to verify
echo "Creating initial test backup..."
sudo /usr/local/bin/zivpn_backup.py 2>/dev/null || true

echo ""
echo "========================================================================"
echo "== INSTALL COMPLETE v6.5.1 with WORKING Restore =="
echo "========================================================================"
echo ""
echo "✅ TELEGRAM BOT BACKUP/RESTORE/UNINSTALL FEATURES ADDED"
echo "✅ FIXED: Restore function now works properly"
echo "✅ FIXED: Permission issues resolved"
echo "✅ DOMAIN/DNS SUPPORT ADDED"
echo "✅ FIXED: Deleted users can now be recreated"
echo "✅ FIXED: Create Account Successfully message with double check mark (✅✅)"
echo ""
echo "📋 **RESTORE FUNCTION NOW WORKING:**"
echo "   1. Send /restore command to bot"
echo "   2. Upload backup file (.tar.gz)"
echo "   3. Confirm restore"
echo "   4. System will restore all users and settings"
echo ""
echo "👑 **Admin Commands (Telegram Bot):**"
echo "  /admin       - Show all admin commands"
echo "  /backup      - Create system backup (sends .tar.gz file) ✅"
echo "  /restore     - Restore from backup (upload .tar.gz file) ✅ FIXED"
echo "  /uninstall   - Uninstall ZIVPN system"
echo "  /stats       - Show detailed system statistics"
echo "  /listall     - List all users (including deleted)"
echo "  /restart     - Restart ZIVPN services"
echo ""
echo "✅ NEW User Card format with DOMAIN:"
echo "   👑 Premium User : 1"
echo "   📡 Server IP : ${ZIVPN_SERVER_IP_DEFAULT}"
echo "   🌐 Server DNS : ${ZIVPN_DOMAIN_DEFAULT:-Not set}"
echo "   👤 Username: xxxx"
echo "   🔑 Password: xxxx"
echo "   📅 Expired Date: xxxx (xx days left)"
echo "   🔋 Status : 🟢 Online"
echo ""
echo "📦 **Migration Workflow (Server to Server):**"
echo "1. On old server: Use /backup command in Telegram Bot"
echo "2. Save the backup file sent by bot"
echo "3. On new server: Install using this script"
echo "4. Set ADMIN_IDS in /etc/default/zivpn_bot"
echo "5. Use /restore command and upload backup file"
echo "6. All users and settings restored! ✅"
echo ""
echo "⚠️ **Important:** If you skipped BOT_TOKEN during install, edit /etc/default/zivpn_bot and set:"
echo "   BOT_TOKEN=\"<your token>\""
echo "   ADMIN_IDS=\"<your telegram id>\""
echo "   Then run: sudo systemctl restart zivpn_bot.service"
echo ""
echo "🔍 **Troubleshooting:**"
echo "   Check bot logs: sudo journalctl -u zivpn_bot.service -n 100 --no-pager"
echo "   Check zivpn logs: sudo journalctl -u zivpn.service -n 50 --no-pager"
echo "   Manual backup test: sudo /usr/local/bin/zivpn_backup.py"
echo ""
echo "✅ Installation complete with WORKING Telegram Bot Restore Function!"
echo "========================================================================"
