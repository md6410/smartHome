#!/bin/bash
# =====================================================================
# smartHome - COMPLETE INSTALLER
#
# Installs, in one pass:
#   Smart Home control   app.py               :5000
#   Chat server          chatServer.py        :5554
#   Upload server        uploadServer.py      :8000  (dashboard toggle)
#   Firmware server      firmware_server-3.py :5001  (dashboard toggle)
#   Caddy                                     :80 :443
#   proxyctl             proxy/               :8090  (owns the Caddyfile)
#
# Routing, TLS, static sites and request logging are all managed from
# the proxyctl panel. Nothing writes /etc/caddy/Caddyfile by hand.
#
#   git clone https://github.com/md6410/smartHome.git
#   cd smartHome && bash install.sh
#
# Every file, service, package and firewall rule created here is written
# to /var/lib/smarthome/manifest, and uninstall.sh reverses exactly that.
# =====================================================================

set -Eeuo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

# apt must never stop to ask a question - there is no one watching it here
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

say()  { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}  ok  $*${NC}"; }
warn() { echo -e "${YELLOW}  !   $*${NC}"; }
die()  { echo -e "${RED}x $*${NC}" >&2; exit 1; }

trap 'die "Failed on line $LINENO. Run uninstall.sh to undo what was already changed."' ERR

# ---------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------
[[ $EUID -eq 0 ]] && die "Don't run as root. Run: bash install.sh"
command -v sudo >/dev/null || die "sudo is required."

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USERNAME="$(whoami)"
INSTALL_DIR="$SRC_DIR"
PROXY_DIR="$INSTALL_DIR/proxy"
STATE_DIR="/var/lib/smarthome"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$STATE_DIR/backup-$STAMP"
MANIFEST="$STATE_DIR/manifest"

MISSING=()
for f in app.py templates/index.html requirements.txt uninstall.sh \
         proxy/proxy_manager.py proxy/templates/proxy.html; do
    [[ -f "$SRC_DIR/$f" ]] || MISSING+=("$f")
done
if (( ${#MISSING[@]} )); then
    echo -e "${RED}Missing from $SRC_DIR:${NC}" >&2
    printf '  %s\n' "${MISSING[@]}" >&2
    echo >&2
    echo "Copy the whole project across, or clone it:" >&2
    echo "  git clone https://github.com/md6410/smartHome.git" >&2
    exit 1
fi

echo -e "${MAGENTA}smartHome - complete installation${NC}"
echo "======================================"
echo "  Smart Home control      :5000"
echo "  Chat server             :5554"
echo "  Upload server           :8000   (dashboard toggle)"
echo "  Firmware server         :5001   (dashboard toggle)"
echo "  Caddy                   :80 :443"
echo "  proxyctl routing panel  :8090"
echo
echo -e "${BLUE}User:    $USERNAME${NC}"
echo -e "${BLUE}Folder:  $INSTALL_DIR${NC}"
echo

# ---------------------------------------------------------------------
# Answers needed up front, so the rest runs unattended
# ---------------------------------------------------------------------
read -rp "Base domain for the four services [turingco.ir]: " BASE_DOMAIN
BASE_DOMAIN="${BASE_DOMAIN:-turingco.ir}"
BASE_DOMAIN="${BASE_DOMAIN#.}"; BASE_DOMAIN="${BASE_DOMAIN%.}"

read -rp "Email for Let's Encrypt certificates (blank to skip): " ACME_EMAIL

read -rp "Folder to serve static websites from [/var/www/sites]: " WEBROOT
WEBROOT="${WEBROOT:-/var/www/sites}"
[[ "$WEBROOT" == /* ]] || die "The website folder must be a full path starting with /."

echo
echo "  Domains:  home.$BASE_DOMAIN  chat.$BASE_DOMAIN"
echo "            uploadserver.$BASE_DOMAIN  firmware.$BASE_DOMAIN"
echo "  Websites: $WEBROOT"
echo "  Certs:    ${ACME_EMAIL:-Caddy default, no account email}"
echo
read -rp "Continue? (y/n): " -n 1 -r; echo
[[ $REPLY =~ ^[Yy]$ ]] || exit 1

# ---------------------------------------------------------------------
# Manifest - the record uninstall.sh reads back
# ---------------------------------------------------------------------
sudo mkdir -p "$STATE_DIR" "$BACKUP_DIR"
sudo touch "$MANIFEST"
record() { echo "$1:$2" | sudo tee -a "$MANIFEST" >/dev/null; }

if sudo grep -q '^complete:' "$MANIFEST" 2>/dev/null; then
    warn "A previous installation is recorded here. Re-running updates it."
fi

record meta "user=$USERNAME"
record meta "install_dir=$INSTALL_DIR"
record meta "webroot=$WEBROOT"
record meta "backup=$BACKUP_DIR"
record meta "started=$STAMP"
record dir "$STATE_DIR"

# ---------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------
say "[1/12] System packages"
echo "  This is the long step - build tools and image libraries."
echo "  On a slow connection it can take 10-20 minutes. Output follows."

sudo apt-get update -y
sudo apt-get install -y \
    python3 python3-pip python3-dev \
    git curl wget net-tools ufw dnsutils acl \
    build-essential pkg-config \
    libjpeg-dev libpng-dev libtiff-dev \
    libavcodec-dev libavformat-dev libswscale-dev libv4l-dev \
    debian-keyring debian-archive-keyring apt-transport-https
sudo apt-get install -y python3-rpi.gpio || warn "python3-rpi.gpio unavailable (not a Pi?) - continuing"
ok "packages installed"

# ---------------------------------------------------------------------
# 2. Python libraries
# ---------------------------------------------------------------------
say "[2/12] Python libraries"
echo "  Also slow - opencv may build from source on a Pi."
echo

# Newer Debian/Raspberry Pi OS refuses to install into the system Python
# without this flag; older pip does not recognise it. Test once, visibly,
# instead of hiding the error and guessing from a failed exit code.
if pip3 install --break-system-packages --dry-run pip >/dev/null 2>&1; then
    PIPFLAG="--break-system-packages"
else
    PIPFLAG=""
fi
echo "  pip flag: ${PIPFLAG:-none needed}"

# shellcheck disable=SC2086
pip3 install $PIPFLAG -r "$SRC_DIR/requirements.txt"

# proxyctl runs as root, so Flask must be importable by root too
# shellcheck disable=SC2086
sudo pip3 install $PIPFLAG flask
ok "libraries installed"

# ---------------------------------------------------------------------
# 3. Folders
# ---------------------------------------------------------------------
say "[3/12] Folders"
mkdir -p "$INSTALL_DIR"/{logs,uploads,uploads/firmware,instance}
record dir "$INSTALL_DIR/logs"
record dir "$INSTALL_DIR/uploads"
ok "application folders ready"

# ---------------------------------------------------------------------
# 4. Secret key
# ---------------------------------------------------------------------
say "[4/12] Secret keys"
# Each server now creates its own random key in instance/ on first start
# (local_secrets.py), so nothing in the code needs rewriting here.
mkdir -p "$INSTALL_DIR/instance"
chmod 700 "$INSTALL_DIR/instance"
ok "keys will be generated in $INSTALL_DIR/instance on first start"

# ---------------------------------------------------------------------
# 5. Caddy
# ---------------------------------------------------------------------
say "[5/12] Caddy"
if command -v caddy >/dev/null; then
    ok "already installed - uninstall.sh will leave it in place"
else
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    sudo apt-get update -y
    sudo apt-get install -y caddy
    record pkg caddy
    record file /etc/apt/sources.list.d/caddy-stable.list
    record file /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    ok "installed"
fi

# nginx and Caddy cannot share port 80
if systemctl list-unit-files 2>/dev/null | grep -q '^nginx.service'; then
    warn "nginx found - stopping it so Caddy can hold port 80"
    sudo cp -r /etc/nginx "$BACKUP_DIR/nginx" 2>/dev/null || true
    sudo systemctl stop nginx 2>/dev/null || true
    sudo systemctl disable nginx 2>/dev/null || true
    record disabled_service nginx
fi
# leftovers from the earlier nginx-based version of this panel
sudo rm -f /etc/nginx/sites-enabled/nginxctl_* /etc/nginx/conf.d/nginxctl_* 2>/dev/null || true

# From here the Caddyfile belongs to proxyctl - keep whatever was there
if [[ -f /etc/caddy/Caddyfile ]]; then
    sudo cp /etc/caddy/Caddyfile "$BACKUP_DIR/Caddyfile.orig"
    record backup_file "/etc/caddy/Caddyfile"
    ok "existing Caddyfile saved to $BACKUP_DIR"
fi

# ---------------------------------------------------------------------
# 6. Request log - proxyctl reads its log viewer from this file
# ---------------------------------------------------------------------
say "[6/12] Request log"
sudo mkdir -p /var/log/caddy
sudo touch /var/log/caddy/access.log
sudo chown -R caddy:caddy /var/log/caddy
sudo chmod 755 /var/log/caddy
sudo chmod 644 /var/log/caddy/access.log
record dir /var/log/caddy
ok "/var/log/caddy/access.log ready"

# ---------------------------------------------------------------------
# 7. Website folder - Caddy serves as its own user and must reach it
# ---------------------------------------------------------------------
say "[7/12] Website folder"
sudo mkdir -p "$WEBROOT"
sudo chown -R caddy:caddy "$WEBROOT"
sudo chmod 755 "$WEBROOT"
record dir "$WEBROOT"

# Caddy needs execute permission on every parent to reach the folder.
# Under a home directory (drwx------) it cannot, so grant traverse with
# an ACL rather than opening that home directory to every user.
PARENT="$(dirname "$WEBROOT")"
while [[ "$PARENT" != "/" ]]; do
    if ! sudo -u caddy test -x "$PARENT" 2>/dev/null; then
        sudo setfacl -m u:caddy:x "$PARENT" && record acl "$PARENT"
        warn "granted caddy traverse on $PARENT"
    fi
    PARENT="$(dirname "$PARENT")"
done
if sudo -u caddy test -r "$WEBROOT"; then
    ok "caddy can read $WEBROOT"
else
    warn "caddy still cannot read $WEBROOT - check the path by hand"
fi

# ---------------------------------------------------------------------
# 8. Service units
# ---------------------------------------------------------------------
say "[8/12] Services"

unit() {
    sudo tee "/etc/systemd/system/$1" >/dev/null
    record file "/etc/systemd/system/$1"
}

unit smarthome.service <<EOF
[Unit]
Description=smartHome Control System
After=network.target
PartOf=smarthome-group.target

[Service]
Type=simple
User=$USERNAME
WorkingDirectory=$INSTALL_DIR
Environment=SMARTHOME_DOMAIN=$BASE_DOMAIN
ExecStart=/usr/bin/python3 $INSTALL_DIR/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
WantedBy=smarthome-group.target
EOF
ok "smarthome.service"

if [[ -f "$INSTALL_DIR/chatServer.py" ]]; then
unit chatserver.service <<EOF
[Unit]
Description=smartHome Chat Server
After=network.target
PartOf=smarthome-group.target

[Service]
Type=simple
User=$USERNAME
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/chatServer.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
WantedBy=smarthome-group.target
EOF
ok "chatserver.service"
fi

# proxyctl runs as root: it writes /etc/caddy/Caddyfile, reloads the
# service, and hands uploaded site files to the caddy user.
unit proxyctl.service <<EOF
[Unit]
Description=proxyctl reverse proxy manager
After=network.target
Wants=caddy.service

[Service]
Type=simple
User=root
WorkingDirectory=$PROXY_DIR
Environment=PROXYCTL_WEBROOT=$WEBROOT
Environment=PROXYCTL_SEED_DOMAIN=$BASE_DOMAIN
Environment=PROXYCTL_CADDYFILE=/etc/caddy/Caddyfile
Environment=PROXYCTL_ACCESS_LOG=/var/log/caddy/access.log
ExecStart=/usr/bin/python3 $PROXY_DIR/proxy_manager.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
ok "proxyctl.service"

# Caddy itself: the stock unit has no Restart= and starts as the caddy
# user, so a boot where /var/log/caddy/access.log is missing or owned by
# root leaves it dead with "caddy failed". Recreate the log as root before
# every start, wait for the network, and retry instead of giving up.
sudo mkdir -p /etc/systemd/system/caddy.service.d
unit caddy.service.d/smarthome.conf <<EOF
[Unit]
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
ExecStartPre=+/bin/sh -c 'mkdir -p /var/log/caddy && touch /var/log/caddy/access.log && chown -R caddy:caddy /var/log/caddy && chmod 755 /var/log/caddy && chmod 644 /var/log/caddy/access.log'
Restart=on-failure
RestartSec=5
EOF
ok "caddy.service boot fixes"

unit smarthome-group.target <<EOF
[Unit]
Description=smartHome Service Group
Wants=smarthome.service chatserver.service proxyctl.service

[Install]
WantedBy=multi-user.target
EOF
ok "smarthome-group.target"

# ---------------------------------------------------------------------
# 9. Permissions
# ---------------------------------------------------------------------
say "[9/12] Permissions"
for g in gpio dialout i2c spi; do
    if getent group "$g" >/dev/null && ! id -nG "$USERNAME" | grep -qw "$g"; then
        sudo usermod -a -G "$g" "$USERNAME"
        record group "$g"
    fi
done
chmod +x "$INSTALL_DIR"/*.py 2>/dev/null || true
chmod +x "$PROXY_DIR"/proxy_manager.py 2>/dev/null || true
ok "hardware groups and file modes set"

# ---------------------------------------------------------------------
# 10. Firewall
# ---------------------------------------------------------------------
say "[10/12] Firewall"
# Only 22, 80 and 443 face the internet. The panel and the application
# ports stay on the LAN; public traffic arrives through Caddy.
LAN_CIDR="$(ip -o -f inet addr show 2>/dev/null \
    | awk '$2!="lo"{print $4}' | head -1 \
    | python3 -c "
import sys, ipaddress
raw = sys.stdin.read().strip()
print(str(ipaddress.ip_network(raw, strict=False)) if raw else '')
" 2>/dev/null || true)"

for p in 22 80 443; do
    sudo ufw allow "$p"/tcp >/dev/null 2>&1 || true
    record ufw "$p/tcp"
done

if [[ -n "$LAN_CIDR" ]]; then
    for p in 8090 5000 5554 8000 5001; do
        sudo ufw allow from "$LAN_CIDR" to any port "$p" proto tcp >/dev/null 2>&1 || true
        record ufw_from "$LAN_CIDR|$p"
    done
    ok "22, 80, 443 open; panel and app ports limited to $LAN_CIDR"
else
    for p in 8090 5000 5554 8000 5001; do
        sudo ufw allow "$p"/tcp >/dev/null 2>&1 || true
        record ufw "$p/tcp"
    done
    warn "LAN range not detected - app ports opened to all; narrow them later"
fi
echo "y" | sudo ufw enable >/dev/null 2>&1 || true
record ufw_enabled "1"

# ---------------------------------------------------------------------
# 11. Start
# ---------------------------------------------------------------------
say "[11/12] Starting services"
sudo systemctl daemon-reload
sudo systemctl enable --now caddy >/dev/null 2>&1 || true
for s in smarthome.service chatserver.service proxyctl.service smarthome-group.target; do
    [[ -f "/etc/systemd/system/$s" ]] || continue
    sudo systemctl enable "$s" >/dev/null 2>&1 || true
    record service "$s"
done
sudo systemctl restart smarthome.service
[[ -f /etc/systemd/system/chatserver.service ]] && sudo systemctl restart chatserver.service
sudo systemctl restart proxyctl.service
sleep 4
ok "services started"

# ---------------------------------------------------------------------
# 12. First Caddyfile, written by proxyctl from the seeded routes
# ---------------------------------------------------------------------
say "[12/12] Generating the Caddyfile"
if [[ -n "$ACME_EMAIL" ]]; then
    curl -sf -X POST -H 'Content-Type: application/json' \
        -d "{\"acme_email\":\"$ACME_EMAIL\"}" \
        http://127.0.0.1:8090/api/settings >/dev/null 2>&1 || true
fi

if curl -sf -X POST http://127.0.0.1:8090/api/apply 2>/dev/null | grep -q '"ok": *true'; then
    ok "routes applied and Caddy reloaded"
else
    warn "apply did not report success - open the panel and press Apply"
fi

sudo ln -sf "$INSTALL_DIR/update.sh" /usr/local/bin/smarthome-update
record file /usr/local/bin/smarthome-update

record complete "$(date +%Y%m%d-%H%M%S)"
sudo cp "$SRC_DIR/uninstall.sh" "$STATE_DIR/uninstall.sh" 2>/dev/null || true

# ---------------------------------------------------------------------
IP_ADDR="$(hostname -I | awk '{print $1}')"
echo
echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}  Installation complete${NC}"
echo -e "${GREEN}==============================================${NC}"
echo
echo -e "${MAGENTA}Routing panel${NC}"
echo -e "   ${GREEN}http://$IP_ADDR:8090${NC}   domains, TLS, static sites, request log"
echo
echo -e "${MAGENTA}Services${NC}"
echo -e "   ${GREEN}https://home.$BASE_DOMAIN${NC}          smart home control"
echo -e "   ${GREEN}https://chat.$BASE_DOMAIN${NC}          chat"
echo -e "   ${GREEN}https://uploadserver.$BASE_DOMAIN${NC}  uploads, toggled from the dashboard"
echo -e "   ${GREEN}https://firmware.$BASE_DOMAIN${NC}      firmware, toggled from the dashboard"
echo -e "   ${GREEN}http://$IP_ADDR${NC}                    control panel over the LAN"
echo
echo -e "${MAGENTA}DNS${NC}   point these A records at your public IP:"
echo "   home  chat  uploadserver  firmware   under .$BASE_DOMAIN"
echo
echo -e "${MAGENTA}Behind Cloudflare or Arvan${NC}"
echo "   SSL mode Full, and paste the CDN ranges into"
echo "   Settings > Trusted proxies so the log shows real visitor IPs."
echo
echo -e "${MAGENTA}Checks${NC}"
echo "   systemctl status proxyctl caddy smarthome --no-pager"
echo "   curl -I -H 'Host: home.$BASE_DOMAIN' http://127.0.0.1/"
echo "   journalctl -u proxyctl -f"
echo
echo -e "${MAGENTA}Updates${NC}"
echo "   smarthome-update            pull the latest code and restart"
echo "   smarthome-update --rollback undo the last update"
echo
echo -e "${MAGENTA}Removal${NC}"
echo "   bash uninstall.sh"
echo
echo -e "${YELLOW}Reboot recommended so the hardware groups take effect: sudo reboot${NC}"
echo
