#!/bin/bash
# =========================================
# smartHome - COMPLETE INSTALLER
# Installs: app.py, chatServer.py + Caddy
# uploadServer.py controlled from web interface
# =========================================

set -e

echo "🚀 smartHome - Complete Installation"
echo "======================================"
echo "Installing:"
echo "  ✓ Smart Home Control (port 5000)"
echo "  ✓ Chat Server (port 5554)"
echo "  ✓ Upload Server (web-controlled, port 8000)"
echo "  ✓ Caddy (ports 80/443)"
echo "  ✓ All dependencies"
echo ""
read -p "Continue installation? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ Don't run as root. Run as: bash install.sh${NC}"
   exit 1
fi

# Get system info
USERNAME=$(whoami)
HOME_DIR="/home/$USERNAME"
INSTALL_DIR="$HOME_DIR/smartHome"

echo -e "${BLUE}👤 User: $USERNAME${NC}"
echo -e "${BLUE}📁 Install: $INSTALL_DIR${NC}"
echo ""

# =========================================
# 1. UPDATE SYSTEM
# =========================================
echo -e "${CYAN}[1/15] 🔄 Updating system...${NC}"
sudo apt update -y
sudo apt upgrade -y

# =========================================
# 2. INSTALL SYSTEM PACKAGES
# =========================================
echo -e "${CYAN}[2/15] 📦 Installing system packages...${NC}"
sudo apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-rpi.gpio \
    git \
    curl \
    wget \
    nano \
    vim \
    net-tools \
    ufw \
    build-essential \
    cmake \
    pkg-config \
    libjpeg-dev \
    libpng-dev \
    libtiff-dev \
    libavcodec-dev \
    libavformat-dev \
    libswscale-dev \
    libv4l-dev \
    debian-keyring \
    debian-archive-keyring \
    apt-transport-https \
    dnsutils

# =========================================
# 3. CONFIGURE DNS SERVERS
# =========================================
echo -e "${CYAN}[3/15] 🌐 Configuring DNS servers...${NC}"

# Configure DNS via NetworkManager
ACTIVE_CONNECTION=$(nmcli -t -f NAME con show --active | head -1)
if [ -n "$ACTIVE_CONNECTION" ]; then
    sudo nmcli con mod "$ACTIVE_CONNECTION" ipv4.dns "8.8.8.8 1.1.1.1 8.8.4.4"
    sudo nmcli con up "$ACTIVE_CONNECTION" > /dev/null 2>&1 || true
    echo -e "${GREEN}✓ DNS configured via NetworkManager${NC}"
else
    # Fallback: Set DNS in resolv.conf
    sudo tee /etc/resolv.conf > /dev/null <<EOF
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 8.8.4.4
EOF
    echo -e "${GREEN}✓ DNS configured in resolv.conf${NC}"
fi

# Test DNS
if ping -c 1 google.com > /dev/null 2>&1; then
    echo -e "${GREEN}✓ DNS working correctly${NC}"
else
    echo -e "${YELLOW}⚠️ DNS might not be working properly${NC}"
fi

# =========================================
# 4. INSTALL PYTHON LIBRARIES
# =========================================
echo -e "${CYAN}[4/15] 🐍 Installing Python libraries...${NC}"
pip3 install --user --break-system-packages \
    flask \
    flask-login \
    flask-bcrypt \
    flask-socketio \
    flask-sqlalchemy \
    python-socketio \
    eventlet \
    jdatetime \
    RPi.GPIO \
    requests \
    opencv-python \
    pyserial \
    python-engineio

echo -e "${GREEN}✓ Python libraries installed${NC}"

# =========================================
# 5. CREATE ADDITIONAL FOLDERS
# =========================================
echo -e "${CYAN}[5/15] 📁 Creating folders...${NC}"
mkdir -p "$INSTALL_DIR"/{logs,uploads,instance}

# =========================================
# 6. VERIFY FILES
# =========================================
echo -e "${CYAN}[6/15] 📄 Verifying application files...${NC}"

if [ ! -f "$INSTALL_DIR/app.py" ]; then
    echo -e "${RED}❌ ERROR: app.py not found${NC}"
    exit 1
fi

if [ ! -f "$INSTALL_DIR/uploadServer.py" ]; then
    echo -e "${YELLOW}⚠️ WARNING: uploadServer.py not found${NC}"
fi

if [ ! -f "$INSTALL_DIR/chatServer.py" ]; then
    echo -e "${YELLOW}⚠️ WARNING: chatServer.py not found${NC}"
fi

if [ ! -f "$INSTALL_DIR/templates/index.html" ]; then
    echo -e "${RED}❌ ERROR: templates/index.html not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Core files verified${NC}"

# =========================================
# 7. GENERATE SECRET KEY (if needed)
# =========================================
echo -e "${CYAN}[7/15] 🔐 Checking SECRET_KEY...${NC}"
if grep -q "CHANGE-THIS-TO-YOUR-GENERATED-SECRET-KEY" "$INSTALL_DIR/app.py" 2>/dev/null; then
    SECRET_KEY=$(python3 -c "import os; print(os.urandom(24).hex())")
    sed -i "s/CHANGE-THIS-TO-YOUR-GENERATED-SECRET-KEY/$SECRET_KEY/g" "$INSTALL_DIR/app.py"
    echo -e "${GREEN}✓ Generated new SECRET_KEY${NC}"
else
    echo -e "${GREEN}✓ SECRET_KEY already set${NC}"
fi

# =========================================
# 8. INSTALL CADDY
# =========================================
echo -e "${CYAN}[8/15] 🌐 Installing Caddy web server...${NC}"

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy

echo -e "${GREEN}✓ Caddy installed${NC}"

# =========================================
# 9. CONFIGURE CADDY
# =========================================
echo -e "${CYAN}[9/15] ⚙️ Configuring Caddy...${NC}"

sudo tee /etc/caddy/Caddyfile > /dev/null <<'EOF'
# Main Smart Home Control
home.turingco.ir {
    reverse_proxy localhost:5000
}

# Upload Server Subdomain (runs when toggled from app.py)
uploadserver.turingco.ir {
    reverse_proxy localhost:8000
}

# Chat Server Subdomain
chat.turingco.ir {
    reverse_proxy localhost:5554
}

# Local network HTTP access (no domain)
:80 {
    reverse_proxy localhost:5000
}
EOF

sudo systemctl enable caddy
sudo systemctl restart caddy

echo -e "${GREEN}✓ Caddy configured with home.turingco.ir${NC}"

# =========================================
# 10. CREATE SYSTEMD - SMART HOME
# =========================================
echo -e "${CYAN}[10/15] 🏠 Creating Smart Home service...${NC}"

sudo tee /etc/systemd/system/smarthome.service > /dev/null <<EOF
[Unit]
Description=smartHome Control System
After=network.target
PartOf=smarthome-group.target

[Service]
Type=simple
User=$USERNAME
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
WantedBy=smarthome-group.target
EOF

echo -e "${GREEN}✓ Smart Home service created${NC}"

# =========================================
# 11. CREATE SYSTEMD - CHAT
# =========================================
echo -e "${CYAN}[11/15] 💬 Creating Chat Server service...${NC}"

if [ -f "$INSTALL_DIR/chatServer.py" ]; then
    sudo tee /etc/systemd/system/chatserver.service > /dev/null <<EOF
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
    echo -e "${GREEN}✓ Chat server service created${NC}"
else
    echo -e "${YELLOW}⚠️ Skipped (chatServer.py not found)${NC}"
fi

# =========================================
# 12. CREATE SERVICE GROUP
# =========================================
echo -e "${CYAN}[12/15] 🎯 Creating service group...${NC}"

sudo tee /etc/systemd/system/smarthome-group.target > /dev/null <<EOF
[Unit]
Description=smartHome Service Group
Wants=smarthome.service chatserver.service

[Install]
WantedBy=multi-user.target
EOF

# =========================================
# 13. SETUP GPIO & PERMISSIONS
# =========================================
echo -e "${CYAN}[13/15] 🔧 Setting up permissions...${NC}"

sudo usermod -a -G gpio,dialout,i2c,spi $USERNAME
chmod +x "$INSTALL_DIR/app.py" 2>/dev/null || true
chmod +x "$INSTALL_DIR/uploadServer.py" 2>/dev/null || true
chmod +x "$INSTALL_DIR/chatServer.py" 2>/dev/null || true

# =========================================
# 14. CONFIGURE FIREWALL
# =========================================
echo -e "${CYAN}[14/15] 🔒 Configuring firewall...${NC}"

sudo ufw allow 22/tcp     # SSH
sudo ufw allow 80/tcp     # HTTP
sudo ufw allow 443/tcp    # HTTPS
sudo ufw allow 5000/tcp   # Smart Home
sudo ufw allow 8000/tcp   # Upload
sudo ufw allow 5554/tcp   # Chat
echo "y" | sudo ufw enable

# =========================================
# 15. START SERVICES
# =========================================
echo -e "${CYAN}[15/15] 🚀 Starting services...${NC}"

sudo systemctl daemon-reload

# Enable services
sudo systemctl enable smarthome.service
[ -f "$INSTALL_DIR/chatServer.py" ] && sudo systemctl enable chatserver.service
sudo systemctl enable smarthome-group.target

# Start services
sudo systemctl start smarthome.service
[ -f "$INSTALL_DIR/chatServer.py" ] && sudo systemctl start chatserver.service || true

# Get IP
IP_ADDR=$(hostname -I | awk '{print $1}')

# =========================================
# INSTALLATION COMPLETE
# =========================================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✅ INSTALLATION COMPLETE! 🎉             ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${MAGENTA}📱 ACCESS YOUR SERVICES:${NC}"
echo ""
echo -e "${CYAN}🏠 Smart Home Control:${NC}"
echo -e "   ${GREEN}https://home.turingco.ir${NC} (main domain)"
echo -e "   ${GREEN}http://$IP_ADDR${NC} (local network)"
echo -e "   ${GREEN}http://$IP_ADDR:5000${NC} (direct)"
echo ""
echo -e "${CYAN}📤 Upload Server:${NC}"
echo -e "   ${GREEN}https://uploadserver.turingco.ir${NC}"
echo -e "   ${YELLOW}Toggle ON/OFF from Smart Home dashboard${NC}"
echo ""
echo -e "${CYAN}💬 Chat Server:${NC}"
echo -e "   ${GREEN}https://chat.turingco.ir${NC}"
echo -e "   ${GREEN}http://$IP_ADDR:5554${NC} (direct)"
echo ""
echo -e "${YELLOW}📝 DNS CONFIGURATION:${NC}"
echo -e "   ✓ DNS servers configured (Google: 8.8.8.8, Cloudflare: 1.1.1.1)"
echo -e "   ✓ Make sure these DNS A records exist:"
echo -e "     - home.turingco.ir → Your Public IP"
echo -e "     - uploadserver.turingco.ir → Your Public IP"
echo -e "     - chat.turingco.ir → Your Public IP"
echo ""
echo -e "${CYAN}🔍 SERVICE MANAGEMENT:${NC}"
echo ""
echo -e "${BLUE}Control ALL services:${NC}"
echo "   sudo systemctl start smarthome-group.target"
echo "   sudo systemctl stop smarthome-group.target"
echo "   sudo systemctl restart smarthome-group.target"
echo ""
echo -e "${BLUE}Individual services:${NC}"
echo "   sudo systemctl status smarthome.service"
echo "   sudo systemctl status chatserver.service"
echo "   sudo systemctl status caddy"
echo ""
echo -e "${BLUE}View logs:${NC}"
echo "   journalctl -u smarthome.service -f"
echo "   journalctl -u chatserver.service -f"
echo "   journalctl -u caddy -f"
echo ""
echo -e "${BLUE}Test DNS:${NC}"
echo "   ping google.com"
echo "   ping home.turingco.ir"
echo ""
echo -e "${GREEN}🔄 Reboot recommended:${NC}"
echo "   sudo reboot"
echo ""
echo -e "${BLUE}📚 Repository: https://github.com/md6410/smartHome${NC}"
echo ""
