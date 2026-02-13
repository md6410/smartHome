# 🏠 smartHome - Complete Raspberry Pi Smart Home System

3-in-1 Smart Home System: Control + Upload + Chat


## ⚙️ Cloudflare Configuration (Required)

If using Cloudflare DNS:

1. **DNS Records** - Add these A records:
   - `home` → Your Public IP
   - `uploadserver` → Your Public IP
   - `chat` → Your Public IP

2. **SSL/TLS Mode** - Set to **"Full"**
   - Go to: Cloudflare Dashboard → SSL/TLS
   - Select: **"Full"** (not Flexible, not Full (strict))
   - This prevents redirect loops

3. **Wait 2-3 minutes** for SSL certificates to generate


## ⚡ ONE-LINE INSTALLATION

On fresh Raspberry Pi OS:

```bash
git clone https://github.com/md6410/smartHome.git && cd smartHome && bash install.sh
