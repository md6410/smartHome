# 🏠 smartHome - Complete Raspberry Pi Smart Home System

3-in-1 Smart Home System: Control + Upload + Chat

---

## ✨ File Manager Features

### 📤 File Upload
- Drag & drop support — drop files directly onto the upload zone
- Multi-file queue — add multiple files at once, see each one's status
- Per-file progress bar during upload
- Choose destination folder: Upload Folder, DLNA Music, DLNA Movie, DLNA Pictures
- File type icons auto-detected (PDF, video, audio, image, code, etc.)
- Remove individual files from queue before uploading
- Clear entire queue with one click

### 📋 Paste Text
- Paste any text directly in the browser — saved as a `.txt` file
- Optional custom filename (auto-generates timestamped name if left blank)
- Choose destination folder same as file upload

### 🔗 Temporary Upload Links
- Generate a time-limited link to share with guests
- Set expiry duration in minutes, hours, or days
- Set maximum number of files the guest can upload (0 = unlimited)
- Set maximum total upload size in MB (0 = unlimited)
- Guest sees live usage counters (files used / size used)
- Client-side pre-check warns guest before attempting oversized uploads
- Link auto-expires — shows clear expired message on access

### 📁 File Management (Admin only)
- View all uploaded files with size and download count
- View per-file download history: IP address, timestamp, user agent
- Delete files directly from the dashboard

### 🔒 Account & Password
- Session-based login with 2-hour expiry
- Change password from within the dashboard (requires current password)
- Passwords stored in `uploads/data/users.json` — persist across restarts
- Secret reset link for when you forget your password (see below)

### 👁️ Public Download Page
- Separate public page (`/files`) for guests to download files only
- No login required for downloads

---

## 🔑 Forgot Your Password?

### Method 1 — Check the console on startup
Every time the server starts, the reset URL is printed in the terminal:
🔑 Password reset link: http://localhost:8000/reset/my-secret-reset-key-change-this

text

### Method 2 — Go to the reset URL directly
http://<your-pi-ip>:8000/reset/<RESET_SECRET>

text
The default value of `RESET_SECRET` is `my-secret-reset-key-change-this` — find and change it in `uploadServer.py`.

### Method 3 — Reset manually via terminal
```bash
cd /home/pi/smartHome
python3 -c "
import hashlib, json
users = json.load(open('uploads/data/users.json'))
users['admin'] = hashlib.sha256(b'yournewpassword').hexdigest()
json.dump(users, open('uploads/data/users.json','w'), indent=2)
print('Done')
"
⚠️ Change RESET_SECRET in uploadServer.py to something only you know before exposing the server publicly.

📁 Project Structure
text
smartHome/
├── uploadServer.py          # Main Flask server
├── templates/
│   ├── upload.html          # Admin dashboard
│   ├── public.html          # Public download page
│   └── reset.html           # Password reset page
└── uploads/
    ├── public/              # Uploaded files (served publicly)
    └── data/
        ├── users.json           # Hashed user credentials
        ├── download_counts.json # Per-file download counters
        └── downloadedIP.txt     # Download IP log
🔧 Configuration
Open uploadServer.py and change these before going public:

Variable	Default	Description
app.secret_key	'your-secret-key...'	Flask session secret — must change
RESET_SECRET	'my-secret-reset-key...'	URL token for password reset — must change
upload_folders	uploads/public + DLNA paths	Destination folder mapping
🔐 Default Credentials
Username	Password
admin	13691113
user1	password1
Change passwords immediately after first login using the 🔒 Change Password section in the dashboard.

⚙️ Cloudflare Configuration (Required)
If using Cloudflare DNS:

DNS Records - Add these A records:

home → Your Public IP

uploadserver → Your Public IP

chat → Your Public IP

SSL/TLS Mode - Set to "Full"

Go to: Cloudflare Dashboard → SSL/TLS

Select: "Full" (not Flexible, not Full (strict))

This prevents redirect loops

Wait 2-3 minutes for SSL certificates to generate

⚡ ONE-LINE INSTALLATION
On fresh Raspberry Pi OS:

bash
git clone https://github.com/md6410/smartHome.git && cd smartHome && bash install.sh
