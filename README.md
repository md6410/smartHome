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
