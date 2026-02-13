from flask import Flask, request, render_template, send_from_directory, session, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import os
import hashlib
import json
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-to-random-string-12345'
app.permanent_session_lifetime = timedelta(hours=2)

# Better session configuration
app.config.update(
    SESSION_COOKIE_NAME='file_manager_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_REFRESH_EACH_REQUEST=True
)
upload_dir = 'uploads'
upload_folders = {
    'Upload Folder': upload_dir,
    'DLNA Music': '/media/HDD/Music',
    'DLNA Movie': '/media/HDD/Movies',
    'DLNA Pictures': '/media/HDD/Pictures'
}

# Users database (username: password_hash)
users = {
    'admin': hashlib.sha256(b'13691113').hexdigest(),
    'user1': hashlib.sha256(b'password1').hexdigest(),
}

download_counter_file = 'download_counts.json'
ip_log_file = 'downloadedIP.txt'

# Template filter for file icons
@app.template_filter('get_file_icon')
def get_file_icon(filename):
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    icons = {
        'pdf': '📄',
        'doc': '📝', 'docx': '📝',
        'xls': '📊', 'xlsx': '📊',
        'ppt': '📊', 'pptx': '📊',
        'zip': '🗜️', 'rar': '🗜️', '7z': '🗜️',
        'mp3': '🎵', 'wav': '🎵', 'flac': '🎵',
        'mp4': '🎬', 'avi': '🎬', 'mkv': '🎬',
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️',
        'txt': '📃',
        'py': '🐍', 'js': '📜', 'html': '🌐',
    }
    return icons.get(ext, '📦')

def get_download_counts():
    if os.path.exists(download_counter_file):
        try:
            with open(download_counter_file, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_download_counts(counts):
    with open(download_counter_file, 'w') as f:
        json.dump(counts, f)

def verify_credentials(username, password):
    if username in users:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return users[username] == password_hash
    return False

def get_file_size(filename):
    try:
        size = os.path.getsize(os.path.join(upload_dir, filename))
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    except:
        return "Unknown"

def get_file_download_ips(filename):
    """Get list of IPs that downloaded a specific file"""
    downloads = []
    if os.path.exists(ip_log_file):
        try:
            with open(ip_log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(',')
                    if len(parts) >= 2 and parts[0] == filename:
                        downloads.append({
                            'ip': parts[1] if len(parts) > 1 else 'Unknown',
                            'user_agent': parts[2] if len(parts) > 2 else 'Unknown',
                            'timestamp': parts[3] if len(parts) > 3 else 'Unknown'
                        })
        except Exception as e:
            print(f"Error reading IP log: {e}")
    return downloads

@app.route('/')
def index():
    file_list = os.listdir(upload_dir)
    download_counts = get_download_counts()
    file_info = []
    for filename in file_list:
        file_info.append({
            'name': filename,
            'size': get_file_size(filename),
            'downloads': download_counts.get(filename, 0)
        })
    return render_template('upload.html', 
                         file_list=file_info, 
                         is_authenticated=session.get('authenticated', False),
                         username=session.get('username', ''))

@app.route('/files')
def public_files():
    """Public page for downloading files only"""
    file_list = os.listdir(upload_dir)
    file_info = []
    for filename in file_list:
        file_info.append({
            'name': filename,
            'size': get_file_size(filename)
        })
    return render_template('public.html', file_list=file_info)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    if verify_credentials(username, password):
        session.permanent = True
        session['authenticated'] = True
        session['username'] = username
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Invalid username or password'}), 401

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    # Check authentication
    if not session.get('authenticated', False):
        return "Unauthorized - Please login first", 403
    
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    
    if file:
        filename = secure_filename(file.filename)
        destination = request.form.get('destination', 'Upload Folder')
        upload_folder = upload_folders.get(destination, upload_dir)
        
        # Create directory if it doesn't exist
        os.makedirs(upload_folder, exist_ok=True)
        
        filepath = os.path.join(upload_folder, filename)
        file.save(filepath)
        
        # Initialize download count for new file
        download_counts = get_download_counts()
        if filename not in download_counts:
            download_counts[filename] = 0
            save_download_counts(download_counts)
            
        return "File uploaded successfully"

@app.route('/uploads/<path:filename>', methods=['GET'])
def get_file(filename):
    client_ip = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Log IP to file with timestamp
    with open(ip_log_file, 'a', encoding='utf-8') as f:
        f.write(f"{filename},{client_ip},{request.headers.get('User-Agent', 'Unknown')},{timestamp}\n")
    
    # Update download count
    download_counts = get_download_counts()
    if filename in download_counts:
        download_counts[filename] += 1
    else:
        download_counts[filename] = 1
    save_download_counts(download_counts)
    
    return send_from_directory(upload_dir, filename)

@app.route('/file-ips/<path:filename>', methods=['GET'])
def file_ips(filename):
    """Get IPs that downloaded a specific file"""
    if not session.get('authenticated', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        downloads = get_file_download_ips(filename)
        return jsonify({
            'success': True,
            'filename': filename,
            'downloads': downloads,
            'total': len(downloads)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/delete/<path:filename>', methods=['POST'])
def delete_file(filename):
    if not session.get('authenticated', False):
        return "Unauthorized", 403
    
    file_path = os.path.join(upload_dir, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        
        # Remove file from download counts
        download_counts = get_download_counts()
        if filename in download_counts:
            del download_counts[filename]
            save_download_counts(download_counts)
            
        return "File deleted successfully"
    else:
        return "File not found", 404

if __name__ == '__main__':
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
    app.run(debug=True, host='0.0.0.0', port=8000)
