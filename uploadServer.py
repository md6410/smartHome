from flask import Flask, request, render_template, send_from_directory, session, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import os
import hashlib
import json
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-to-random-string-12345'
app.permanent_session_lifetime = timedelta(hours=2)

app.config.update(
    SESSION_COOKIE_NAME='file_manager_session',
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_REFRESH_EACH_REQUEST=True
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads', 'public')
DATA_DIR = os.path.join(BASE_DIR, 'uploads', 'data')

os.makedirs(PUBLIC_UPLOAD_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

upload_folders = {
    'Upload Folder': PUBLIC_UPLOAD_DIR,
    'DLNA Music': '/media/HDD/Music',
    'DLNA Movie': '/media/HDD/Movies',
    'DLNA Pictures': '/media/HDD/Pictures'
}

# Secret key for password reset — change this to something only you know
RESET_SECRET = 'my-secret-reset-key-change-this'

USERS_FILE = os.path.join(DATA_DIR, 'users.json')
TEMP_TOKENS = {}
FILE_TOKENS = {}
download_counter_file = os.path.join(DATA_DIR, 'download_counts.json')
ip_log_file = os.path.join(DATA_DIR, 'downloadedIP.txt')


# ── User management ───────────────────────────────────────────────────────────

def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    default = {
        'admin': hashlib.sha256(b'13691113').hexdigest(),
        'user1': hashlib.sha256(b'password1').hexdigest(),
    }
    save_users(default)
    return default


def save_users(users_dict):
    with open(USERS_FILE, 'w') as f:
        json.dump(users_dict, f, indent=2)


def verify_credentials(username, password):
    current_users = load_users()
    if username in current_users:
        return current_users[username] == hashlib.sha256(password.encode()).hexdigest()
    return False


# ── Token management ──────────────────────────────────────────────────────────

def create_temp_token(minutes, max_files=0, max_size_mb=0):
    token = secrets.token_urlsafe(32)
    TEMP_TOKENS[token] = {
        'expiry': datetime.now() + timedelta(minutes=minutes),
        'max_files': max_files,
        'max_size_mb': max_size_mb,
        'uploaded_files': 0,
        'uploaded_bytes': 0
    }
    return token


def validate_temp_token(token):
    if token in TEMP_TOKENS:
        if datetime.now() < TEMP_TOKENS[token]['expiry']:
            return True
        else:
            del TEMP_TOKENS[token]
    return False


def get_token_data(token):
    return TEMP_TOKENS.get(token)


def cleanup_expired_tokens():
    expired = [t for t, data in TEMP_TOKENS.items() if datetime.now() >= data['expiry']]
    for t in expired:
        del TEMP_TOKENS[t]
def create_file_token(filename, minutes=0, max_downloads=0):
    token = secrets.token_urlsafe(32)
    FILE_TOKENS[token] = {
        'filename': filename,
        'expiry': datetime.now() + timedelta(minutes=minutes) if minutes > 0 else None,
        'max_downloads': max_downloads,
        'download_count': 0,
        'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    return token

def validate_file_token(token):
    if token not in FILE_TOKENS:
        return None, 'Link not found or already expired'
    td = FILE_TOKENS[token]
    if td['expiry'] and datetime.now() > td['expiry']:
        del FILE_TOKENS[token]
        return None, 'Link has expired'
    if td['max_downloads'] > 0 and td['download_count'] >= td['max_downloads']:
        del FILE_TOKENS[token]
        return None, 'Download limit reached'
    return td, None


# ── File helpers ──────────────────────────────────────────────────────────────

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


def get_file_size(filename):
    try:
        size = os.path.getsize(os.path.join(PUBLIC_UPLOAD_DIR, filename))
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    except:
        return "Unknown"


def get_file_download_ips(filename):
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


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    cleanup_expired_tokens()

    token = request.args.get('token')
    if token:
        if validate_temp_token(token):
            session['temp_access'] = True
            session['temp_token'] = token
            session['temp_expiry'] = TEMP_TOKENS[token]['expiry'].strftime('%Y-%m-%d %H:%M:%S')
        else:
            session.pop('temp_access', None)
            session.pop('temp_token', None)
            session.pop('temp_expiry', None)
            return render_template('upload.html',
                                   is_authenticated=False,
                                   is_temp=False,
                                   username='',
                                   file_list=[],
                                   link_expired=True,
                                   temp_expiry='',
                                   token_data=None)
        return redirect(url_for('index'))

    if session.get('temp_access') and session.get('temp_token'):
        if not validate_temp_token(session['temp_token']):
            session.pop('temp_access', None)
            session.pop('temp_token', None)
            session.pop('temp_expiry', None)
            return render_template('upload.html',
                                   is_authenticated=False,
                                   is_temp=False,
                                   username='',
                                   file_list=[],
                                   link_expired=True,
                                   temp_expiry='',
                                   token_data=None)

    try:
        all_items = os.listdir(PUBLIC_UPLOAD_DIR)
        file_list = [f for f in all_items
                     if os.path.isfile(os.path.join(PUBLIC_UPLOAD_DIR, f)) and not f.startswith('.')]
    except:
        file_list = []

    download_counts = get_download_counts()
    file_info = [{'name': f, 'size': get_file_size(f), 'downloads': download_counts.get(f, 0)} for f in file_list]

    token_data = None
    if session.get('temp_access') and session.get('temp_token'):
        token_data = get_token_data(session['temp_token'])

    return render_template('upload.html',
                           file_list=file_info,
                           is_authenticated=session.get('authenticated', False),
                           is_temp=session.get('temp_access', False),
                           temp_expiry=session.get('temp_expiry', ''),
                           username=session.get('username', ''),
                           link_expired=False,
                           token_data=token_data)


@app.route('/files')
def public_files():
    if not session.get('authenticated', False):
        return redirect(url_for('index'))
    try:
        all_items = os.listdir(PUBLIC_UPLOAD_DIR)
        file_list = [f for f in all_items
                     if os.path.isfile(os.path.join(PUBLIC_UPLOAD_DIR, f)) and not f.startswith('.')]
    except:
        file_list = []
    download_counts = get_download_counts()
    file_info = [{'name': f, 'size': get_file_size(f), 'downloads': download_counts.get(f, 0)} for f in file_list]
    return render_template('public.html', file_list=file_info, username=session.get('username', ''))


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


@app.route('/change-password', methods=['POST'])
def change_password():
    if not session.get('authenticated', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data             = request.get_json()
    current_password = data.get('current_password', '')
    new_password     = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')

    if not current_password or not new_password or not confirm_password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    if new_password != confirm_password:
        return jsonify({'success': False, 'message': 'New passwords do not match'}), 400
    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400

    username      = session.get('username')
    current_users = load_users()

    if current_users.get(username) != hashlib.sha256(current_password.encode()).hexdigest():
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 401

    current_users[username] = hashlib.sha256(new_password.encode()).hexdigest()
    save_users(current_users)
    return jsonify({'success': True, 'message': 'Password changed successfully'})

@app.route('/delete-all', methods=['POST'])
def delete_all_files():
    if not session.get('authenticated', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    try:
        all_items = os.listdir(PUBLIC_UPLOAD_DIR)
        files = [f for f in all_items if os.path.isfile(os.path.join(PUBLIC_UPLOAD_DIR, f)) and not f.startswith('.')]
        for filename in files:
            os.remove(os.path.join(PUBLIC_UPLOAD_DIR, filename))
        # Clear download counts
        save_download_counts({})
        return jsonify({'success': True, 'message': f'{len(files)} file(s) deleted'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/generate-file-link', methods=['POST'])
def generate_file_link():
    if not session.get('authenticated', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    data        = request.get_json()
    filename    = data.get('filename', '').strip()
    minutes     = max(0, int(data.get('minutes', 0)))
    max_dl      = max(0, int(data.get('max_downloads', 0)))
    if not filename:
        return jsonify({'success': False, 'message': 'Filename required'}), 400
    filepath = os.path.join(PUBLIC_UPLOAD_DIR, secure_filename(filename))
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'message': 'File not found'}), 404
    token    = create_file_token(filename, minutes, max_dl)
    td       = FILE_TOKENS[token]
    link     = request.host_url.rstrip('/') + f'/dl/{token}'
    expiry   = td['expiry'].strftime('%Y-%m-%d %H:%M:%S') if td['expiry'] else 'Never'
    return jsonify({'success': True, 'link': link, 'expiry': expiry})


@app.route('/dl/<token>')
def download_via_token(token):
    td, error = validate_file_token(token)
    if not td:
        return f'''<!DOCTYPE html>
<html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Link Expired</title>
<style>
  body{{font-family:-apple-system,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);
       min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}}
  .box{{background:white;border-radius:16px;padding:40px 30px;text-align:center;max-width:400px;width:100%;}}
  .icon{{font-size:3em;margin-bottom:16px;}}
  h2{{color:#333;margin-bottom:10px;}}
  p{{color:#888;margin-bottom:24px;}}
  a{{background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:12px 28px;
     border-radius:8px;text-decoration:none;font-weight:600;}}
</style></head>
<body><div class="box">
  <div class="icon">⏰</div>
  <h2>Link Unavailable</h2>
  <p>{error}</p>
  <a href="/">Go Home</a>
</div></body></html>''', 410

    filename = td['filename']
    filepath = os.path.join(PUBLIC_UPLOAD_DIR, filename)
    if not os.path.exists(filepath):
        return 'File not found', 404

    FILE_TOKENS[token]['download_count'] += 1

    client_ip = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(ip_log_file, 'a', encoding='utf-8') as f:
        f.write(f"{filename},{client_ip},{request.headers.get('User-Agent','Unknown')},{timestamp}\n")
    counts = get_download_counts()
    counts[filename] = counts.get(filename, 0) + 1
    save_download_counts(counts)

    # Auto-delete token if download limit hit
    if td['max_downloads'] > 0 and FILE_TOKENS.get(token, {}).get('download_count', 0) >= td['max_downloads']:
        if token in FILE_TOKENS:
            del FILE_TOKENS[token]

    return send_from_directory(PUBLIC_UPLOAD_DIR, filename, as_attachment=True)

@app.route('/reset/<secret>', methods=['GET', 'POST'])
def reset_password(secret):
    if secret != RESET_SECRET:
        return "Not found", 404

    current_users = load_users()

    if request.method == 'POST':
        username     = request.form.get('username', '').strip()
        new_password = request.form.get('new_password', '')
        confirm      = request.form.get('confirm_password', '')

        if not username or not new_password or not confirm:
            return render_template('reset.html', error='All fields are required',
                                   secret=secret, users=list(current_users.keys()))
        if username not in current_users:
            return render_template('reset.html', error=f'User "{username}" not found',
                                   secret=secret, users=list(current_users.keys()))
        if new_password != confirm:
            return render_template('reset.html', error='Passwords do not match',
                                   secret=secret, users=list(current_users.keys()))
        if len(new_password) < 6:
            return render_template('reset.html', error='Password must be at least 6 characters',
                                   secret=secret, users=list(current_users.keys()))

        current_users[username] = hashlib.sha256(new_password.encode()).hexdigest()
        save_users(current_users)
        return render_template('reset.html',
                               success=f'Password for "{username}" has been reset',
                               secret=secret, users=list(current_users.keys()))

    return render_template('reset.html', secret=secret, users=list(current_users.keys()))


@app.route('/generate-temp-link', methods=['POST'])
def generate_temp_link():
    if not session.get('authenticated', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data        = request.get_json()
    minutes     = max(1, min(int(data.get('minutes', 60)), 10080))
    max_files   = max(0, int(data.get('max_files', 0)))
    max_size_mb = max(0, int(data.get('max_size_mb', 0)))

    token  = create_temp_token(minutes, max_files, max_size_mb)
    expiry = TEMP_TOKENS[token]['expiry'].strftime('%Y-%m-%d %H:%M:%S')
    link   = request.host_url.rstrip('/') + f'/?token={token}'

    return jsonify({'success': True, 'link': link, 'expiry': expiry})


@app.route('/upload', methods=['POST'])
def upload_file():
    is_auth = session.get('authenticated', False)
    is_temp = session.get('temp_access', False)
    token   = session.get('temp_token')

    if not is_auth and not is_temp:
        return "Unauthorized", 403
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    file_data = file.read()
    file_size = len(file_data)

    if is_temp and token and token in TEMP_TOKENS:
        td = TEMP_TOKENS[token]
        if td['max_files'] > 0 and td['uploaded_files'] >= td['max_files']:
            return jsonify({'success': False, 'message': f"Upload limit reached ({td['max_files']} files)"}), 403
        if td['max_size_mb'] > 0:
            max_bytes = td['max_size_mb'] * 1024 * 1024
            if td['uploaded_bytes'] + file_size > max_bytes:
                remaining = max_bytes - td['uploaded_bytes']
                return jsonify({'success': False, 'message': f"Size limit reached. Remaining: {remaining/1024/1024:.1f} MB"}), 403

    filename    = secure_filename(file.filename)
    destination = request.form.get('destination', 'Upload Folder')
    upload_dir  = upload_folders.get(destination, PUBLIC_UPLOAD_DIR)
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, filename)

    with open(filepath, 'wb') as f:
        f.write(file_data)

    if is_temp and token and token in TEMP_TOKENS:
        TEMP_TOKENS[token]['uploaded_files'] += 1
        TEMP_TOKENS[token]['uploaded_bytes'] += file_size

    download_counts = get_download_counts()
    if filename not in download_counts:
        download_counts[filename] = 0
        save_download_counts(download_counts)

    return "File uploaded successfully"


@app.route('/upload-text', methods=['POST'])
def upload_text():
    if not session.get('authenticated', False) and not session.get('temp_access', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data         = request.get_json()
    text_content = data.get('text', '').strip()
    filename     = data.get('filename', '').strip()
    destination  = data.get('destination', 'Upload Folder')

    if not text_content:
        return jsonify({'success': False, 'message': 'No text provided'}), 400

    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'paste_{timestamp}.txt'
    else:
        if not filename.lower().endswith('.txt'):
            filename += '.txt'
        filename = secure_filename(filename)

    upload_dir = upload_folders.get(destination, PUBLIC_UPLOAD_DIR)
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(text_content)

    download_counts = get_download_counts()
    if filename not in download_counts:
        download_counts[filename] = 0
        save_download_counts(download_counts)

    return jsonify({'success': True, 'message': f'Text saved as {filename}'})


@app.route('/uploads/<path:filename>', methods=['GET'])
def get_file(filename):
    client_ip = request.remote_addr
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(ip_log_file, 'a', encoding='utf-8') as f:
        f.write(f"{filename},{client_ip},{request.headers.get('User-Agent', 'Unknown')},{timestamp}\n")
    download_counts = get_download_counts()
    download_counts[filename] = download_counts.get(filename, 0) + 1
    save_download_counts(download_counts)
    return send_from_directory(PUBLIC_UPLOAD_DIR, filename)


@app.route('/file-ips/<path:filename>', methods=['GET'])
def file_ips(filename):
    if not session.get('authenticated', False):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    try:
        downloads = get_file_download_ips(filename)
        return jsonify({'success': True, 'filename': filename,
                        'downloads': downloads, 'total': len(downloads)})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/delete/<path:filename>', methods=['POST'])
def delete_file(filename):
    if not session.get('authenticated', False):
        return "Unauthorized", 403
    file_path = os.path.join(PUBLIC_UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        download_counts = get_download_counts()
        if filename in download_counts:
            del download_counts[filename]
            save_download_counts(download_counts)
        return "File deleted successfully"
    return "File not found", 404


if __name__ == '__main__':
    print(f"\n🔑 Password reset link: http://localhost:8000/reset/{RESET_SECRET}\n")
    app.run(debug=True, host='0.0.0.0', port=8000)
