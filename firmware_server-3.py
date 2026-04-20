from flask import Flask, request, render_template, send_from_directory, session, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import os, json, re
from datetime import datetime, timedelta
import hashlib

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-to-random-string-12345'
app.permanent_session_lifetime = timedelta(hours=8)

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
FIRMWARE_DIR    = os.path.join(BASE_DIR, 'uploads', 'firmware')
os.makedirs(FIRMWARE_DIR, exist_ok=True)

# ── Projects ─────────────────────────────────────────────────────────────────
# Add more project names here as needed
PROJECTS = [
    'ESP_AP_CONTROL',
    'AIRSAAP_FLIGHT',
    'AIRSAAP_TELEMETRY',
]

ADMIN_PASSWORD_HASH = hashlib.sha256(b'13691113').hexdigest()  # change this

# ── Helpers ───────────────────────────────────────────────────────────────────

def get_project_dir(project):
    d = os.path.join(FIRMWARE_DIR, secure_filename(project))
    os.makedirs(d, exist_ok=True)
    return d

def version_txt_path(project):
    return os.path.join(get_project_dir(project), 'version.txt')

def get_current_version(project):
    p = version_txt_path(project)
    if os.path.exists(p):
        with open(p, 'r') as f:
            return f.read().strip()
    return None

def parse_version(v):
    """Parse 'V1.23' -> (1, 23) for comparison"""
    v = v.strip().lstrip('Vv')
    parts = v.replace('-','.').split('.')
    try:
        return tuple(int(x) for x in parts)
    except:
        return (0,)

def get_project_files(project):
    d = get_project_dir(project)
    files = []
    for f in os.listdir(d):
        fp = os.path.join(d, f)
        if os.path.isfile(fp) and f != 'version.txt':
            stat = os.stat(fp)
            files.append({
                'name': f,
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
            })
    files.sort(key=lambda x: x['modified'], reverse=True)
    return files

def format_size(b):
    for unit in ['B','KB','MB','GB']:
        if b < 1024.0:
            return f'{b:.1f} {unit}'
        b /= 1024.0
    return f'{b:.1f} TB'

def is_admin():
    return session.get('fw_admin', False)

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if not is_admin():
        return redirect(url_for('login_page'))
    projects_info = []
    for p in PROJECTS:
        ver = get_current_version(p)
        files = get_project_files(p)
        projects_info.append({
            'name': p,
            'version': ver or '(none)',
            'file_count': len(files),
            'files': files,
        })
    return render_template('firmware.html', projects=projects_info, admin=True)

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('firmware.html', projects=[], admin=False, login_page=True)

@app.route('/login', methods=['POST'])
def do_login():
    pw = request.form.get('password', '')
    if hashlib.sha256(pw.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
        session.permanent = True
        session['fw_admin'] = True
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Wrong password'}), 401

@app.route('/logout')
def logout():
    session.pop('fw_admin', None)
    return redirect(url_for('login_page'))

@app.route('/upload', methods=['POST'])
def upload_firmware():
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403

    project = request.form.get('project', '').strip()
    version = request.form.get('version', '').strip()

    if project not in PROJECTS:
        return jsonify({'success': False, 'message': 'Invalid project'}), 400
    if not version:
        return jsonify({'success': False, 'message': 'Version is required'}), 400
    if not re.match(r'^[Vv]?\d+(\.\d+)+$', version):
        return jsonify({'success': False, 'message': 'Invalid version format (e.g. V1.02)'}), 400
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file'}), 400

    f = request.files['file']
    if not f.filename.lower().endswith(('.bin', '.hex')):
        return jsonify({'success': False, 'message': 'Only .bin or .hex files allowed'}), 400

    # Normalise version to uppercase V
    version = 'V' + version.lstrip('Vv')
    filename = f'{project}_{version}{os.path.splitext(f.filename)[1].lower()}'
    dest = os.path.join(get_project_dir(project), filename)
    f.save(dest)

    # Update version.txt
    with open(version_txt_path(project), 'w') as vf:
        vf.write(version)

    return jsonify({'success': True, 'filename': filename, 'version': version})

@app.route('/delete/<project>/<filename>', methods=['POST'])
def delete_firmware(project, filename):
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    if project not in PROJECTS:
        return jsonify({'success': False, 'message': 'Bad project'}), 400
    fp = os.path.join(get_project_dir(project), secure_filename(filename))
    if os.path.exists(fp):
        os.remove(fp)
        # If deleted file matches current version.txt, clear it
        cur = get_current_version(project)
        if cur and cur in filename:
            # check if any remaining file carries this version
            remaining = [x for x in os.listdir(get_project_dir(project)) if cur in x]
            if not remaining:
                os.remove(version_txt_path(project))
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'File not found'}), 404

@app.route('/set-version/<project>', methods=['POST'])
def set_version(project):
    if not is_admin():
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    if project not in PROJECTS:
        return jsonify({'success': False, 'message': 'Bad project'}), 400
    data = request.get_json()
    version = data.get('version', '').strip()
    if not version:
        return jsonify({'success': False, 'message': 'Version required'}), 400
    version = 'V' + version.lstrip('Vv')
    with open(version_txt_path(project), 'w') as vf:
        vf.write(version)
    return jsonify({'success': True, 'version': version})

# ── ESP32 endpoints (called by ESP32 firmware) ────────────────────────────────

@app.route('/<project>/version.txt')
def esp_version(project):
    """ESP32 calls this to check latest version"""
    if project not in PROJECTS:
        return 'Not found', 404
    ver = get_current_version(project)
    if not ver:
        return 'No version', 404
    return ver, 200, {'Content-Type': 'text/plain'}

@app.route('/<project>/<filename>')
def esp_download(project, filename):
    """ESP32 calls this to download .bin"""
    if project not in PROJECTS:
        return 'Not found', 404
    d = get_project_dir(project)
    if not os.path.exists(os.path.join(d, filename)):
        return 'File not found', 404
    return send_from_directory(d, filename)

@app.route('/api/projects')
def api_projects():
    if not is_admin():
        return jsonify({'error': 'Unauthorized'}), 403
    result = []
    for p in PROJECTS:
        ver = get_current_version(p)
        files = get_project_files(p)
        for fi in files:
            fi['size_fmt'] = format_size(fi['size'])
        result.append({'name': p, 'version': ver or '', 'files': files})
    return jsonify(result)

if __name__ == '__main__':
    print('\n🚀 Firmware Update Server running on port 5001')
    print('🔑 Admin password: 13691113 (change ADMIN_PASSWORD_HASH)')
    print('📁 Projects:', ', '.join(PROJECTS))
    print()
    app.run(debug=True, host='0.0.0.0', port=5001)
