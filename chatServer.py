from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import os
import base64
import uuid

app = Flask(__name__)
app.config["SECRET_KEY"] = "mysecretkey123"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///chat.db"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# SEPARATE FOLDERS FOR CHAT AND PUBLIC UPLOADS
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHAT_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads', 'chat')
PUBLIC_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads', 'public')

# Create folders
os.makedirs(CHAT_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PUBLIC_UPLOAD_FOLDER, exist_ok=True)
os.makedirs('static/avatars', exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, max_http_buffer_size=50 * 1000 * 1000)

# [ALL YOUR MODELS STAY THE SAME - no changes needed here]
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(255), default='default.png')
    notification_volume = db.Column(db.Float, default=0.5)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ... [keep all other models exactly the same] ...

with app.app_context():
    db.create_all()
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        hashed_pw = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin = User(username='admin', password=hashed_pw, is_admin=True)
        db.session.add(admin)
        db.session.commit()
        print("Default admin created! Username: admin, Password: admin123")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

active_users = {}

def can_contact(user1_id, user2_id):
    """Check if user1 can contact user2"""
    perm = ContactPermission.query.filter_by(user1_id=user1_id, user2_id=user2_id).first()
    if perm:
        return perm.can_contact
    return True

# [ALL ROUTES BEFORE file handlers stay the same...]

@app.route('/chat_files/<path:filename>')
@login_required
def chat_file(filename):
    """Serve chat files ONLY - separate from public uploads"""
    file_path = os.path.join(CHAT_UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        return send_from_directory(CHAT_UPLOAD_FOLDER, filename)
    return "File not found", 404

# [Keep all your existing routes exactly the same until file upload handlers...]

@socketio.on('file_upload')
def handle_file_upload(data):
    receiver_id = data['receiver_id']
    filename = data['filename']
    file_data = data['file']
    file_type = data['type']
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    
    # SAVE TO CHAT FOLDER - NOT PUBLIC UPLOADS
    unique_filename = f"chat_{uuid.uuid4()}_{filename}"
    file_path = os.path.join(CHAT_UPLOAD_FOLDER, unique_filename)
    
    with open(file_path, 'wb') as f:
        f.write(base64.b64decode(file_data.split(',')[1]))
    
    is_delivered = receiver_id in active_users
    
    new_msg = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=filename,
        msg_type=file_type,
        file_path=unique_filename,  # relative to chat folder
        latitude=latitude,
        longitude=longitude,
        is_delivered=is_delivered
    )
    db.session.add(new_msg)
    db.session.commit()
    
    msg_data = {
        'msg_id': new_msg.id,
        'sender_id': current_user.id,
        'sender_name': current_user.username,
        'message': filename,
        'msg_type': file_type,
        'file_path': unique_filename,  # for /chat_files/ route
        'file_url': f'/chat_files/{unique_filename}',  # NEW: chat-specific URL
        'file_data': file_data if file_type in ['image', 'voice'] else None,
        'latitude': latitude,
        'longitude': longitude,
        'is_delivered': is_delivered,
        'is_read': False,
        'timestamp': new_msg.timestamp.strftime('%H:%M')
    }
    
    if receiver_id in active_users:
        emit('new_message', msg_data, room=active_users[receiver_id])
    
    emit('message_sent', msg_data)

@socketio.on('group_file_upload')
def handle_group_file_upload(data):
    group_id = data['group_id']
    filename = data['filename']
    file_data = data['file']
    file_type = data['type']
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    
    group = Group.query.get(group_id)
    
    # SAVE TO CHAT FOLDER - NOT PUBLIC UPLOADS
    unique_filename = f"group_{group_id}_{uuid.uuid4()}_{filename}"
    file_path = os.path.join(CHAT_UPLOAD_FOLDER, unique_filename)
    
    with open(file_path, 'wb') as f:
        f.write(base64.b64decode(file_data.split(',')[1]))
    
    new_msg = GroupMessage(
        group_id=group_id,
        sender_id=current_user.id,
        content=filename,
        msg_type=file_type,
        file_path=unique_filename,  # relative to chat folder
        latitude=latitude,
        longitude=longitude
    )
    db.session.add(new_msg)
    db.session.commit()
    
    read_record = GroupMessageRead(message_id=new_msg.id, user_id=current_user.id)
    db.session.add(read_record)
    db.session.commit()
    
    msg_data = {
        'msg_id': new_msg.id,
        'group_id': group_id,
        'group_name': group.name,
        'sender_id': current_user.id,
        'sender_name': current_user.username,
        'sender_picture': current_user.profile_picture,
        'message': filename,
        'msg_type': file_type,
        'file_path': unique_filename,
        'file_url': f'/chat_files/{unique_filename}',  # NEW: chat-specific URL
        'file_data': file_data if file_type in ['image', 'voice'] else None,
        'latitude': latitude,
        'longitude': longitude,
        'timestamp': new_msg.timestamp.strftime('%H:%M')
    }
    
    members = GroupMember.query.filter_by(group_id=group_id).all()
    for member in members:
        if member.user_id in active_users and member.user_id != current_user.id:
            is_muted = Mute.query.filter_by(user_id=member.user_id, muted_group_id=group_id).first()
            if not is_muted:
                emit('new_group_message', msg_data, room=active_users[member.user_id])
    
    emit('group_message_sent', msg_data)

# [Keep all other routes and socket events exactly the same...]

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5554)
