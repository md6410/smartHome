from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file
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
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

if not os.path.exists('uploads'):
    os.makedirs('uploads')
if not os.path.exists('static/avatars'):
    os.makedirs('static/avatars')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, max_http_buffer_size=50 * 1000 * 1000)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(255), default='default.png')
    notification_volume = db.Column(db.Float, default=0.5)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    msg_type = db.Column(db.String(20), default='text')
    file_path = db.Column(db.String(255))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    is_delivered = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

class ContactPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    contact_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    can_contact = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', foreign_keys=[user_id])
    contact = db.relationship('User', foreign_keys=[contact_id])

class Mute(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    muted_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    muted_group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', foreign_keys=[user_id])
    muted_user = db.relationship('User', foreign_keys=[muted_user_id])

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    avatar = db.Column(db.String(255), default='default_group.png')
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    creator = db.relationship('User', foreign_keys=[created_by])

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    group = db.relationship('Group', foreign_keys=[group_id])
    user = db.relationship('User', foreign_keys=[user_id])

class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    msg_type = db.Column(db.String(20), default='text')
    file_path = db.Column(db.String(255))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    group = db.relationship('Group', foreign_keys=[group_id])
    sender = db.relationship('User', foreign_keys=[sender_id])

class GroupMessageRead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('group_message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    read_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    message = db.relationship('GroupMessage', foreign_keys=[message_id])
    user = db.relationship('User', foreign_keys=[user_id])

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
    perm = ContactPermission.query.filter_by(user_id=user1_id, contact_id=user2_id).first()
    if perm:
        return perm.can_contact
    return True

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register')
def register():
    return "Registration disabled. Contact admin to create account.", 403

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember', False) == 'on'
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=remember, duration=timedelta(days=30))
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid username or password")
    
    return render_template('login.html')

@app.route('/admin/create-user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        return "Access Denied - Admin only", 403
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(is_admin=False).count() >= 50:
            return render_template('create_user.html', error="Maximum 50 users reached!")
        
        if User.query.filter_by(username=username).first():
            return render_template('create_user.html', error="Username already exists!")
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        
        return render_template('create_user.html', success=f"User '{username}' created successfully!")
    
    users_list = User.query.filter_by(is_admin=False).all()
    user_count = len(users_list)
    
    return render_template('create_user.html', users_list=users_list, user_count=user_count)

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        return "Cannot delete admin user", 403
    
    Message.query.filter((Message.sender_id == user_id) | (Message.receiver_id == user_id)).delete()
    ContactPermission.query.filter((ContactPermission.user_id == user_id) | (ContactPermission.contact_id == user_id)).delete()
    Mute.query.filter((Mute.user_id == user_id) | (Mute.muted_user_id == user_id)).delete()
    
    db.session.delete(user)
    db.session.commit()
    
    return redirect(url_for('create_user'))

@app.route('/admin/permissions/<int:user_id>', methods=['GET', 'POST'])
@login_required
def manage_permissions(user_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    
    user = User.query.get_or_404(user_id)
    all_users = User.query.filter(User.id != user_id, User.is_admin == False).all()
    
    if request.method == 'POST':
        ContactPermission.query.filter_by(user_id=user_id).delete()
        
        for other_user in all_users:
            can_contact_user = request.form.get(f'contact_{other_user.id}') == 'on'
            perm = ContactPermission(user_id=user_id, contact_id=other_user.id, can_contact=can_contact_user)
            db.session.add(perm)
        
        db.session.commit()
        return redirect(url_for('create_user'))
    
    permissions = {}
    for other_user in all_users:
        perm = ContactPermission.query.filter_by(user_id=user_id, contact_id=other_user.id).first()
        permissions[other_user.id] = perm.can_contact if perm else True
    
    return render_template('permissions.html', user=user, all_users=all_users, permissions=permissions)

@app.route('/dashboard')
@login_required
def dashboard():
    all_users = User.query.filter(User.id != current_user.id, User.is_admin == False).all()
    users = [u for u in all_users if can_contact(current_user.id, u.id)]
    
    chat_list = []
    for user in users:
        last_msg = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == user.id)) |
            ((Message.sender_id == user.id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()
        
        if last_msg:
            unread_count = Message.query.filter(
                Message.sender_id == user.id,
                Message.receiver_id == current_user.id,
                Message.is_read == False
            ).count()
            
            chat_list.append({
                'user': user,
                'last_message': last_msg.content if last_msg.msg_type == 'text' else f"📎 {last_msg.msg_type}",
                'timestamp': last_msg.timestamp,
                'unread_count': unread_count,
                'is_online': user.id in active_users
            })
    
    chat_list.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Get user's groups with last message and unread count
    my_groups = GroupMember.query.filter_by(user_id=current_user.id).all()
    groups_data = []
    for gm in my_groups:
        last_msg = GroupMessage.query.filter_by(group_id=gm.group_id).order_by(GroupMessage.timestamp.desc()).first()
        
        unread_count = 0
        if last_msg:
            all_group_msgs = GroupMessage.query.filter(
                GroupMessage.group_id == gm.group_id,
                GroupMessage.sender_id != current_user.id,
                GroupMessage.timestamp >= gm.joined_at
            ).all()
            
            for msg in all_group_msgs:
                is_read = GroupMessageRead.query.filter_by(
                    message_id=msg.id,
                    user_id=current_user.id
                ).first()
                if not is_read:
                    unread_count += 1
        
        if last_msg:
            if last_msg.msg_type == 'text':
                last_message_text = f"{last_msg.sender.username}: {last_msg.content[:30]}..." if len(last_msg.content) > 30 else f"{last_msg.sender.username}: {last_msg.content}"
            else:
                last_message_text = f"{last_msg.sender.username}: 📎 {last_msg.msg_type}"
        else:
            last_message_text = "No messages yet"
        
        groups_data.append({
            'group': gm.group,
            'last_message': last_message_text,
            'timestamp': last_msg.timestamp if last_msg else gm.joined_at,
            'unread_count': unread_count
        })
    
    groups_data.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('dashboard.html', users=users, chat_list=chat_list, active_users=active_users, groups=groups_data)

@app.route('/chat/<int:user_id>')
@login_required
def chat(user_id):
    other_user = User.query.get_or_404(user_id)
    
    if other_user.is_admin and not current_user.is_admin:
        return "Cannot chat with admin", 403
    
    if not can_contact(current_user.id, user_id):
        return "You don't have permission to contact this user", 403
    
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    Message.query.filter(
        Message.sender_id == user_id,
        Message.receiver_id == current_user.id,
        Message.is_read == False
    ).update({Message.is_read: True})
    db.session.commit()
    
    if user_id in active_users:
        socketio.emit('messages_read', {'reader_id': current_user.id}, room=active_users[user_id])
    
    is_muted = Mute.query.filter_by(user_id=current_user.id, muted_user_id=user_id).first() is not None
    
    return render_template('chat.html', other_user=other_user, messages=messages, active_users=active_users, is_muted=is_muted)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename:
                ext = file.filename.rsplit('.', 1)[1].lower()
                if ext in ['png', 'jpg', 'jpeg', 'gif']:
                    filename = f"user_{current_user.id}_{uuid.uuid4()}.{ext}"
                    file.save(os.path.join('static/avatars', filename))
                    
                    if current_user.profile_picture != 'default.png':
                        old_path = os.path.join('static/avatars', current_user.profile_picture)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    
                    current_user.profile_picture = filename
        
        volume = request.form.get('volume')
        if volume:
            current_user.notification_volume = float(volume)
        
        db.session.commit()
        return render_template('settings.html', success="Settings saved successfully!")
    
    return render_template('settings.html')

@app.route('/admin/create-group', methods=['GET', 'POST'])
@login_required
def create_group():
    if not current_user.is_admin:
        return "Access Denied", 403
    
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        selected_users = request.form.getlist('members')
        
        if not group_name:
            return render_template('create_group.html', error="Group name is required!")
        
        new_group = Group(name=group_name, created_by=current_user.id)
        db.session.add(new_group)
        db.session.commit()
        
        for user_id in selected_users:
            member = GroupMember(group_id=new_group.id, user_id=int(user_id))
            db.session.add(member)
        
        db.session.commit()
        return redirect(url_for('manage_groups'))
    
    users = User.query.filter_by(is_admin=False).all()
    return render_template('create_group.html', users=users)

@app.route('/admin/manage-groups')
@login_required
def manage_groups():
    if not current_user.is_admin:
        return "Access Denied", 403
    
    groups = Group.query.all()
    
    group_data = []
    for group in groups:
        member_count = GroupMember.query.filter_by(group_id=group.id).count()
        group_data.append({
            'group': group,
            'member_count': member_count
        })
    
    return render_template('manage_groups.html', group_data=group_data)

@app.route('/admin/delete-group/<int:group_id>', methods=['POST'])
@login_required
def delete_group(group_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    
    GroupMember.query.filter_by(group_id=group_id).delete()
    GroupMessage.query.filter_by(group_id=group_id).delete()
    GroupMessageRead.query.filter(GroupMessageRead.message_id.in_(
        db.session.query(GroupMessage.id).filter_by(group_id=group_id)
    )).delete(synchronize_session=False)
    Group.query.filter_by(id=group_id).delete()
    db.session.commit()
    
    return redirect(url_for('manage_groups'))

@app.route('/admin/edit-group/<int:group_id>', methods=['GET', 'POST'])
@login_required
def edit_group(group_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    
    group = Group.query.get_or_404(group_id)
    
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        if group_name:
            group.name = group_name
        
        if 'group_avatar' in request.files:
            file = request.files['group_avatar']
            if file and file.filename:
                ext = file.filename.rsplit('.', 1)[1].lower()
                if ext in ['png', 'jpg', 'jpeg', 'gif']:
                    filename = f"group_{group.id}_{uuid.uuid4()}.{ext}"
                    file.save(os.path.join('static/avatars', filename))
                    
                    if group.avatar != 'default_group.png':
                        old_path = os.path.join('static/avatars', group.avatar)
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    
                    group.avatar = filename
        
        db.session.commit()
        return redirect(url_for('manage_groups'))
    
    members = GroupMember.query.filter_by(group_id=group_id).all()
    all_users = User.query.filter_by(is_admin=False).all()
    
    return render_template('edit_group.html', group=group, members=members, all_users=all_users)

@app.route('/admin/add-group-member/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
def add_group_member(group_id, user_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    
    existing = GroupMember.query.filter_by(group_id=group_id, user_id=user_id).first()
    if not existing:
        member = GroupMember(group_id=group_id, user_id=user_id)
        db.session.add(member)
        db.session.commit()
    
    return redirect(url_for('edit_group', group_id=group_id))

@app.route('/admin/remove-group-member/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
def remove_group_member(group_id, user_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    
    GroupMember.query.filter_by(group_id=group_id, user_id=user_id).delete()
    db.session.commit()
    
    return redirect(url_for('edit_group', group_id=group_id))

@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
    group = Group.query.get_or_404(group_id)
    
    is_member = GroupMember.query.filter_by(group_id=group_id, user_id=current_user.id).first()
    if not is_member and not current_user.is_admin:
        return "You are not a member of this group", 403
    
    messages = GroupMessage.query.filter_by(group_id=group_id).order_by(GroupMessage.timestamp).all()
    members = GroupMember.query.filter_by(group_id=group_id).all()
    
    for msg in messages:
        if msg.sender_id != current_user.id:
            existing_read = GroupMessageRead.query.filter_by(
                message_id=msg.id,
                user_id=current_user.id
            ).first()
            if not existing_read:
                read_record = GroupMessageRead(message_id=msg.id, user_id=current_user.id)
                db.session.add(read_record)
    db.session.commit()
    
    is_muted = Mute.query.filter_by(user_id=current_user.id, muted_group_id=group_id).first() is not None
    
    return render_template('group_chat.html', group=group, messages=messages, members=members, is_muted=is_muted)

@app.route('/mute/<int:user_id>', methods=['POST'])
@login_required
def mute_user(user_id):
    existing = Mute.query.filter_by(user_id=current_user.id, muted_user_id=user_id).first()
    if not existing:
        mute = Mute(user_id=current_user.id, muted_user_id=user_id)
        db.session.add(mute)
        db.session.commit()
    return jsonify({'status': 'muted'})

@app.route('/unmute/<int:user_id>', methods=['POST'])
@login_required
def unmute_user(user_id):
    Mute.query.filter_by(user_id=current_user.id, muted_user_id=user_id).delete()
    db.session.commit()
    return jsonify({'status': 'unmuted'})

@app.route('/mute-group/<int:group_id>', methods=['POST'])
@login_required
def mute_group(group_id):
    existing = Mute.query.filter_by(user_id=current_user.id, muted_group_id=group_id).first()
    if not existing:
        mute = Mute(user_id=current_user.id, muted_group_id=group_id)
        db.session.add(mute)
        db.session.commit()
    return jsonify({'status': 'muted'})

@app.route('/unmute-group/<int:group_id>', methods=['POST'])
@login_required
def unmute_group(group_id):
    Mute.query.filter_by(user_id=current_user.id, muted_group_id=group_id).delete()
    db.session.commit()
    return jsonify({'status': 'unmuted'})

@app.route('/get-volume')
@login_required
def get_volume():
    return jsonify({'volume': current_user.notification_volume})

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "File not found", 404

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Socket.IO Events
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        active_users[current_user.id] = request.sid
        emit('user_online', {'user_id': current_user.id}, broadcast=True)
        print(f"{current_user.username} connected")

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated and current_user.id in active_users:
        del active_users[current_user.id]
        emit('user_offline', {'user_id': current_user.id}, broadcast=True)
        print(f"{current_user.username} disconnected")

@socketio.on('private_message')
def handle_private_message(data):
    receiver_id = data['receiver_id']
    message_text = data['message']
    
    is_delivered = receiver_id in active_users
    
    new_msg = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=message_text,
        msg_type='text',
        is_delivered=is_delivered
    )
    db.session.add(new_msg)
    db.session.commit()
    
    msg_data = {
        'msg_id': new_msg.id,
        'sender_id': current_user.id,
        'sender_name': current_user.username,
        'message': message_text,
        'msg_type': 'text',
        'is_delivered': is_delivered,
        'is_read': False,
        'timestamp': new_msg.timestamp.strftime('%H:%M')
    }
    
    if receiver_id in active_users:
        emit('new_message', msg_data, room=active_users[receiver_id])
    
    emit('message_sent', msg_data)

@socketio.on('file_upload')
def handle_file_upload(data):
    receiver_id = data['receiver_id']
    filename = data['filename']
    file_data = data['file']
    file_type = data['type']
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    
    unique_filename = f"{uuid.uuid4()}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    with open(file_path, 'wb') as f:
        f.write(base64.b64decode(file_data.split(',')[1]))
    
    is_delivered = receiver_id in active_users
    
    new_msg = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=filename,
        msg_type=file_type,
        file_path=unique_filename,
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
        'file_path': unique_filename,
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

@socketio.on('mark_read')
def handle_mark_read(data):
    msg_ids = data['msg_ids']
    sender_id = data['sender_id']
    
    Message.query.filter(Message.id.in_(msg_ids)).update({Message.is_read: True}, synchronize_session=False)
    db.session.commit()
    
    if sender_id in active_users:
        emit('messages_read', {'msg_ids': msg_ids, 'reader_id': current_user.id}, room=active_users[sender_id])

@socketio.on('group_message')
def handle_group_message(data):
    group_id = data['group_id']
    message_text = data['message']
    
    group = Group.query.get(group_id)
    
    new_msg = GroupMessage(
        group_id=group_id,
        sender_id=current_user.id,
        content=message_text,
        msg_type='text'
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
        'message': message_text,
        'msg_type': 'text',
        'timestamp': new_msg.timestamp.strftime('%H:%M')
    }
    
    members = GroupMember.query.filter_by(group_id=group_id).all()
    for member in members:
        if member.user_id in active_users and member.user_id != current_user.id:
            is_muted = Mute.query.filter_by(user_id=member.user_id, muted_group_id=group_id).first()
            if not is_muted:
                emit('new_group_message', msg_data, room=active_users[member.user_id])
    
    emit('group_message_sent', msg_data)

@socketio.on('group_file_upload')
def handle_group_file_upload(data):
    group_id = data['group_id']
    filename = data['filename']
    file_data = data['file']
    file_type = data['type']
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    
    group = Group.query.get(group_id)
    
    unique_filename = f"{uuid.uuid4()}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    with open(file_path, 'wb') as f:
        f.write(base64.b64decode(file_data.split(',')[1]))
    
    new_msg = GroupMessage(
        group_id=group_id,
        sender_id=current_user.id,
        content=filename,
        msg_type=file_type,
        file_path=unique_filename,
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

@socketio.on('mark_group_read')
def handle_mark_group_read(data):
    group_id = data['group_id']
    
    group_messages = GroupMessage.query.filter_by(group_id=group_id).all()
    
    for msg in group_messages:
        if msg.sender_id != current_user.id:
            existing = GroupMessageRead.query.filter_by(
                message_id=msg.id,
                user_id=current_user.id
            ).first()
            if not existing:
                read_record = GroupMessageRead(message_id=msg.id, user_id=current_user.id)
                db.session.add(read_record)
    
    db.session.commit()

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5554)
