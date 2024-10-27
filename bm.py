import os
import sys
import json
import subprocess
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_socketio import SocketIO
from datetime import datetime
import threading
import zipfile
import shutil
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, async_mode='threading')

USER_HOME = os.path.expanduser("~")
BACKUP_DIR = os.path.join(USER_HOME, "backups")
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backup_config.json")


active_processes = {}  
current_progress = {}  


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  

    def __init__(self, username, password, is_admin=False):
        self.username = username
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.is_admin = is_admin

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    
    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    else:
        config = {"directories": []}
        save_config(config)
    return config


def save_config(config):
    config_dir = os.path.dirname(CONFIG_FILE)
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)


def count_files(directories):
    total_files = 0
    for directory in directories:
        for root, dirs, files in os.walk(directory):
            total_files += len(files)
    return total_files


def count_files_in_zip(zip_path):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        return len(zip_ref.namelist())


def execute_backup(zip_path, directories):
    thread_id = threading.get_ident()
    current_progress[thread_id] = 0

    try:
        total_files = count_files(directories)
        processed_files = 0
        command = ['zip', '-r', zip_path] + directories
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        active_processes[thread_id] = process

        for line in process.stdout:
            if line.startswith("  adding:"):
                processed_files += 1
                progress = (processed_files / total_files) * 100 if total_files > 0 else 100
                current_progress[thread_id] = min(progress, 100)
                socketio.emit('progress_update', {'progress': current_progress[thread_id]})

        process.wait()
    except Exception as e:
        safe_error = escape(str(e))
        socketio.emit('progress_update', {'output': f'Error during backup: {safe_error}', 'progress': current_progress[thread_id]})
    finally:
        active_processes.pop(thread_id, None)
        current_progress.pop(thread_id, None)

    socketio.emit('progress_update', {'progress': 100, 'output': 'Backup completed successfully!'})


def execute_instant_backup(zip_path, folder_path):
    thread_id = threading.get_ident()
    current_progress[thread_id] = 0

    try:
        if not os.path.exists(folder_path):
            safe_folder_path = escape(folder_path)
            socketio.emit('progress_update', {'output': f'Folder "{safe_folder_path}" does not exist.', 'progress': 0})
            return

        total_files = count_files([folder_path])
        processed_files = 0

        command = ['zip', '-r', zip_path, folder_path]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        active_processes[thread_id] = process

        for line in process.stdout:
            if line.startswith("  adding:"):
                processed_files += 1
                progress = (processed_files / total_files) * 100 if total_files > 0 else 100
                current_progress[thread_id] = min(progress, 100)
                socketio.emit('progress_update', {'progress': current_progress[thread_id]})

        process.wait()
    except Exception as e:
        safe_error = escape(str(e))
        socketio.emit('progress_update', {'output': f'Error during instant backup: {safe_error}', 'progress': current_progress[thread_id]})
    finally:
        active_processes.pop(thread_id, None)
        current_progress.pop(thread_id, None)

    socketio.emit('progress_update', {'progress': 100, 'output': 'Instant backup completed successfully!'})


@app.route('/delete_backups', methods=['POST'])
@login_required
def delete_backups_route():
    backup_names = request.json.get('backup_names', [])

    if not backup_names:
        return jsonify({'success': False, 'message': 'No backups selected.'}), 400

    for backup_name in backup_names:
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        metadata_path = backup_path.replace(".zip", ".json")

        try:
            if os.path.exists(backup_path):
                os.remove(backup_path)
            if os.path.exists(metadata_path):
                os.remove(metadata_path)
        except Exception as e:
            safe_error = escape(str(e))
            print(f"Error deleting {backup_name}: {safe_error}")

    return jsonify({'success': True, 'message': 'Backups deleted successfully!'})

@app.route('/cancel_backup', methods=['POST'])
@login_required
def cancel_backup():
    thread_id = threading.get_ident()
    process = active_processes.get(thread_id)

    if process:
        process.terminate()
        active_processes.pop(thread_id, None)
        current_progress[thread_id] = 0
        socketio.emit('progress_update', {'output': 'Operation canceled.', 'progress': 0})

    return jsonify({'success': True})


def execute_restore(zip_path, action):
    thread_id = threading.get_ident()
    current_progress[thread_id] = 0

    try:
        total_files = count_files_in_zip(zip_path)
        processed_files = 0

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            all_members = zip_ref.infolist()

            if action == 'clean_restore':
                metadata_file = zip_path.replace(".zip", ".json")
                if os.path.exists(metadata_file):
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        backed_up_dirs = metadata.get("directories", [])
                else:
                    backed_up_dirs = list(set(member.filename.split('/')[0] for member in all_members if '/' in member.filename))

                excluded_dirs = [BACKUP_DIR.rstrip('/')]
                excluded_dirs = [os.path.abspath(d) for d in excluded_dirs]

                for dir_to_remove in backed_up_dirs:
                    if not os.path.isabs(dir_to_remove):
                        dir_to_remove = os.path.join('/', dir_to_remove)
                    target_path = os.path.normpath(dir_to_remove)
                    if any(target_path == ed or target_path.startswith(ed + os.sep) for ed in excluded_dirs):
                        print(f"Skipped deletion of {target_path}")
                        continue
                    if os.path.exists(target_path):
                        try:
                            if os.path.isdir(target_path):
                                shutil.rmtree(target_path)
                            else:
                                os.remove(target_path)
                        except Exception as e:
                            safe_error = escape(str(e))
                            print(f"Error deleting {target_path}: {safe_error}")

            for member in all_members:
                zip_ref.extract(member, '/')
                processed_files += 1
                progress = (processed_files / total_files) * 100 if total_files > 0 else 100
                current_progress[thread_id] = min(progress, 100)
                socketio.emit('progress_update', {'progress': current_progress[thread_id]})

    except Exception as e:
        safe_error = escape(str(e))
        socketio.emit('progress_update', {'output': f'Error during restore: {safe_error}', 'progress': current_progress[thread_id]})
    finally:
        current_progress.pop(thread_id, None)

    socketio.emit('progress_update', {'progress': 100, 'output': 'Restore completed successfully!'})


def get_crontab():
    result = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        return ''
    return result.stdout

def parse_crontab():
    crontab_content = get_crontab()
    lines = crontab_content.splitlines()
    backup_entries = []
    for line in lines:
        if '--auto-backup' in line:
            parts = line.strip().split()
            if len(parts) < 6:
                continue  
            schedule_parts = parts[:5]
            schedule = ' '.join(schedule_parts)
            python_command = ' '.join(parts[5:])
            backup_entries.append({'schedule': schedule, 'command': python_command, 'line': line})
    return backup_entries


@app.route('/get_crontab', methods=['GET'])
@login_required
def get_crontab_schedules():
    backup_entries = parse_crontab()
    schedules = []
    for entry in backup_entries:
        parts = entry['schedule'].split()
        if len(parts) < 5:
            continue  
        minute, hour, _, _, days = parts
        days_list = days.split(',') if days != '*' else ['0', '1', '2', '3', '4', '5', '6']
        schedules.append({
            'minute': escape(minute),
            'hour': escape(hour),
            'days': [escape(day) for day in days_list],
            'line': escape(entry['line'])
        })
    return jsonify({'schedules': schedules})

@app.route('/update_directories', methods=['POST'])
@login_required
def update_directories():
    directories = request.json.get('directories', [])
    valid_directories = [d for d in directories if os.path.isabs(d) and os.path.exists(d)]

    
    config = {"directories": valid_directories}
    save_config(config)
    return jsonify({'success': True, 'message': 'Backup directories updated successfully.'})

@app.route('/create_backup', methods=['POST'])
@login_required
def create_backup_route():
    config = load_config()
    directories = config['directories']

    if not directories:
        return jsonify({'success': False, 'message': 'No directories selected for backup.'}), 400

    date_str = datetime.now().strftime("%d.%m.%Y-%H.%M-server-backup")
    zip_name = f"{date_str}.zip"
    zip_path = os.path.join(BACKUP_DIR, zip_name)

    metadata = {
        "date": datetime.now().strftime("%d-%m-%Y %H:%M"),
        "directories": directories
    }
    metadata_file = zip_path.replace(".zip", ".json")
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f)

    backup_thread = threading.Thread(target=execute_backup, args=(zip_path, directories))
    backup_thread.start()

    return jsonify({'success': True})


@app.route('/status', methods=['GET'])
@login_required
def get_status():
    thread_id = threading.get_ident()
    operation = 'in_progress' if thread_id in active_processes else None
    progress = current_progress.get(thread_id, 0)
    return jsonify({'operation': operation, 'progress': progress})

@app.route('/instant_backup', methods=['POST'])
@login_required
def instant_backup_route():
    data = request.json
    folder_path = data.get('folder_path')

    if not folder_path:
        return jsonify({'success': False, 'message': 'Folder path missing.'}), 400

    if not os.path.isabs(folder_path):
        return jsonify({'success': False, 'message': 'Please enter a valid absolute path.'}), 400

    if not os.path.exists(folder_path):
        return jsonify({'success': False, 'message': f'The folder "{folder_path}" does not exist.'}), 400

    
    date_str = datetime.now().strftime("%d.%m.%Y-%H.%M-instant-backup")
    folder_name = os.path.basename(os.path.normpath(folder_path))
    zip_name = f"{date_str}-{folder_name}.zip"
    zip_path = os.path.join(BACKUP_DIR, zip_name)

    
    metadata = {
        "date": datetime.now().strftime("%d-%m-%Y %H:%M"),
        "directories": [folder_path]
    }
    metadata_file = zip_path.replace(".zip", ".json")
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f)

    
    try:
        instant_backup_thread = threading.Thread(target=execute_instant_backup, args=(zip_path, folder_path))
        instant_backup_thread.start()
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error starting instant backup: {str(e)}'}), 500

    return jsonify({'success': True, 'message': 'Instant backup started.'})


@app.route('/restore_backup', methods=['POST'])
@login_required
def restore_backup_route():
    backup_name = request.form.get('backup_name', '')
    action = request.form.get('action', '')
    backup_name = escape(backup_name)
    action = escape(action)

    backup_path = os.path.join(BACKUP_DIR, backup_name)

    if not os.path.exists(backup_path):
        return jsonify({'success': False, 'message': 'The selected backup does not exist.'}), 400

    if action not in ['overwrite', 'clean_restore']:
        return jsonify({'success': False, 'message': 'Invalid restore action.'}), 400

    restore_thread = threading.Thread(target=execute_restore, args=(backup_path, action))
    restore_thread.start()

    return jsonify({'success': True})

def remove_crontab_entries(entries_to_remove):
    current_crontab = get_crontab()

    
    new_crontab_lines = [line for line in current_crontab.splitlines() if line not in entries_to_remove]
    new_crontab = "\n".join(new_crontab_lines) + "\n"

    
    process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
    process.communicate(new_crontab)

def set_crontab(cron_entries):
    python_executable = sys.executable  
    script_path = os.path.abspath(__file__)  

    cron_commands = []
    for entry in cron_entries:
        schedule = entry['schedule']
        cron_command = f"{schedule} {python_executable} {script_path} --auto-backup\n"
        cron_commands.append(cron_command)

    
    current_crontab = get_crontab()

    
    new_crontab_lines = current_crontab.splitlines()
    new_crontab_lines.extend(cron_commands)

    
    new_crontab = "\n".join(new_crontab_lines) + "\n"
    process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
    process.communicate(new_crontab)


def get_backups():
    backups = []
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    for filename in os.listdir(BACKUP_DIR):
        if filename.endswith(".zip"):
            file_path = os.path.join(BACKUP_DIR, filename)
            creation_time = os.path.getmtime(file_path)
            backup = {
                "name": escape(filename),
                "date": datetime.fromtimestamp(creation_time).strftime("%d-%m-%Y %H:%M"),
                "directories": []
            }
            metadata_file = file_path.replace(".zip", ".json")
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    try:
                        metadata = json.load(f)
                        dirs = metadata.get("directories", [])
                        backup["directories"] = [escape(d) for d in dirs]
                    except json.JSONDecodeError:
                        backup["directories"] = []
            backups.append(backup)
    backups.sort(key=lambda x: os.path.getmtime(os.path.join(BACKUP_DIR, x["name"])), reverse=True)
    return backups


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/user_management', methods=['GET', 'POST'])
@login_required
def user_management():
    if not current_user.is_admin:
        flash('Access denied: insufficient permissions.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
        else:
            new_user = User(username=username, password=password, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            flash(f'User {username} created successfully!', 'success')

    users = User.query.all()
    return render_template('user_management.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Access denied: insufficient permissions.', 'danger')
        return redirect(url_for('user_management'))

    user = User.query.get_or_404(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.username} deleted.', 'success')

    return redirect(url_for('user_management'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if current_user.id != user.id and not current_user.is_admin:
        flash('Access denied: insufficient permissions.', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        if current_user.is_admin or current_user.id == user.id:
            user.username = request.form.get('username')
            password = request.form.get('password')
            if password:
                user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

            if current_user.is_admin:
                is_admin = request.form.get('is_admin') == 'on'
                user.is_admin = is_admin

            db.session.commit()
            flash(f'User {user.username} updated successfully!', 'success')
            if current_user.is_admin:
                return redirect(url_for('user_management'))
            else:
                return redirect(url_for('index'))
        else:
            flash('Access denied: insufficient permissions.', 'danger')
            return redirect(url_for('index'))

    return render_template('edit_user.html', user=user)

@app.route('/remove_crontab_entries', methods=['POST'])
@login_required
def remove_crontab_entries_route():
    entries_to_remove = request.json.get('entries', [])
    if not entries_to_remove:
        return jsonify({'success': False, 'message': 'No schedules selected.'}), 400

    try:
        remove_crontab_entries(entries_to_remove)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/set_crontab', methods=['POST'])
@login_required
def set_crontab_schedule():
    data = request.json
    times = data.get('times')
    days = data.get('days')

    if not times or not days:
        return jsonify({'success': False, 'message': 'Missing parameters'}), 400

    cron_entries = []
    for time in times:
        hour = escape(time.get('hour', '0'))
        minute = escape(time.get('minute', '0'))
        day_field = ','.join([escape(day) for day in days]) if len(days) < 7 else '*'
        schedule = f"{minute} {hour} * * {day_field}"
        cron_entries.append({'schedule': schedule})

    try:
        set_crontab(cron_entries)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/')
@login_required
def index():
    config = load_config()
    backups = get_backups()
    return render_template('index.html', backups=backups, directories=config['directories'])

if __name__ == '__main__':
    if '--auto-backup' in sys.argv:
        config = load_config()
        directories = config['directories']
        if not directories:
            print("No directories selected for backup.")
            sys.exit(1)
        date_str = datetime.now().strftime("%d.%m.%Y-%H.%M-server-backup")
        zip_name = f"{date_str}.zip"
        zip_path = os.path.join(BACKUP_DIR, zip_name)

        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)

        subprocess.run(['zip', '-r', zip_path] + directories)

        metadata = {
            "date": datetime.now().strftime("%d-%m-%Y %H:%M"),
            "directories": directories
        }
        metadata_file = zip_path.replace(".zip", ".json")
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f)
    else:
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
        socketio.run(app, host='127.0.0.1', port=5000)
