
# Backup Manager

This project is a Flask-based Backup Manager that provides an interface for managing backups, 
including creating, restoring, and deleting backup files. The application supports multithreading 
to allow users to execute multiple actions in parallel (e.g., creating and deleting backups at the 
same time). The manager also supports user roles, allowing administrators to manage user accounts 
and backup configurations.

## Features

- **Create Backup**: Generate a compressed zip backup of specified directories with real-time progress tracking.
- **Instant Backup**: Backup a specific directory instantly with dynamic feedback on progress.
- **Restore Backup**: Restore backups with options for overwriting or cleaning existing files.
- **Delete Backup**: Delete selected backups without interrupting ongoing backup operations.
- **Automatic Backups**: Schedule backups through crontab with customizable days and times.
- **User Management**: Administrators can create, edit, and delete user accounts, including setting administrative privileges.
- **Profile Management**: All users can update their passwords, while only administrators can manage user roles.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/nemmusu/backup-manager.git
   cd backup-manager
   ```

2. **Install Dependencies**:
   It is recommended to use a virtual environment.
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Initialize the Database**:
   ```bash
   python script_db_init.py
   ```
   The script will prompt for an admin username and password.

4. **Run the Application**:
   ```bash
   flask run
   ```
   or with `SocketIO` support:
   ```bash
   python bm.py
   ```

5. **Access the Application**:
   Open a web browser and go to [http://127.0.0.1:5000](http://127.0.0.1:5000).

## Usage

### Creating a Backup
1. Navigate to the main dashboard.
2. Click the "Create Backup" button.
3. Track the backup progress via the progress bar.

### Deleting a Backup
1. Select backups to delete using the checkboxes next to each backup.
2. Click "Delete Selected" to remove them.
   - Note: Deletion actions do not interfere with ongoing backup processes.

### Restoring a Backup
1. Select a backup and choose the restore option (`Overwrite` or `Clean Restore`).
2. Monitor the progress to confirm the restore completes successfully.

### Setting up Automatic Backups
1. Go to the "Configure Automatic Backup" section.
2. Set times and days for scheduled backups and apply settings.

### User Management
1. Admin users can manage user roles and account settings via the "User Management" panel.
2. Standard users can change their passwords under the "Edit Profile" option.

## Requirements

- Python 3.7+
- Flask
- Flask-SocketIO
- Flask-SQLAlchemy
- Flask-Bcrypt
- Flask-Login

Install dependencies via `pip install -r requirements.txt`.

## Folder Structure

- `bm.py`: Main application file with routes and backup logic.
- `templates/`: Contains HTML templates for the Flask application.
- `script_db_init.py`: Initializes the database and creates an admin account.

## Notes

- Ensure `crontab` is available for setting automatic backups.
- All backups are saved in a directory named `backups` under the user’s home folder.


