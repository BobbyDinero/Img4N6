import os
import shutil
import time
import hashlib
from datetime import datetime
from werkzeug.utils import secure_filename


def allowed_file(filename, allowed_extensions):
    """Check if file has allowed extension"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def get_unique_filename(directory, filename):
    """Generate unique filename to avoid conflicts"""
    filename = secure_filename(filename)
    base_name, ext = os.path.splitext(filename)
    counter = 1

    while os.path.exists(os.path.join(directory, filename)):
        filename = f"{base_name}_{counter}{ext}"
        counter += 1

    return filename


def compute_file_hash(file_path, algorithm="sha256"):
    """Compute hash of file"""
    try:
        hash_func = getattr(hashlib, algorithm)()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        return f"Error computing {algorithm}: {e}"


def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1

    return f"{size_bytes:.1f} {size_names[i]}"


def safe_remove_directory(path):
    """Safely remove directory with error handling"""
    try:
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
            return True
    except Exception as e:
        print(f"Error removing directory {path}: {e}")
        return False


def create_directory_if_not_exists(path):
    """Create directory if it doesn't exist"""
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception as e:
        print(f"Error creating directory {path}: {e}")
        return False


def is_session_expired(session_data, timeout_hours=1):
    """Check if session has expired"""
    created_at = session_data.get("created_at", 0)
    current_time = time.time()
    return (current_time - created_at) > (timeout_hours * 3600)


def get_file_info(file_path):
    """Get basic file information"""
    try:
        stat = os.stat(file_path)
        return {
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "extension": os.path.splitext(file_path)[1].lower(),
        }
    except Exception as e:
        return {"error": str(e)}


class SessionManager:
    """Manages scan sessions"""

    def __init__(self):
        self.sessions = {}
        self.lock = None

    def create_session(self, session_id, temp_dir, file_count):
        """Create a new scan session"""
        session_data = {
            "created_at": time.time(),
            "status": "pending",
            "progress": 0,
            "current_file": None,
            "results": [],
            "temp_dir": temp_dir,
            "file_count": file_count,
            "error": None,
        }
        self.sessions[session_id] = session_data
        return session_data

    def get_session(self, session_id):
        """Get session data"""
        return self.sessions.get(session_id)

    def update_session(self, session_id, **kwargs):
        """Update session data"""
        if session_id in self.sessions:
            self.sessions[session_id].update(kwargs)

    def delete_session(self, session_id):
        """Delete session and cleanup files"""
        if session_id in self.sessions:
            session_data = self.sessions[session_id]
            temp_dir = session_data.get("temp_dir")

            if temp_dir:
                safe_remove_directory(temp_dir)

            del self.sessions[session_id]

    def cleanup_expired_sessions(self, timeout_hours=1):
        """Clean up expired sessions"""
        current_time = time.time()
        expired_sessions = []

        for session_id, session_data in self.sessions.items():
            if is_session_expired(session_data, timeout_hours):
                expired_sessions.append(session_id)

        for session_id in expired_sessions:
            self.delete_session(session_id)

        return len(expired_sessions)

    def get_session_count(self):
        """Get total number of active sessions"""
        return len(self.sessions)


def validate_api_key(api_key):
    """Basic validation for API keys"""
    if not api_key or not isinstance(api_key, str):
        return False

    # Basic length check (most API keys are at least 32 chars)
    if len(api_key.strip()) < 32:
        return False

    return True


def sanitize_filename_for_display(filename, max_length=50):
    """Sanitize filename for display purposes"""
    if len(filename) <= max_length:
        return filename

    name, ext = os.path.splitext(filename)
    truncated_name = name[: max_length - len(ext) - 3] + "..."
    return truncated_name + ext


def log_scan_event(event_type, session_id, filename=None, details=None):
    """Log scan events for debugging"""
    timestamp = datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "event_type": event_type,
        "session_id": session_id,
        "filename": filename,
        "details": details,
    }

    # In production, you might want to write to a proper log file
    print(f"[{timestamp}] {event_type}: {session_id} - {filename} - {details}")

    return log_entry
