"""Configuration for IMG4N6 - now actually imported and used by app.py."""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(24).hex())
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"  # off unless asked
    HOST = os.environ.get("IMG4N6_HOST", "127.0.0.1")
    PORT = int(os.environ.get("IMG4N6_PORT", "5000"))

    # Scan limits
    MAX_SCAN_DEPTH = int(os.environ.get("IMG4N6_MAX_DEPTH", "3"))
    MAX_FILES_PER_SCAN = int(os.environ.get("IMG4N6_MAX_FILES", "1000"))
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
    ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp",
                          ".tiff", ".tif", ".webp"}

    # Path safety (Windows-oriented; harmless on other platforms)
    ALLOWED_DRIVES = os.environ.get(
        "IMG4N6_ALLOWED_DRIVES", "C:,D:,E:,F:").split(",")
    BLOCKED_PATHS = [
        "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
        "C:\\System Volume Information", "C:\\$Recycle.Bin",
        "/etc", "/usr", "/bin", "/sbin", "/boot", "/proc", "/sys",
    ]

    # Workers / timeouts
    MAX_WORKER_THREADS = int(os.environ.get("IMG4N6_WORKERS", "4"))
    PER_FILE_TIMEOUT = 120          # seconds; enforced via futures (Windows-safe)
    VT_API_TIMEOUT = 15

    # Sessions
    SESSION_TTL_SECONDS = 3600      # in-memory sessions auto-purged after 1 h
    CLEANUP_INTERVAL = 300

    # Persistence
    YARA_RULES_PATH = os.path.join(BASE_DIR, "rules.yar")
    DB_PATH = os.environ.get("IMG4N6_DB",
                             os.path.join(BASE_DIR, "scan_history.db"))

    # Duplicate detection
    PHASH_NEAR_THRESHOLD = 6        # Hamming distance for "near duplicate"
