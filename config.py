import os
from datetime import timedelta


class Config:
    """Base configuration class"""

    # Flask settings
    SECRET_KEY = os.environ.get("SECRET_KEY") or "your-secret-key-change-in-production"

    # File upload settings
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB
    UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
    TEMP_FOLDER = os.path.join(os.getcwd(), "temp_sessions")

    # Allowed file extensions
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "tiff", "webp"}

    # Scanner settings
    YARA_RULES_PATH = "rules.yar"
    SESSION_TIMEOUT = timedelta(hours=1)  # Auto-cleanup after 1 hour
    CLEANUP_INTERVAL = 300  # Cleanup every 5 minutes

    # Analysis levels
    ANALYSIS_LEVELS = ["quick", "deep", "ultra"]
    DEFAULT_ANALYSIS_LEVEL = "quick"

    # VirusTotal settings
    VT_API_TIMEOUT = 30  # seconds
    VT_API_RETRIES = 3

    # Threading settings
    MAX_WORKER_THREADS = 4
    THREAD_TIMEOUT = 300  # 5 minutes per file max


class DevelopmentConfig(Config):
    """Development configuration"""

    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""

    DEBUG = False
    TESTING = False

    # Use environment variables for production
    SECRET_KEY = os.environ.get("SECRET_KEY") or "prod-secret-key-must-be-set"

    # Production paths
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER") or "/var/www/uploads"
    TEMP_FOLDER = os.environ.get("TEMP_FOLDER") or "/var/www/temp_sessions"


class TestingConfig(Config):
    """Testing configuration"""

    DEBUG = True
    TESTING = True
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB for testing


# Configuration mapping
config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
