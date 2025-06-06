import os
import uuid
import json
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify
import tempfile
import subprocess
import sys

# Create Flask application instance
app = Flask(__name__)

# Configuration for safe scanning
app.config["MAX_SCAN_DEPTH"] = 3  # Maximum folder depth to scan
app.config["MAX_FILES_PER_SCAN"] = 1000  # Limit files per scan session
app.config["ALLOWED_DRIVES"] = ["C:", "D:", "E:"]  # Restrict to specific drives
app.config["BLOCKED_PATHS"] = [  # Block system directories
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\System Volume Information",
]

# Global storage for scan sessions (no file storage)
scan_sessions = {}
session_lock = threading.Lock()


def is_safe_path(folder_path):
    """Validate that the path is safe to scan"""
    try:
        # Convert to absolute path
        abs_path = os.path.abspath(folder_path)

        # Check if path exists
        if not os.path.exists(abs_path) or not os.path.isdir(abs_path):
            return False, "Path does not exist or is not a directory"

        # Check if on allowed drive
        drive = os.path.splitdrive(abs_path)[0] + "\\"
        if drive not in app.config["ALLOWED_DRIVES"]:
            return False, f"Drive {drive} not allowed for scanning"

        # Check against blocked paths
        for blocked in app.config["BLOCKED_PATHS"]:
            if abs_path.lower().startswith(blocked.lower()):
                return False, f"System directory {blocked} cannot be scanned"

        # Additional safety checks
        if len(abs_path) < 10:  # Too short, likely root directory
            return False, "Root directories cannot be scanned"

        return True, "Path is safe"

    except Exception as e:
        return False, f"Path validation error: {str(e)}"


def find_image_files_safely(folder_path, max_files=1000, max_depth=3):
    """Safely find image files with limits"""
    image_files = []
    allowed_extensions = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"}

    try:

        def scan_directory(path, current_depth=0):
            if current_depth > max_depth or len(image_files) >= max_files:
                return

            try:
                for item in os.listdir(path):
                    if len(image_files) >= max_files:
                        break

                    item_path = os.path.join(path, item)

                    # Skip hidden files and system files
                    if item.startswith(".") or item.startswith("$"):
                        continue

                    if os.path.isfile(item_path):
                        # Check file extension
                        ext = os.path.splitext(item.lower())[1]
                        if ext in allowed_extensions:
                            # Additional safety: check file size
                            try:
                                size = os.path.getsize(item_path)
                                if 0 < size < 100 * 1024 * 1024:  # Between 0 and 100MB
                                    image_files.append(item_path)
                            except:
                                continue  # Skip files we can't read

                    elif os.path.isdir(item_path) and current_depth < max_depth:
                        # Recursively scan subdirectories
                        scan_directory(item_path, current_depth + 1)

            except PermissionError:
                pass  # Skip directories we can't access
            except Exception:
                pass  # Skip any problematic directories

        scan_directory(folder_path)
        return image_files

    except Exception as e:
        return []


def scan_file_safely(file_path, analysis_level, vt_api_key, yara_rules_path):
    """Scan file with additional safety measures"""
    try:
        # Import scanner in isolated way
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from image_threat_scanner import (
            extract_exif_data,
            compute_sha256,
            detect_data_anomalies,
            detect_lsb_steganography,
            scan_with_yara,
        )

        # Pre-flight safety checks
        if not os.path.exists(file_path):
            return create_error_result(file_path, "File not found")

        # Check file size (avoid extremely large files)
        file_size = os.path.getsize(file_path)
        if file_size > 100 * 1024 * 1024:  # 100MB limit
            return create_error_result(file_path, "File too large for safe scanning")

        if file_size == 0:
            return create_error_result(file_path, "Empty file")

        # Perform scanning with timeout protection
        result = scan_with_timeout(
            file_path, analysis_level, vt_api_key, yara_rules_path
        )
        return result

    except Exception as e:
        return create_error_result(file_path, f"Scan error: {str(e)}")


def scan_with_timeout(
    file_path, analysis_level, vt_api_key, yara_rules_path, timeout=300
):
    """Scan file with timeout to prevent hanging"""
    import signal

    def timeout_handler(signum, frame):
        raise TimeoutError("Scan timeout exceeded")

    try:
        # Set timeout (5 minutes max per file)
        if hasattr(signal, "SIGALRM"):  # Unix-like systems
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)

        # Perform the actual scan
        from image_threat_scanner import (
            extract_exif_data,
            compute_sha256,
            detect_data_anomalies,
            detect_lsb_steganography,
            scan_with_yara,
            analyze_metadata_anomalies,
        )

        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Basic analysis (always performed)
        threats = []
        warnings = []

        try:
            # EXIF analysis
            exif_data = extract_exif_data(file_path)
            metadata_anomalies = analyze_metadata_anomalies(exif_data)
            for anomaly in metadata_anomalies:
                warnings.append(
                    {"type": "Metadata Anomaly", "description": anomaly, "level": "low"}
                )

            # YARA scanning (if rules exist)
            if os.path.exists(yara_rules_path):
                yara_hits = scan_with_yara(file_path, yara_rules_path)
                for hit in yara_hits:
                    if "error" not in hit.lower():
                        threats.append(
                            {
                                "type": "YARA Detection",
                                "description": hit,
                                "level": "high",
                            }
                        )

            # Additional analysis based on level
            if analysis_level in ["deep", "ultra"]:
                # Statistical analysis
                stat_anomalies = detect_data_anomalies(file_path)
                for anomaly in stat_anomalies:
                    warnings.append(
                        {
                            "type": "Statistical Anomaly",
                            "description": anomaly,
                            "level": "medium",
                        }
                    )

                # LSB steganography detection
                lsb_findings = detect_lsb_steganography(file_path)
                for finding in lsb_findings:
                    threats.append(
                        {
                            "type": "LSB Steganography",
                            "description": finding,
                            "level": "high",
                        }
                    )

            # Determine status
            if threats:
                status = "threats"
            elif warnings:
                status = "warnings"
            else:
                status = "clean"

            result = {
                "filename": filename,
                "status": status,
                "file_size": file_size,
                "file_path": file_path,  # Include path for reference
                "timestamp": datetime.now().isoformat(),
            }

            if threats:
                result["threats"] = threats
            if warnings:
                result["warnings"] = warnings

            return result

        except Exception as scan_error:
            return create_error_result(file_path, f"Analysis error: {str(scan_error)}")

    except TimeoutError:
        return create_error_result(
            file_path, "Scan timeout - file may be corrupted or too complex"
        )

    finally:
        # Clear timeout
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)


def create_error_result(file_path, error_message):
    """Create standardized error result"""
    return {
        "filename": os.path.basename(file_path),
        "status": "error",
        "error": error_message,
        "file_path": file_path,
        "timestamp": datetime.now().isoformat(),
    }


def scan_files_background_safe(
    session_id, folder_path, analysis_level, vt_api_key, yara_rules_path
):
    """Background task to scan files safely in-place"""
    try:
        with session_lock:
            if session_id not in scan_sessions:
                return
            session = scan_sessions[session_id]
            session["status"] = "finding_files"

        # Find image files safely
        image_files = find_image_files_safely(
            folder_path, app.config["MAX_FILES_PER_SCAN"], app.config["MAX_SCAN_DEPTH"]
        )

        if not image_files:
            with session_lock:
                if session_id in scan_sessions:
                    session["status"] = "completed"
                    session["error"] = "No image files found in specified location"
            return

        with session_lock:
            if session_id in scan_sessions:
                session["status"] = "scanning"
                session["file_count"] = len(image_files)
                session["progress"] = 0

        # Scan each file
        for i, file_path in enumerate(image_files):
            with session_lock:
                if session_id not in scan_sessions:
                    break

                filename = os.path.basename(file_path)
                session["current_file"] = filename
                session["progress"] = int((i / len(image_files)) * 100)

            # Scan individual file
            result = scan_file_safely(
                file_path, analysis_level, vt_api_key, yara_rules_path
            )

            with session_lock:
                if session_id in scan_sessions:
                    session["results"].append(result)

        # Mark as completed
        with session_lock:
            if session_id in scan_sessions:
                session["status"] = "completed"
                session["progress"] = 100
                session["current_file"] = None

    except Exception as e:
        with session_lock:
            if session_id in scan_sessions:
                session["status"] = "error"
                session["error"] = str(e)


# Routes
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan-folder", methods=["POST"])
def scan_folder_safely():
    """Scan files directly from folder path - SAFE VERSION"""
    try:
        data = request.get_json()
        folder_path = data.get("folder_path", "").strip()
        analysis_level = data.get("analysis_level", "quick")
        vt_api_key = data.get("vt_api_key", "").strip()

        # Validate folder path for safety
        is_safe, safety_message = is_safe_path(folder_path)
        if not is_safe:
            return jsonify({"error": f"Unsafe path: {safety_message}"}), 400

        # Validate analysis level
        if analysis_level not in ["quick", "deep", "ultra"]:
            analysis_level = "quick"

        # Create session
        session_id = str(uuid.uuid4())
        yara_rules_path = "rules.yar"

        with session_lock:
            scan_sessions[session_id] = {
                "created_at": time.time(),
                "status": "pending",
                "progress": 0,
                "current_file": None,
                "results": [],
                "folder_path": folder_path,
                "scan_type": "in_place_safe",
            }

        # Start background scanning
        thread = threading.Thread(
            target=scan_files_background_safe,
            args=(session_id, folder_path, analysis_level, vt_api_key, yara_rules_path),
        )
        thread.daemon = True
        thread.start()

        return jsonify(
            {
                "session_id": session_id,
                "analysis_level": analysis_level,
                "scan_type": "in_place_safe",
                "folder_path": folder_path,
                "safety_message": safety_message,
            }
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/status/<session_id>", methods=["GET"])
def get_scan_status(session_id):
    """Get scan status and results"""
    with session_lock:
        if session_id not in scan_sessions:
            return jsonify({"error": "Session not found"}), 404

        session = scan_sessions[session_id].copy()

    return jsonify(session)


@app.route("/api/validate-path", methods=["POST"])
def validate_scan_path():
    """Validate if a path is safe for scanning"""
    try:
        data = request.get_json()
        folder_path = data.get("folder_path", "").strip()

        is_safe, message = is_safe_path(folder_path)

        return jsonify({"is_safe": is_safe, "message": message, "path": folder_path})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("🔒 Starting SAFE In-Place Image Scanner")
    print("=" * 50)
    print("• Files are scanned in their original location")
    print("• No files are copied or moved to this server")
    print("• System directories are blocked for safety")
    print("• File size and count limits enforced")
    print("=" * 50)

    app.run(debug=True, host="127.0.0.1", port=5000, threaded=True)
