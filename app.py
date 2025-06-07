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

        print(f"DEBUG: Original path: {folder_path}")
        print(f"DEBUG: Absolute path: {abs_path}")

        # Check if path exists
        if not os.path.exists(abs_path) or not os.path.isdir(abs_path):
            return False, "Path does not exist or is not a directory"

        # Check if on allowed drive - FIX THE DRIVE COMPARISON
        drive_letter = os.path.splitdrive(abs_path)[0]  # Just "C:" without backslash
        print(f"DEBUG: Detected drive: '{drive_letter}'")
        print(f"DEBUG: Allowed drives: {app.config['ALLOWED_DRIVES']}")

        if drive_letter not in app.config["ALLOWED_DRIVES"]:
            return False, f"Drive {drive_letter} not allowed for scanning"

        # Check against blocked paths
        for blocked in app.config["BLOCKED_PATHS"]:
            if abs_path.lower().startswith(blocked.lower()):
                return False, f"System directory {blocked} cannot be scanned"

        # RELAXED PATH LENGTH CHECK - was too restrictive
        if len(abs_path) < 3:  # Changed from 10 to 3 (just drive letter basically)
            return False, "Root directories cannot be scanned"

        return True, f"Path is safe to scan: {abs_path}"

    except Exception as e:
        print(f"DEBUG: Exception in path validation: {str(e)}")
        return False, f"Path validation error: {str(e)}"


def find_image_files_safely(folder_path, max_files=1000, max_depth=3):
    """Safely find image files with limits - DEBUG VERSION"""
    print(f"🔍 DEBUG: find_image_files_safely called")
    print(f"📂 DEBUG: folder_path: {folder_path}")
    print(f"📊 DEBUG: max_files: {max_files}, max_depth: {max_depth}")

    image_files = []
    allowed_extensions = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"}

    print(f"🎨 DEBUG: Allowed extensions: {allowed_extensions}")

    try:

        def scan_directory(path, current_depth=0):
            print(f"📁 DEBUG: Scanning directory: {path} (depth: {current_depth})")

            if current_depth > max_depth or len(image_files) >= max_files:
                print(
                    f"⚠️ DEBUG: Stopping scan - depth: {current_depth}, files found: {len(image_files)}"
                )
                return

            try:
                dir_contents = os.listdir(path)
                print(f"📄 DEBUG: Directory contains {len(dir_contents)} items")

                for item in dir_contents:
                    if len(image_files) >= max_files:
                        print(f"⚠️ DEBUG: Max files reached: {max_files}")
                        break

                    item_path = os.path.join(path, item)

                    # Skip hidden files and system files
                    if item.startswith(".") or item.startswith("$"):
                        continue

                    if os.path.isfile(item_path):
                        # Check file extension
                        ext = os.path.splitext(item.lower())[1]
                        print(f"📄 DEBUG: Checking file: {item} (ext: {ext})")

                        if ext in allowed_extensions:
                            print(f"✅ DEBUG: Valid image file: {item}")
                            # Additional safety: check file size
                            try:
                                size = os.path.getsize(item_path)
                                if 0 < size < 100 * 1024 * 1024:  # Between 0 and 100MB
                                    image_files.append(item_path)
                                    print(
                                        f"📸 DEBUG: Added to scan list: {item} ({size} bytes)"
                                    )
                                else:
                                    print(
                                        f"⚠️ DEBUG: File too large or empty: {item} ({size} bytes)"
                                    )
                            except Exception as e:
                                print(
                                    f"❌ DEBUG: Error checking file size for {item}: {e}"
                                )
                                continue  # Skip files we can't read

                    elif os.path.isdir(item_path) and current_depth < max_depth:
                        # Recursively scan subdirectories
                        print(f"📁 DEBUG: Found subdirectory: {item}")
                        scan_directory(item_path, current_depth + 1)

            except PermissionError as e:
                print(f"❌ DEBUG: Permission denied for {path}: {e}")
                pass  # Skip directories we can't access
            except Exception as e:
                print(f"❌ DEBUG: Error scanning {path}: {e}")
                pass  # Skip any problematic directories

        scan_directory(folder_path)

        print(f"🏁 DEBUG: File discovery completed")
        print(f"📊 DEBUG: Total image files found: {len(image_files)}")
        return image_files

    except Exception as e:
        print(f"❌ DEBUG: Exception in find_image_files_safely: {str(e)}")
        import traceback

        traceback.print_exc()
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
    """Scan file with timeout to prevent hanging - WITH AI DETECTION"""
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
            detect_ai_generated_content,  # *** CRITICAL IMPORT ***
        )

        print(f"🔍 DEBUG: Starting scan_with_timeout for {file_path}")
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # Basic analysis (always performed)
        threats = []
        warnings = []

        # *** AI DETECTION - THIS WAS MISSING! ***
        print(f"🤖 DEBUG: Starting AI detection for {filename}...")
        try:
            ai_findings, ai_probability = detect_ai_generated_content(file_path)
            print(
                f"✅ DEBUG: AI detection completed - Probability: {ai_probability:.3f}"
            )
            print(f"📋 DEBUG: AI findings: {ai_findings}")
        except Exception as ai_error:
            print(f"❌ DEBUG: AI detection failed: {str(ai_error)}")
            import traceback

            traceback.print_exc()
            ai_findings, ai_probability = [], 0.0

        try:
            # EXIF analysis
            print(f"📷 DEBUG: Extracting EXIF data...")
            exif_data = extract_exif_data(file_path)
            metadata_anomalies = analyze_metadata_anomalies(exif_data)
            for anomaly in metadata_anomalies:
                warnings.append(
                    {"type": "Metadata Anomaly", "description": anomaly, "level": "low"}
                )

            # YARA scanning (if rules exist)
            print(f"🔍 DEBUG: Running YARA scan...")
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
                print(f"🔬 DEBUG: Running deep/ultra analysis...")
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

            # *** MODERN THREATS DETECTION (if you have this function) ***
            try:
                from image_threat_scanner import detect_modern_threats

                modern_threats = detect_modern_threats(file_path)
                print(f"🌐 DEBUG: Modern threats found: {len(modern_threats)}")
            except ImportError:
                print(f"⚠️ DEBUG: detect_modern_threats function not found")
                modern_threats = []
            except Exception as e:
                print(f"❌ DEBUG: Modern threats detection failed: {e}")
                modern_threats = []

            # *** FILE STRUCTURE VALIDATION ***
            try:
                from image_threat_scanner import (
                    detect_polyglot_files,
                    validate_file_structure,
                )

                polyglot_findings = detect_polyglot_files(file_path)
                structure_findings = validate_file_structure(file_path)
                file_structure_issues = polyglot_findings + structure_findings
                print(f"🔗 DEBUG: File structure issues: {len(file_structure_issues)}")
            except ImportError:
                print(f"⚠️ DEBUG: File structure functions not found")
                file_structure_issues = []
            except Exception as e:
                print(f"❌ DEBUG: File structure analysis failed: {e}")
                file_structure_issues = []

            # *** TIMESTAMP ANALYSIS ***
            try:
                from image_threat_scanner import analyze_timestamp_anomalies

                timestamp_anomalies = analyze_timestamp_anomalies(file_path)
                print(f"⏰ DEBUG: Timestamp anomalies: {len(timestamp_anomalies)}")
            except ImportError:
                print(f"⚠️ DEBUG: analyze_timestamp_anomalies function not found")
                timestamp_anomalies = []
            except Exception as e:
                print(f"❌ DEBUG: Timestamp analysis failed: {e}")
                timestamp_anomalies = []

            # Determine status
            if threats:
                status = "threats"
            elif warnings:
                status = "warnings"
            else:
                status = "clean"

            # *** CREATE RESULT WITH ALL AI DATA ***
            result = {
                "filename": filename,
                "status": status,
                "file_size": file_size,
                "file_path": file_path,
                "timestamp": datetime.now().isoformat(),
                # *** AI DETECTION RESULTS ***
                "ai_probability": ai_probability,  # This was missing!
                "ai_indicators": [f.split("└─ ")[1] for f in ai_findings if "└─" in f],
                # *** MODERN THREATS ***
                "modern_threats": modern_threats,
                # *** FILE STRUCTURE ***
                "file_structure_issues": file_structure_issues,
                # *** TIMESTAMP ANOMALIES ***
                "timestamp_anomalies": timestamp_anomalies,
            }

            if threats:
                result["threats"] = threats
            if warnings:
                result["warnings"] = warnings
            if ai_findings:
                result["ai_findings"] = ai_findings

            print(f"✅ DEBUG: Scan complete for {filename}")
            print(f"📊 DEBUG: Final result AI probability: {ai_probability:.3f}")
            print(f"📊 DEBUG: Result keys: {list(result.keys())}")

            return result

        except Exception as scan_error:
            print(f"❌ DEBUG: Analysis error: {str(scan_error)}")
            import traceback

            traceback.print_exc()
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
    print(f"🚀 DEBUG: Background scan started")
    print(f"📁 DEBUG: Session ID: {session_id}")
    print(f"📂 DEBUG: Folder path: {folder_path}")
    print(f"📊 DEBUG: Analysis level: {analysis_level}")

    try:
        with session_lock:
            if session_id not in scan_sessions:
                print(f"❌ DEBUG: Session {session_id} not found in scan_sessions")
                return
            session = scan_sessions[session_id]
            session["status"] = "finding_files"
            print(f"✅ DEBUG: Session found and status set to finding_files")

        # Find image files safely
        print(f"🔍 DEBUG: Starting file discovery...")
        image_files = find_image_files_safely(
            folder_path, app.config["MAX_FILES_PER_SCAN"], app.config["MAX_SCAN_DEPTH"]
        )

        print(f"📸 DEBUG: Found {len(image_files)} image files")
        for i, file_path in enumerate(image_files[:5]):  # Show first 5 files
            print(f"  {i+1}. {file_path}")
        if len(image_files) > 5:
            print(f"  ... and {len(image_files) - 5} more files")

        if not image_files:
            print(f"⚠️ DEBUG: No image files found!")
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
                print(
                    f"📊 DEBUG: Session updated - status=scanning, file_count={len(image_files)}"
                )

        # Scan each file
        print(f"🔬 DEBUG: Starting individual file scans...")
        for i, file_path in enumerate(image_files):
            print(f"\n--- SCANNING FILE {i+1}/{len(image_files)} ---")
            print(f"📄 DEBUG: File: {file_path}")

            with session_lock:
                if session_id not in scan_sessions:
                    print(f"❌ DEBUG: Session {session_id} disappeared during scan")
                    break

                filename = os.path.basename(file_path)
                session["current_file"] = filename
                session["progress"] = int((i / len(image_files)) * 100)
                print(f"📈 DEBUG: Progress: {session['progress']}% - {filename}")

            # Scan individual file
            print(f"🔍 DEBUG: Calling scan_file_safely for {filename}...")
            result = scan_file_safely(
                file_path, analysis_level, vt_api_key, yara_rules_path
            )
            print(f"✅ DEBUG: Scan completed for {filename}")
            print(
                f"📊 DEBUG: Result keys: {list(result.keys()) if isinstance(result, dict) else 'Not a dict'}"
            )

            # Check if AI probability is in result
            if isinstance(result, dict):
                ai_prob = result.get("ai_probability", "MISSING")
                print(f"🤖 DEBUG: AI probability for {filename}: {ai_prob}")
                if "ai_probability" not in result:
                    print(f"⚠️ DEBUG: ai_probability key is missing from result!")

            with session_lock:
                if session_id in scan_sessions:
                    session["results"].append(result)
                    print(
                        f"📋 DEBUG: Result added to session. Total results: {len(session['results'])}"
                    )

        # Mark as completed
        print(f"✅ DEBUG: All files scanned, marking as completed")
        with session_lock:
            if session_id in scan_sessions:
                session["status"] = "completed"
                session["progress"] = 100
                session["current_file"] = None
                print(f"🏁 DEBUG: Background scan completed successfully")
                print(
                    f"📊 DEBUG: Final results count: {len(session.get('results', []))}"
                )

    except Exception as e:
        print(f"❌ DEBUG: Exception in background scan: {str(e)}")
        import traceback

        traceback.print_exc()

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

    app.run(debug=True, host="127.0.0.1", port=5000, threaded=True, use_reloader=True)
