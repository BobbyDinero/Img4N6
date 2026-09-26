"""
IMG4N6 backend (v2)
===================
- Parallel scanning via ThreadPoolExecutor (uses Config.MAX_WORKER_THREADS)
- Per-file timeout via concurrent.futures (works on Windows; v1's SIGALRM
  approach silently did nothing there and crashed in threads on Linux)
- YARA rules compiled ONCE at startup
- Each file read from disk ONCE; bytes handed to the scanner
- SQLite result cache (sha256+level) -> instant rescans of unchanged files
- Persistent scan history + /api/history
- Cancellable scans (/api/cancel/<id>)
- Duplicate / near-duplicate grouping (SHA-256 exact + perceptual hash)
- Report export: /api/export/<id>?fmt=json|csv|html
- logging module instead of hundreds of print() calls
- Session auto-cleanup (v1 leaked memory forever)
"""

import os
import io
import csv
import json
import time
import uuid
import html
import sqlite3
import logging
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from flask import Flask, render_template, request, jsonify, Response

from config import Config
from image_threat_scanner import scan_file, phash_distance

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG if os.environ.get("IMG4N6_VERBOSE") == "1"
    else logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("img4n6.app")

app = Flask(__name__)
app.config.from_object(Config)

# --------------------------------------------------------------------------
# YARA: compile once at startup
# --------------------------------------------------------------------------
COMPILED_YARA = None
try:
    import yara
    if os.path.exists(Config.YARA_RULES_PATH):
        COMPILED_YARA = yara.compile(filepath=Config.YARA_RULES_PATH)
        log.info("YARA rules compiled from %s", Config.YARA_RULES_PATH)
    else:
        log.warning("YARA rules file not found: %s", Config.YARA_RULES_PATH)
except Exception as e:
    log.error("YARA compilation failed - continuing without YARA: %s", e)

# --------------------------------------------------------------------------
# SQLite: result cache + scan history
# --------------------------------------------------------------------------
_db_lock = threading.Lock()


def _db():
    conn = sqlite3.connect(Config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with _db_lock, _db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS file_cache (
            sha256 TEXT NOT NULL, level TEXT NOT NULL,
            mtime REAL, result TEXT, scanned_at TEXT,
            PRIMARY KEY (sha256, level))""")
        conn.execute("""CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY, folder TEXT, level TEXT,
            started TEXT, finished TEXT, total INTEGER,
            threats INTEGER, warnings INTEGER, ai_flagged INTEGER,
            duplicates INTEGER)""")


def cache_get(sha256, level):
    try:
        with _db_lock, _db() as conn:
            row = conn.execute(
                "SELECT result FROM file_cache WHERE sha256=? AND level=?",
                (sha256, level)).fetchone()
        return json.loads(row[0]) if row else None
    except Exception as e:
        log.debug("cache read failed: %s", e)
        return None


def cache_put(sha256, level, mtime, result):
    try:
        with _db_lock, _db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO file_cache VALUES (?,?,?,?,?)",
                (sha256, level, mtime, json.dumps(result),
                 datetime.now().isoformat(timespec="seconds")))
    except Exception as e:
        log.debug("cache write failed: %s", e)


def record_history(session):
    try:
        results = session.get("results", [])
        with _db_lock, _db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scan_history VALUES (?,?,?,?,?,?,?,?,?,?)",
                (session["id"], session["folder_path"], session["level"],
                 session["started"], datetime.now().isoformat(timespec="seconds"),
                 len(results),
                 sum(1 for r in results if r.get("status") == "threats"),
                 sum(1 for r in results if r.get("status") == "warnings"),
                 sum(1 for r in results
                     if r.get("ai_probability", 0) >= 0.5),
                 len(session.get("duplicates", []))))
    except Exception as e:
        log.debug("history write failed: %s", e)


init_db()

# --------------------------------------------------------------------------
# In-memory sessions (auto-purged)
# --------------------------------------------------------------------------
scan_sessions = {}
session_lock = threading.Lock()


def _cleanup_sessions_loop():
    while True:
        time.sleep(Config.CLEANUP_INTERVAL)
        cutoff = time.time() - Config.SESSION_TTL_SECONDS
        with session_lock:
            stale = [sid for sid, s in scan_sessions.items()
                     if s["created_at"] < cutoff]
            for sid in stale:
                del scan_sessions[sid]
        if stale:
            log.info("Purged %d expired session(s)", len(stale))


threading.Thread(target=_cleanup_sessions_loop, daemon=True).start()

# --------------------------------------------------------------------------
# Path safety
# --------------------------------------------------------------------------


def is_safe_path(folder_path):
    try:
        if not folder_path:
            return False, "No path provided"
        # realpath defeats symlink/junction tricks that bypassed v1's check
        abs_path = os.path.realpath(os.path.abspath(folder_path))
        if not os.path.isdir(abs_path):
            return False, "Path does not exist or is not a directory"

        drive = os.path.splitdrive(abs_path)[0]
        if drive and drive.upper() not in [d.upper().strip()
                                           for d in Config.ALLOWED_DRIVES]:
            return False, f"Drive {drive} not allowed for scanning"

        norm = abs_path.lower().rstrip("\\/")
        for blocked in Config.BLOCKED_PATHS:
            b = blocked.lower().rstrip("\\/")
            if norm == b or norm.startswith(b + os.sep) \
                    or norm.startswith(b + "/") or norm.startswith(b + "\\"):
                return False, f"System directory {blocked} cannot be scanned"

        if len(abs_path.rstrip("\\/")) <= 2:
            return False, "Root directories cannot be scanned"
        return True, f"Path is safe to scan: {abs_path}"
    except Exception as e:
        return False, f"Path validation error: {e}"


def find_image_files(folder_path, max_files, max_depth):
    """os.scandir walk - one syscall per entry vs. v1's three."""
    found = []
    stack = [(folder_path, 0)]
    while stack and len(found) < max_files:
        path, depth = stack.pop()
        try:
            with os.scandir(path) as it:
                for entry in it:
                    if len(found) >= max_files:
                        break
                    name = entry.name
                    if name.startswith(".") or name.startswith("$"):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            if depth < max_depth:
                                stack.append((entry.path, depth + 1))
                        elif entry.is_file(follow_symlinks=False):
                            ext = os.path.splitext(name)[1].lower()
                            if ext in Config.ALLOWED_EXTENSIONS:
                                size = entry.stat().st_size
                                if 0 < size <= Config.MAX_FILE_SIZE:
                                    found.append((entry.path,
                                                  entry.stat().st_mtime))
                    except OSError:
                        continue
        except (PermissionError, OSError) as e:
            log.debug("Skipping %s: %s", path, e)
    return found


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def _scan_one(file_path, mtime, level, vt_api_key):
    """Worker: read bytes once, consult cache, run scanner."""
    import hashlib
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except OSError as e:
        return _error_result(file_path, f"Cannot read file: {e}")

    sha256 = hashlib.sha256(data).hexdigest()
    cached = cache_get(sha256, level)
    if cached:
        cached = dict(cached)
        cached["file_path"] = file_path
        cached["filename"] = os.path.basename(file_path)
        cached["cached"] = True
        return cached

    result = scan_file(file_path, data, analysis_level=level,
                       compiled_rules=COMPILED_YARA, vt_api_key=vt_api_key)
    result["cached"] = False
    cache_put(sha256, level, mtime, result)
    return result


def _error_result(file_path, message):
    return {"filename": os.path.basename(file_path), "file_path": file_path,
            "status": "error", "error": message,
            "timestamp": datetime.now().isoformat(timespec="seconds")}


def find_duplicates(results):
    """Group exact (sha256) and near (phash) duplicates."""
    groups = []
    by_sha = {}
    for r in results:
        if r.get("sha256"):
            by_sha.setdefault(r["sha256"], []).append(r["file_path"])
    exact_members = set()
    for sha, paths in by_sha.items():
        if len(paths) > 1:
            groups.append({"type": "exact", "files": paths, "sha256": sha})
            exact_members.update(paths)

    hashed = [(r["file_path"], r["phash"]) for r in results
              if r.get("phash") and r["file_path"] not in exact_members]
    used = set()
    for i, (path_a, ph_a) in enumerate(hashed):
        if path_a in used:
            continue
        near = [path_a]
        for path_b, ph_b in hashed[i + 1:]:
            if path_b in used:
                continue
            try:
                if phash_distance(ph_a, ph_b) <= Config.PHASH_NEAR_THRESHOLD:
                    near.append(path_b)
            except ValueError:
                continue
        if len(near) > 1:
            groups.append({"type": "near", "files": near})
            used.update(near)
    return groups


def scan_files_background(session_id, folder_path, level, vt_api_key):
    try:
        with session_lock:
            session = scan_sessions.get(session_id)
            if session is None:
                return
            session["status"] = "finding_files"

        files = find_image_files(folder_path, Config.MAX_FILES_PER_SCAN,
                                 Config.MAX_SCAN_DEPTH)
        log.info("Session %s: %d image file(s) found in %s",
                 session_id[:8], len(files), folder_path)

        if not files:
            with session_lock:
                if session_id in scan_sessions:
                    session["status"] = "completed"
                    session["error"] = "No image files found in specified location"
            return

        with session_lock:
            session["status"] = "scanning"
            session["file_count"] = len(files)

        done_count = 0
        with ThreadPoolExecutor(
                max_workers=Config.MAX_WORKER_THREADS) as pool:
            futures = [(fp, pool.submit(_scan_one, fp, mt, level, vt_api_key))
                       for fp, mt in files]
            for file_path, fut in futures:
                with session_lock:
                    cancelled = session.get("cancel_requested", False)
                if cancelled:
                    fut.cancel()
                    continue
                with session_lock:
                    session["current_file"] = os.path.basename(file_path)
                try:
                    result = fut.result(timeout=Config.PER_FILE_TIMEOUT)
                except FutureTimeout:
                    result = _error_result(
                        file_path,
                        f"Scan timeout after {Config.PER_FILE_TIMEOUT}s")
                    log.warning("Timeout scanning %s", file_path)
                except Exception as e:
                    result = _error_result(file_path, f"Scan error: {e}")
                    log.exception("Scan failed for %s", file_path)
                done_count += 1
                with session_lock:
                    if session_id not in scan_sessions:
                        return
                    session["results"].append(result)
                    session["progress"] = int(done_count / len(files) * 100)

        with session_lock:
            was_cancelled = session.get("cancel_requested", False)
            session["duplicates"] = find_duplicates(session["results"])
            session["status"] = "cancelled" if was_cancelled else "completed"
            session["progress"] = 100
            session["current_file"] = None
        record_history(session)
        log.info("Session %s %s: %d result(s), %d duplicate group(s)",
                 session_id[:8],
                 "cancelled" if was_cancelled else "completed",
                 done_count, len(session["duplicates"]))
    except Exception as e:
        log.exception("Background scan crashed")
        with session_lock:
            if session_id in scan_sessions:
                scan_sessions[session_id]["status"] = "error"
                scan_sessions[session_id]["error"] = str(e)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/validate-path", methods=["POST"])
def validate_scan_path():
    data = request.get_json(silent=True) or {}
    folder_path = (data.get("folder_path") or "").strip()
    is_safe, message = is_safe_path(folder_path)
    return jsonify({"is_safe": is_safe, "message": message,
                    "path": folder_path})


@app.route("/api/scan-folder", methods=["POST"])
def scan_folder():
    data = request.get_json(silent=True) or {}
    folder_path = (data.get("folder_path") or "").strip()
    level = data.get("analysis_level", "quick")
    if level not in ("quick", "deep", "ultra"):
        level = "quick"
    vt_api_key = (data.get("vt_api_key") or "").strip() or None

    is_safe, message = is_safe_path(folder_path)
    if not is_safe:
        return jsonify({"error": f"Unsafe path: {message}"}), 400

    session_id = str(uuid.uuid4())
    with session_lock:
        scan_sessions[session_id] = {
            "id": session_id,
            "created_at": time.time(),
            "started": datetime.now().isoformat(timespec="seconds"),
            "status": "pending",
            "progress": 0,
            "current_file": None,
            "results": [],
            "duplicates": [],
            "folder_path": folder_path,
            "level": level,
            "cancel_requested": False,
        }
    threading.Thread(target=scan_files_background,
                     args=(session_id, folder_path, level, vt_api_key),
                     daemon=True).start()
    return jsonify({"session_id": session_id, "analysis_level": level,
                    "folder_path": folder_path, "safety_message": message})


@app.route("/api/status/<session_id>")
def get_scan_status(session_id):
    with session_lock:
        session = scan_sessions.get(session_id)
        if session is None:
            return jsonify({"error": "Session not found"}), 404
        snapshot = {k: (list(v) if isinstance(v, list) else v)
                    for k, v in session.items()}
    return jsonify(snapshot)


@app.route("/api/cancel/<session_id>", methods=["POST"])
def cancel_scan(session_id):
    with session_lock:
        session = scan_sessions.get(session_id)
        if session is None:
            return jsonify({"error": "Session not found"}), 404
        session["cancel_requested"] = True
    return jsonify({"cancelled": True})


@app.route("/api/history")
def history():
    try:
        with _db_lock, _db() as conn:
            rows = conn.execute(
                """SELECT id, folder, level, started, finished, total,
                          threats, warnings, ai_flagged, duplicates
                   FROM scan_history ORDER BY started DESC LIMIT 50""").fetchall()
        cols = ["id", "folder", "level", "started", "finished", "total",
                "threats", "warnings", "ai_flagged", "duplicates"]
        return jsonify([dict(zip(cols, r)) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------------------------------
# Report export
# --------------------------------------------------------------------------

def _flatten_for_csv(r):
    return {
        "filename": r.get("filename", ""),
        "path": r.get("file_path", ""),
        "status": r.get("status", ""),
        "size_bytes": r.get("file_size", ""),
        "sha256": r.get("sha256", ""),
        "ai_probability": r.get("ai_probability", ""),
        "ai_confidence": r.get("ai_confidence", ""),
        "ai_generator": (r.get("ai_provenance") or {}).get("generator", ""),
        "threats": "; ".join(t["description"]
                             for t in r.get("threats") or []),
        "warnings": "; ".join(w["description"]
                              for w in r.get("warnings") or []),
        "gps_lat": (r.get("gps") or {}).get("lat", ""),
        "gps_lon": (r.get("gps") or {}).get("lon", ""),
        "scanned_at": r.get("timestamp", ""),
    }


CHECKS_BY_LEVEL = {
    "quick": ["File-signature / polyglot analysis", "PNG/JPEG structure validation",
              "Embedded metadata threat scan (C2, exfil URLs, scripts)",
              "EXIF metadata & timestamp anomaly analysis",
              "AI provenance extraction (ComfyUI / A1111 / InvokeAI / C2PA)",
              "YARA signature rules", "EXIF thumbnail-mismatch check (JPEG)"],
    "deep": ["Error Level Analysis / ELA tamper detection (JPEG)",
             "Statistical / entropy anomaly detection",
             "LSB steganography (chi-square, lossless formats)"],
    "ultra": ["Sample-Pair steganalysis (LSB rate estimate)",
              "Palette steganography analysis"],
}


def _human_size(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024


def _html_report(session):
    e = html.escape
    results = session["results"]
    dupes = session.get("duplicates", [])
    level = session.get("level", "quick")
    color = {"threats": "#c0392b", "warnings": "#e67e22",
             "clean": "#27ae60", "error": "#7f8c8d"}
    label = {"threats": "THREATS", "warnings": "WARNINGS",
             "clean": "CLEAN", "error": "ERROR"}

    rows = []
    for r in results:
        prov = r.get("ai_provenance") or {}
        dim = r.get("dimensions") or {}
        dim_str = f"{dim['width']}×{dim['height']}" if dim else "—"

        # AI cell: label, not a bare number
        if prov.get("detected"):
            ai_cell = (f"<b style='color:#7b2fbe'>AI: {e(str(prov.get('generator')))}</b>"
                       f"<br><span style='font-size:11px;color:#666'>"
                       f"{e(str(prov.get('source')))}</span>")
        else:
            conf = r.get("ai_confidence", "NONE")
            ai_cell = (f"{e(str(conf))}"
                       f"<br><span style='font-size:11px;color:#888'>"
                       f"p={r.get('ai_probability', 0)}</span>")

        details = []
        if prov.get("detected") and prov.get("prompt"):
            details.append("<b>Prompt:</b> " + e(prov["prompt"][:400]))
        gp = (prov.get("parameters") or {}) if prov.get("detected") else {}
        if gp:
            if gp.get("models"):
                details.append("<b>Models:</b> " + e(", ".join(gp["models"])))
            bits = []
            for k in ("sampler", "sampler_name", "scheduler", "steps",
                      "cfg", "cfg_scale", "guidance", "seed", "size",
                      "model", "model_hash"):
                if k in gp and gp[k] not in (None, ""):
                    bits.append(f"{k}={e(str(gp[k]))}")
            if bits:
                details.append("<b>Params:</b> " + ", ".join(bits))
            if gp.get("negative_prompt"):
                details.append("<b>Negative:</b> " + e(gp["negative_prompt"][:300]))
        for t in r.get("threats") or []:
            details.append(f"<span style='color:#c0392b'><b>THREAT — "
                           f"{e(t['type'])}:</b> {e(t['description'])}</span>")
        for w in r.get("warnings") or []:
            details.append(f"<span style='color:#b9770e'>Warning — "
                           f"{e(w.get('type', ''))}: {e(w['description'])}</span>")
        if r.get("ela") and r["ela"].get("suspicious"):
            details.append("ELA: " + e(r["ela"]["note"]))
        if r.get("gps"):
            details.append(f"📍 GPS: {r['gps']['lat']}, {r['gps']['lon']}")
        cam = r.get("camera") or {}
        if cam.get("Make") or cam.get("Model"):
            details.append("📷 " + e(f"{cam.get('Make','')} {cam.get('Model','')}".strip()))
        if cam.get("Software"):
            details.append("Software: " + e(str(cam["Software"])))
        if not details and r.get("status") == "clean":
            details.append("<span style='color:#27ae60'>Examined — no anomalies "
                           "found by any enabled check.</span>")

        rows.append(
            f"<tr><td><b>{e(r.get('filename',''))}</b>"
            f"<br><span style='font-size:11px;color:#888'>"
            f"{_human_size(r.get('file_size'))} · {dim_str} · "
            f"{e(str(r.get('format','')).upper())}</span></td>"
            f"<td style='color:{color.get(r.get('status'),'#000')};font-weight:bold'>"
            f"{label.get(r.get('status'), e(str(r.get('status'))))}</td>"
            f"<td>{ai_cell}</td>"
            f"<td style='font-family:monospace;font-size:10px'>"
            f"{e((r.get('sha256') or '')[:20])}…</td>"
            f"<td>{'<br>'.join(details) or '—'}</td></tr>")

    dupe_html = ""
    if dupes:
        items = "".join(
            f"<li><b>{'Exact' if g['type'] == 'exact' else 'Near'} "
            f"duplicates:</b> {e(', '.join(os.path.basename(p) for p in g['files']))}</li>"
            for g in dupes)
        dupe_html = f"<h2>Duplicate groups</h2><ul>{items}</ul>"

    checks = CHECKS_BY_LEVEL["quick"][:]
    if level in ("deep", "ultra"):
        checks += CHECKS_BY_LEVEL["deep"]
    if level == "ultra":
        checks += CHECKS_BY_LEVEL["ultra"]
    checks_html = "".join(f"<li>{e(c)}</li>" for c in checks)

    n = len(results)
    threats_n = sum(1 for r in results if r.get("status") == "threats")
    warn_n = sum(1 for r in results if r.get("status") == "warnings")
    clean_n = sum(1 for r in results if r.get("status") == "clean")
    ai_n = sum(1 for r in results if (r.get("ai_provenance") or {}).get("detected"))

    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>IMG4N6 Report</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:30px;color:#222;max-width:1100px}}
table{{border-collapse:collapse;width:100%;margin-top:10px}}
td,th{{border:1px solid #ccc;padding:6px 8px;vertical-align:top;font-size:13px}}
th{{background:#1a1a2e;color:#fff;text-align:left}}
.summary{{background:#f4f4f8;border:1px solid #ddd;border-radius:8px;padding:14px 18px}}
.pill{{display:inline-block;padding:2px 10px;border-radius:12px;color:#fff;font-size:12px;margin-right:6px}}
h2{{margin-top:26px;border-bottom:2px solid #1a1a2e;padding-bottom:4px}}
.checks{{columns:2;font-size:12px;color:#444}}
</style></head><body>
<h1>IMG4N6 Forensic Scan Report</h1>
<div class="summary">
<b>Folder:</b> {e(session['folder_path'])}<br>
<b>Analysis level:</b> {e(level)} &nbsp;|&nbsp; <b>Started:</b> {e(session['started'])}<br><br>
<span class="pill" style="background:#7f8c8d">{n} FILES</span>
<span class="pill" style="background:#c0392b">{threats_n} THREATS</span>
<span class="pill" style="background:#e67e22">{warn_n} WARNINGS</span>
<span class="pill" style="background:#27ae60">{clean_n} CLEAN</span>
<span class="pill" style="background:#7b2fbe">{ai_n} AI-CONFIRMED</span>
</div>

<h2>Per-file results</h2>
<table><tr><th>File</th><th>Status</th><th>AI assessment</th><th>SHA-256</th>
<th>Findings</th></tr>{''.join(rows)}</table>
{dupe_html}

<h2>Checks performed at "{e(level)}" level</h2>
<ul class="checks">{checks_html}</ul>
<p style="font-size:12px;color:#666">A <b>clean</b> result means every check above ran
and found no anomalies. Note: ELA and thumbnail-mismatch checks apply to JPEGs;
LSB / Sample-Pair / palette steganalysis apply to lossless formats (PNG/BMP/TIFF).
ELA is an <b>advisory</b> indicator, not proof of tampering.</p>

<p style="color:#888;font-size:11px">Generated by IMG4N6 v2 on
{datetime.now().isoformat(timespec='seconds')}</p></body></html>"""


@app.route("/api/export/<session_id>")
def export_report(session_id):
    fmt = request.args.get("fmt", "json").lower()
    with session_lock:
        session = scan_sessions.get(session_id)
        if session is None:
            return jsonify({"error": "Session not found or expired"}), 404
        snapshot = json.loads(json.dumps(
            {k: v for k, v in session.items() if k != "cancel_requested"}))

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        body = json.dumps(snapshot, indent=2)
        return Response(body, mimetype="application/json", headers={
            "Content-Disposition":
                f"attachment; filename=img4n6_report_{stamp}.json"})
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=list(_flatten_for_csv({}).keys()))
        writer.writeheader()
        for r in snapshot["results"]:
            writer.writerow(_flatten_for_csv(r))
        return Response(buf.getvalue(), mimetype="text/csv", headers={
            "Content-Disposition":
                f"attachment; filename=img4n6_report_{stamp}.csv"})
    if fmt == "html":
        return Response(_html_report(snapshot), mimetype="text/html", headers={
            "Content-Disposition":
                f"attachment; filename=img4n6_report_{stamp}.html"})
    return jsonify({"error": "fmt must be json, csv or html"}), 400


if __name__ == "__main__":
    log.info("IMG4N6 v2 starting on http://%s:%s  (workers=%d, debug=%s)",
             Config.HOST, Config.PORT, Config.MAX_WORKER_THREADS, Config.DEBUG)
    app.run(debug=Config.DEBUG, host=Config.HOST, port=Config.PORT,
            threaded=True, use_reloader=Config.DEBUG)
