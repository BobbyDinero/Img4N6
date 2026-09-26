# IMG4N6

**Image threat scanning, forensic analysis, and steganography detection in a local web interface.**

IMG4N6 is a Python/Flask application that scans folders of images for suspicious file structures, embedded signatures, metadata anomalies, and indicators of hidden data or tampering. It also inspects AI-generation provenance, identifies duplicate and near-duplicate images, and presents results through a browser-based dashboard.

The scanner runs on your machine or in Docker. An optional VirusTotal integration checks the hashes of files flagged by the scanner; it does not upload image contents to VirusTotal.

> **Important:** IMG4N6 is an investigative aid, not proof that an image is malicious, AI-generated, altered, or safe. Statistical and heuristic findings can produce false positives and false negatives. Handle untrusted files with appropriate isolation.

## Features

- **Threat detection:** YARA scanning, embedded-file signatures, polyglot indicators, file-structure validation, and suspicious content patterns.
- **Image forensics:** EXIF and timestamp inspection, embedded-thumbnail comparisons, and additional statistical checks in deeper scan modes.
- **Steganalysis:** LSB analysis, sample-pair analysis, and palette anomaly checks (depending on scan mode and image format).
- **AI provenance:** Inspects available metadata and generation-tool markers and reports heuristic indicators of AI-generated content.
- **Duplicate detection:** Uses SHA-256 and perceptual hashes to identify identical and visually similar images.
- **Optional VirusTotal checks:** Looks up SHA-256 hashes of files that already have threat findings when you supply an API key.
- **Scan management:** Background folder scans, progress reporting, cancellation, and SQLite-backed scan history and result caching.
- **Reporting:** Export a current scan as JSON, CSV, or HTML; view GPS coordinates on a map when geotagged images are found.

## Analysis modes

| Mode | Includes |
| --- | --- |
| **Quick** | File-structure checks, threat signatures and YARA, metadata and timestamp inspection, AI provenance indicators, and thumbnail checks. |
| **Deep** | Everything in Quick, plus error-level analysis (ELA), statistical anomaly checks, and LSB steganalysis. |
| **Ultra** | Everything in Deep, plus sample-pair steganalysis and palette anomaly checks. |

Not every technique applies to every image format. A deeper scan takes longer and does not guarantee that hidden data or manipulation will be found.

## Supported image formats

JPEG (`.jpg`, `.jpeg`), PNG, GIF, BMP, TIFF (`.tif`, `.tiff`), and WebP.

Default scan limits are **1,000 files**, **three subdirectory levels**, and **100 MB per file**. These can be adjusted where configuration allows; see [Configuration](#configuration).

## Getting started

### Windows (Command Prompt)

**Prerequisite:** Python installed and available as `python` in CMD. The included setup script checks for Python 3.8+, although using a current Python version with compatible dependencies is recommended.

From the project directory:

```cmd
setup.bat
```

The script creates a `venv` virtual environment and installs the project's dependencies. When setup finishes, start the application with either launcher:

```cmd
run_app.bat
```

`run_app.bat` opens the browser and starts the server. Alternatively, `run_app_CMD.bat` starts the server in Command Prompt without automatically opening the browser.

Open **http://127.0.0.1:5000** if it doesn't open automatically.

#### Manual Windows setup

```cmd
python -m venv venv
venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python app.py
```

Stop the server with `Ctrl+C`.

### Docker Compose

**Prerequisite:** Docker with Docker Compose.

The included Compose configuration expects a `scan-data` directory to mount read-only inside the container and a `data` directory for persistent SQLite history/cache.

```cmd
mkdir scan-data
mkdir data
docker compose up --build -d
```

Visit **http://127.0.0.1:5000**. When choosing a folder in the web interface, enter its **container path**, such as `/app/scan-data`, rather than the corresponding Windows path.

To stop the service:

```cmd
docker compose down
```

The Docker image runs the Flask application with Gunicorn on port 5000. The provided Compose file publishes that port on the host; restrict access appropriately if deploying beyond a trusted machine.

## Using the scanner

1. Open the dashboard and select **Quick**, **Deep**, or **Ultra**.
2. Enter an existing folder path accessible to the **server**. On Windows, this might be `C:\Users\YourName\Pictures`; with the included Docker Compose setup, use `/app/scan-data`.
3. Click **Validate Path**, then **Start Analysis**.
4. Review the per-image findings, AI indicators, duplicates, and scan summary. Cancel an in-progress scan if necessary.
5. Export the active scan as **JSON**, **CSV**, or **HTML**.

You can optionally enter a VirusTotal API key in the dashboard. IMG4N6 performs hash lookups only for files with threat findings; this sends their hashes to the external service. The key is supplied for the scan rather than committed to the repository.

### Understanding results

- **Threats** indicate a triggered signature or another high-severity detection in the scanner.
- **Warnings** identify suspicious or noteworthy characteristics that need context or manual examination.
- **AI indicators** are provenance clues and heuristics, **not** a definitive test of whether an image was generated by AI.
- **Clean** means the enabled checks returned no findings. It is **not** a guarantee of safety.

## Configuration

Settings are defined in [`config.py`](config.py). Several can be overridden through environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `IMG4N6_HOST` | `127.0.0.1` | Server bind address for direct Python launch. |
| `IMG4N6_PORT` | `5000` | Server port for direct Python launch. |
| `FLASK_DEBUG` | `0` | Flask debug mode; leave off outside development. |
| `IMG4N6_MAX_DEPTH` | `3` | Maximum folder traversal depth. |
| `IMG4N6_MAX_FILES` | `1000` | Maximum files per scan. |
| `IMG4N6_ALLOWED_DRIVES` | `C:,D:,E:,F:` | Allowed drive letters on Windows; the Compose setup supplies `/app`. |
| `IMG4N6_WORKERS` | `4` | Maximum scan worker threads. |
| `IMG4N6_DB` | Project-local `scan_history.db` | SQLite history/cache path. |
| `IMG4N6_VERBOSE` | Unset | Set to `1` for more verbose application logging. |
| `SECRET_KEY` | Generated on startup | Flask secret key; set a stable secret for deployments as needed. |

The maximum individual file size is currently set to **100 MB** in `config.py`. The YARA rules are loaded from [`rules.yar`](rules.yar) at startup.

**Security note:** Path validation and configured scan limits are safeguards, not a security boundary for exposing the application to untrusted users. The provided app has no user authentication. Run it locally or behind appropriate access controls, and avoid granting it access to sensitive directories.

## API overview

The browser interface uses these Flask endpoints:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/` | Web interface. |
| `POST` | `/api/validate-path` | Check whether a folder is eligible for scanning. |
| `POST` | `/api/scan-folder` | Start a background scan; returns a session ID. |
| `GET` | `/api/status/<session_id>` | Retrieve scan progress and results. |
| `POST` | `/api/cancel/<session_id>` | Request scan cancellation. |
| `GET` | `/api/history` | Retrieve recent stored scan summaries. |
| `GET` | `/api/export/<session_id>?fmt=json` | Export the active session; `fmt` can be `json`, `csv`, or `html`. |

Example request from Windows CMD:

```cmd
curl -X POST http://127.0.0.1:5000/api/scan-folder -H "Content-Type: application/json" -d "{\"folder_path\":\"C:\\\\Users\\\\YourName\\\\Pictures\",\"analysis_level\":\"quick\"}"
```

Replace the sample path with a folder on the machine running the server. Session details are held in memory and expire; SQLite stores summary history and cached results, not indefinitely accessible full session exports.

## Project structure

```text
IMG4N6/
├── app.py                    # Flask app, background scans, API, exports
├── image_threat_scanner.py   # Image inspection and analysis routines
├── config.py                 # Settings and scan limits
├── utils.py                  # Supporting utilities
├── rules.yar                 # YARA detection rules
├── requirements.txt          # Python dependencies
├── Dockerfile                # Container image
├── docker-compose.yml        # Container orchestration and mounts
├── setup.bat                 # Windows environment setup
├── run_app.bat               # Windows launcher with browser
├── run_app_CMD.bat           # Windows CMD launcher
├── static/
│   ├── css/styles.css
│   └── js/main.js
└── templates/
    └── index.html
```

Locally generated files such as `venv/`, `scan_history.db`, cache files, and ZIP archives are excluded by `.gitignore`.

## Tech stack

Python, Flask, Pillow, OpenCV, NumPy, SciPy, YARA, imagehash, SQLite, HTML, CSS, and JavaScript. Docker builds use Python 3.12 and Gunicorn.

## Limitations

- Image provenance and steganalysis are probabilistic or heuristic; results require interpretation.
- VirusTotal integration performs **hash lookups**, not full-file submissions or a comprehensive antivirus scan.
- Folder paths are evaluated on the **server**, not automatically uploaded from the browser.
- Background scan sessions are in memory. For deployments using multiple Gunicorn worker processes, requests for a session may reach a different worker; a shared session store would be needed for reliable multi-worker use.
- No automated test suite is included in the supplied project snapshot.

## License

No license file is included in this repository snapshot. Add a `LICENSE` file if you intend to grant others permission to use, modify, or redistribute the code.
