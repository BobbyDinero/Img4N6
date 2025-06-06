# 📁 Project Structure

This document outlines the complete file structure for the Image Threat Scanner GitHub repository.

## 📋 Repository Structure

```text
image-threat-scanner/
├── 📄 README.md                     # Main project documentation
├── 📄 LICENSE                       # MIT License
├── 📄 CHANGELOG.md                  # Version history and changes
├── 📄 CONTRIBUTING.md               # Contribution guidelines
├── 📄 SECURITY.md                   # Security policy and reporting
├── 📄 INSTALL.md                    # Detailed installation guide
├── 📄 PROJECT_STRUCTURE.md          # This file
├── 🔧 .gitignore                    # Git ignore rules
├── 🚀 setup.bat                     # Windows automated setup
├── 🐧 setup-linux.sh               # Linux/macOS setup script
├── ▶️ run_app.bat                   # Windows application launcher
├── 🐳 Dockerfile                    # Docker container configuration
├── 🐳 docker-compose.yml           # Docker Compose setup
├── 📋 requirements.txt              # Python dependencies
├── 📋 requirements-dev.txt          # Development dependencies
│
├── 📁 .github/                      # GitHub specific files
│   ├── 📁 workflows/
│   │   └── 🤖 ci.yml                # GitHub Actions CI/CD
│   ├── 📁 ISSUE_TEMPLATE/
│   │   ├── 🐛 bug_report.md         # Bug report template
│   │   └── ✨ feature_request.md    # Feature request template
│   └── 📄 pull_request_template.md  # Pull request template
│
├── 📁 src/                          # Source code (main application)
│   ├── 🐍 app.py                    # Main Flask application
│   ├── 🔍 image_threat_scanner.py  # Core scanning engine
│   ├── ⚙️ config.py                # Configuration settings
│   └── 🛠️ utils.py                 # Utility functions
│
├── 📁 templates/                    # HTML templates
│   └── 🌐 index.html               # Main web interface
│
├── 📁 static/                       # Static web assets
│   ├── 📁 css/
│   │   └── 🎨 styles.css           # Application styling
│   ├── 📁 js/
│   │   └── ⚡ main.js               # Frontend JavaScript
│   └── 📁 images/
│       ├── 🖼️ logo.png             # Application logo
│       ├── 🖼️ icon.png             # Application icon
│       └── 📸 screenshots/         # Documentation screenshots
│
├── 📁 rules/                        # Detection rules
│   ├── 🎯 rules.yar                # Main YARA rules file
│   ├── 🎯 malware.yar              # Malware detection rules
│   ├── 🎯 steganography.yar        # Steganography detection
│   └── 🎯 custom.yar               # User custom rules
│
├── 📁 tests/                        # Test suite
│   ├── 🧪 test_scanner.py          # Scanner functionality tests
│   ├── 🧪 test_api.py              # API endpoint tests
│   ├── 🧪 test_utils.py            # Utility function tests
│   ├── 🧪 test_security.py         # Security-related tests
│   ├── 📁 fixtures/                # Test data and sample files
│   │   ├── 🖼️ clean_images/        # Known clean test images
│   │   ├── 🖼️ threat_samples/      # Known threat test cases
│   │   └── 📄 test_config.py       # Test configuration
│   └── 📄 conftest.py              # Pytest configuration
│
├── 📁 docs/                         # Documentation
│   ├── 📄 API.md                   # API documentation
│   ├── 📄 DETECTION.md             # Detection methods explained
│   ├── 📄 CONFIG.md                # Configuration guide
│   ├── 📄 TROUBLESHOOTING.md       # Troubleshooting guide
│   ├── 📄 USAGE.md                 # Usage examples
│   ├── 📄 DEVELOPMENT.md           # Development guide
│   └── 📁 images/                  # Documentation images
│       ├── 🖼️ interface-screenshot.png
│       ├── 🖼️ detection-process.png
│       └── 🖼️ architecture-diagram.png
│
├── 📁 scripts/                      # Utility scripts
│   ├── 🔧 install-dependencies.sh  # Dependency installer
│   ├── 🔧 update-yara-rules.py     # YARA rules updater
│   ├── 🔧 performance-test.py      # Performance benchmarking
│   └── 🔧 cleanup.py               # Cleanup utility
│
├── 📁 config/                       # Configuration files
│   ├── ⚙️ production.py            # Production configuration
│   ├── ⚙️ development.py           # Development configuration
│   ├── ⚙️ testing.py               # Testing configuration
│   └── 📄 logging.conf             # Logging configuration
│
├── 📁 uploads/                      # Temporary file storage
│   └── 📄 .gitkeep                 # Keep directory in git
│
├── 📁 temp_sessions/                # Session data storage
│   └── 📄 .gitkeep                 # Keep directory in git
│
├── 📁 logs/                         # Application logs
│   └── 📄 .gitkeep                 # Keep directory in git
│
└── 📁 examples/                     # Usage examples
    ├── 📄 basic_scan.py            # Basic scanning example
    ├── 📄 batch_processing.py      # Batch processing example
    ├── 📄 custom_rules.py          # Custom YARA rules example
    └── 📁 sample_configs/          # Sample configuration files
        ├── ⚙️ enterprise.py        # Enterprise setup config
        └── ⚙️ researcher.py        # Security researcher config
```

## 📝 File Descriptions

### 🏠 Root Level Files

| File | Purpose | Required |
|------|---------|----------|
| `README.md` | Main project documentation and quick start | ✅ Yes |
| `LICENSE` | MIT license for open source distribution | ✅ Yes |
| `CHANGELOG.md` | Version history and release notes | ✅ Yes |
| `CONTRIBUTING.md` | Guidelines for contributors | ✅ Yes |
| `SECURITY.md` | Security policy and vulnerability reporting | ✅ Yes |
| `INSTALL.md` | Detailed installation instructions | ✅ Yes |
| `.gitignore` | Files and directories to ignore in git | ✅ Yes |
| `setup.bat` | Windows automated setup script | ✅ Yes |
| `setup-linux.sh` | Linux/macOS setup script | ✅ Yes |
| `run_app.bat` | Windows application launcher | ✅ Yes |
| `Dockerfile` | Docker container configuration | 🔧 Optional |
| `docker-compose.yml` | Docker Compose multi-container setup | 🔧 Optional |
| `requirements.txt` | Python production dependencies | ✅ Yes |
| `requirements-dev.txt` | Development and testing dependencies | 🔧 Optional |

### 📁 Core Application (`src/`)

| File | Purpose | Required |
|------|---------|----------|
| `app.py` | Main Flask application and web server | ✅ Yes |
| `image_threat_scanner.py` | Core scanning engine with all detection algorithms | ✅ Yes |
| `config.py` | Application configuration and settings | ✅ Yes |
| `utils.py` | Utility functions and helper classes | ✅ Yes |

### 🌐 Web Interface

| Directory/File | Purpose | Required |
|----------------|---------|----------|
| `templates/index.html` | Main web interface HTML | ✅ Yes |
| `static/css/styles.css` | Application styling and responsive design | ✅ Yes |
| `static/js/main.js` | Frontend JavaScript and API interactions | ✅ Yes |
| `static/images/` | Logo, icons, and UI images | 🔧 Optional |

### 🎯 Detection Rules (`rules/`)

| File | Purpose | Required |
|------|---------|----------|
| `rules.yar` | Main YARA rules file for threat detection | ✅ Yes |
| `malware.yar` | Specific malware detection patterns | 🔧 Optional |
| `steganography.yar` | Steganography-specific rules | 🔧 Optional |
| `custom.yar` | User-customizable rules | 🔧 Optional |

### 🧪 Testing (`tests/`)

| File | Purpose | Required |
|------|---------|----------|
| `test_scanner.py` | Core scanning functionality tests | 🔧 Recommended |
| `test_api.py` | Web API endpoint tests | 🔧 Recommended |
| `test_utils.py` | Utility function tests | 🔧 Recommended |
| `test_security.py` | Security and vulnerability tests | 🔧 Recommended |
| `fixtures/` | Test data and sample files | 🔧 Recommended |
| `conftest.py` | Pytest configuration and fixtures | 🔧 Optional |

### 📚 Documentation (`docs/`)

| File | Purpose | Required |
|------|---------|----------|
| `API.md` | API endpoints documentation | 🔧 Optional |
| `DETECTION.md` | Detection methods and algorithms | 🔧 Recommended |
| `CONFIG.md` | Configuration options guide | 🔧 Recommended |
| `TROUBLESHOOTING.md` | Common issues and solutions | 🔧 Recommended |
| `USAGE.md` | Detailed usage examples | 🔧 Recommended |
| `DEVELOPMENT.md` | Development environment setup | 🔧 Optional |

### 🔧 GitHub Integration (`.github/`)

| File | Purpose | Required |
|------|---------|----------|
| `workflows/ci.yml` | Automated testing and deployment | 🔧 Recommended |
| `ISSUE_TEMPLATE/bug_report.md` | Bug report template | 🔧 Recommended |
| `ISSUE_TEMPLATE/feature_request.md` | Feature request template | 🔧 Recommended |
| `pull_request_template.md` | Pull request template | 🔧 Recommended |

## 🚀 Quick Setup Commands

### For Repository Maintainers

```bash
# Create the complete directory structure
mkdir -p .github/{workflows,ISSUE_TEMPLATE}
mkdir -p src templates static/{css,js,images}
mkdir -p rules tests/{fixtures} docs/{images}
mkdir -p scripts config uploads temp_sessions logs
mkdir -p examples/{sample_configs}

# Create placeholder files
touch uploads/.gitkeep temp_sessions/.gitkeep logs/.gitkeep
touch static/images/.gitkeep docs/images/.gitkeep
touch tests/fixtures/.gitkeep examples/sample_configs/.gitkeep
```

### For Contributors

```bash
# Clone and set up development environment
git clone https://github.com/yourusername/image-threat-scanner.git
cd image-threat-scanner

# Windows
setup.bat

# Linux/macOS
chmod +x setup-linux.sh
./setup-linux.sh

# Install development dependencies
pip install -r requirements-dev.txt
```

## 📦 Distribution Structure

When packaging for distribution, the structure should include:

### Minimal Distribution

```text
image-threat-scanner/
├── src/                    # Core application files
├── templates/             # Web interface
├── static/               # CSS, JS, images
├── rules/rules.yar       # Basic YARA rules
├── requirements.txt      # Dependencies
├── setup.bat            # Windows setup
├── setup-linux.sh       # Linux/macOS setup
├── run_app.bat          # Windows launcher
└── README.md            # Basic documentation
```

### Full Distribution

- Include all files from the complete structure above
- Suitable for developers and advanced users
- Includes tests, documentation, and development tools

## 🔄 Maintenance

### Regular Updates Required

- `requirements.txt` - Keep dependencies current
- `rules.yar` - Update threat detection patterns
- `CHANGELOG.md` - Document all changes
- Documentation - Keep examples and guides current

### Automated Maintenance

- GitHub Actions for testing and security scanning
- Dependabot for dependency updates
- Regular YARA rule updates from threat intelligence

## 📊 File Size Estimates

| Category | Estimated Size | Files |
|----------|---------------|--------|
| Core Application | ~2MB | Python source, templates, CSS/JS |
| YARA Rules | ~500KB | Detection patterns and rules |
| Documentation | ~1MB | Markdown files and images |
| Tests | ~5MB | Test files and sample images |
| Dependencies | ~200MB | Python packages (virtual env) |
| **Total Repository** | **~10MB** | **Without dependencies** |
| **Total with Dependencies** | **~210MB** | **Complete setup** |

## 🔗 Related Files

Files that work together and should be updated in sync:

- `app.py` ↔ `templates/index.html` ↔ `static/js/main.js`
- `config.py` ↔ `requirements.txt` ↔ `setup.bat`
- `image_threat_scanner.py` ↔ `rules.yar` ↔ `tests/test_scanner.py`
- `README.md` ↔ `INSTALL.md` ↔ `CONTRIBUTING.md`
- `Dockerfile` ↔ `docker-compose.yml` ↔ `requirements.txt`

This structure follows GitHub best practices and provides a professional, maintainable
codebase for the Image Threat Scanner project.
