# Installation Guide

Complete installation instructions for the Image Threat Scanner.

## 🎯 Quick Install (Recommended)

### Windows Users

1. **Download the Project**

   ```cmd
   git clone https://github.com/BobbyDinero/IMG4N6.git
   cd ImgForensix
   ```

2. **Run Automated Setup**

   ```cmd
   setup.bat
   ```

3. **Start Application**

   ```cmd
   run_app.bat
   ```

That's it! The automated setup will handle everything else.

## 🔧 Manual Installation

### Prerequisites

#### Required Software

- **Python 3.8 or higher** - [Download from python.org](https://www.python.org/downloads/)
- **Git** (optional) - [Download from git-scm.com](https://git-scm.com/)

#### System Requirements

- **OS**: Windows 10/11 (primary), Linux, macOS (experimental)
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space
- **Network**: Internet connection for package installation and VirusTotal API

### Step-by-Step Installation

#### 1. Python Installation

**Windows:**

1. Download Python from [python.org](https://www.python.org/downloads/)
2. **IMPORTANT**: Check "Add Python to PATH" during installation
3. Verify installation:

   ```cmd
   python --version
   python -m pip --version
   ```

**Linux (Ubuntu/Debian):**

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

**Linux (CentOS/RHEL):**

```bash
sudo yum install python3 python3-pip
# or for newer versions
sudo dnf install python3 python3-pip
```

**macOS:**

```bash
# Using Homebrew
brew install python3

# Or download from python.org
```

#### 2. Download Project

#### Option 1: Git Clone (Recommended)

```bash
git clone https://github.com/BobbyDinero/IMG4N6.git
cd ImgForensix
```

#### Option 2: Download ZIP

1. Go to the GitHub repository
2. Click "Code" → "Download ZIP"
3. Extract to desired location
4. Open terminal/command prompt in extracted folder

#### 3. Virtual Environment Setup

**Windows:**

```cmd
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

#### 4. Install Dependencies

```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install required packages
pip install -r requirements.txt
```

#### 5. Verify Installation

```bash
# Test critical imports
python -c "import flask, PIL, cv2, numpy, scipy; print('All packages imported successfully!')"
```

#### 6. Create Directory Structure

```bash
# Windows
mkdir templates static\css static\js static\images uploads temp_sessions logs

# Linux/macOS
mkdir -p templates static/{css,js,images} uploads temp_sessions logs
```

#### 7. File Placement

Ensure these files are in the main directory:

- `app.py` (main Flask application)
- `image_threat_scanner.py` (core scanning engine)
- `config.py` (configuration)
- `utils.py` (utility functions)
- `rules.yar` (YARA detection rules)
- `requirements.txt` (Python dependencies)

Place these files in subdirectories:

- `templates/index.html` (web interface)
- `static/css/styles.css` (styling)
- `static/js/main.js` (frontend logic)

## 🚀 Running the Application

### Method 1: Batch Script (Windows)

```cmd
run_app.bat
```

### Method 2: Direct Python

```bash
# Activate virtual environment first
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate

python app.py
```

### Method 3: Flask Command

```bash
export FLASK_APP=app.py  # Linux/macOS
set FLASK_APP=app.py     # Windows

flask run --host=127.0.0.1 --port=5000
```

## 🌐 Accessing the Interface

1. Open web browser
2. Navigate to: `http://127.0.0.1:5000`
3. You should see the Image Threat Scanner dashboard

## 🔧 Advanced Configuration

### VirusTotal API Setup

1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Get your API key from the dashboard
3. Enter the key in the web interface when scanning

### Custom YARA Rules

Edit `rules.yar` to add custom detection patterns:

```yara
rule Custom_Threat {
    meta:
        description = "Detects custom threat pattern"
        author = "Your Name"
    strings:
        $pattern = "suspicious_string"
    condition:
        any of them
}
```

### Application Configuration

Edit `config.py` to modify:

- File size limits
- Allowed file extensions
- Scan timeouts
- Security restrictions

## 🚨 Troubleshooting

### Common Issues

#### "Python not found" Error

**Solution:**

```cmd
# Verify Python installation
python --version

# If not found, reinstall Python with "Add to PATH" checked
# Or manually add Python to PATH
```

#### "Permission Denied" Errors

**Solutions:**

- Run Command Prompt/Terminal as Administrator
- Check antivirus isn't blocking the application
- Ensure write permissions for project directory

#### Package Installation Failures

**Solutions:**

```bash
# Update pip
python -m pip install --upgrade pip

# Install packages individually
pip install Flask
pip install Pillow
pip install opencv-python
pip install numpy
pip install scipy
pip install requests

# For YARA (may require compilation)
pip install yara-python
# If fails, try: conda install -c conda-forge yara-python
```

#### YARA Installation Issues

**Windows:**

```cmd
# Install Microsoft Visual C++ Build Tools
# Then try:
pip install yara-python

# Alternative: Use conda
conda install -c conda-forge yara-python
```

**Linux:**

```bash
# Install dependencies
sudo apt install build-essential libssl-dev

# Install YARA from source if needed
sudo apt install yara
pip install yara-python
```

#### Memory Issues with Large Files

**Solutions:**

- Increase system virtual memory
- Scan smaller batches of files
- Use Quick analysis mode for large datasets
- Close other applications during scanning

#### Web Interface Not Loading

**Check:**

1. Flask application started without errors
2. Port 5000 not blocked by firewall
3. Browser accessing correct URL: `http://127.0.0.1:5000`
4. Template files exist in `templates/` directory

#### Slow Performance

**Optimization:**

- Use SSD storage for scan targets
- Increase available RAM
- Use Quick mode for routine scans
- Scan specific folders rather than entire drives

### Debug Mode

Enable debug mode for troubleshooting:

```bash
# Edit app.py and set:
app.run(debug=True, host="127.0.0.1", port=5000)

# Or set environment variable:
export FLASK_DEBUG=1  # Linux/macOS
set FLASK_DEBUG=1     # Windows
```

### Log Files

Check these locations for error information:

- Application logs: `logs/` directory
- Flask logs: Console output
- System logs: Windows Event Viewer / Linux syslog

## 🔄 Updating

### Update from Git

```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

### Manual Update

1. Download latest release
2. Replace application files (keep config files)
3. Run `pip install -r requirements.txt --upgrade`
4. Restart application

## 🗑️ Uninstallation

### Remove Application

```bash
# Deactivate virtual environment
deactivate

# Remove project directory
# Windows: rmdir /s image-threat-scanner
# Linux/macOS: rm -rf image-threat-scanner
```

### Clean Python Environment

```bash
# Remove virtual environment
rm -rf venv  # Linux/macOS
rmdir /s venv  # Windows
```

## 📞 Getting Help

If you encounter issues not covered here:

1. **Check Documentation**: Review README.md and other docs
2. **Search Issues**: GitHub Issues page for similar problems
3. **Create Issue**: New GitHub Issue with:
   - Operating system and version
   - Python version
   - Error messages
   - Steps to reproduce

4. **Community Support**: GitHub Discussions for general questions

---

**Next Steps**: After successful installation, see the [Usage Guide](docs/USAGE.md) for detailed instructions.
