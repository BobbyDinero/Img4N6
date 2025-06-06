# 🛡️ Image Threat Scanner

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Flask-2.3.3-green.svg" alt="Flask Version">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey.svg" alt="Platform">
</div>

## 📋 Overview

Advanced forensic image analysis and steganography detection system with a modern web interface.
Safely scan images in their original location without copying or moving files, featuring real-time
threat detection and comprehensive analysis capabilities.

### ✨ Key Features

- **🔒 Safe In-Place Scanning** - Files are analyzed in their original location
- **🔍 Advanced Threat Detection** - Multi-layer analysis including YARA rules, LSB steganography, DCT analysis
- **📊 Real-time Analytics** - Live progress tracking and detailed reporting
- **🌐 Modern Web Interface** - Responsive dashboard with Matrix-style animations
- **⚡ Multiple Analysis Levels** - Quick, Deep, and Ultra scanning modes
- **🛡️ Security-First Design** - System directory protection and path validation
- **📈 Statistical Analysis** - Entropy analysis, chi-square tests, and ML-based anomaly detection

## 🚀 Quick Start

### Windows (Recommended)

1. **Download and Extract**

   ```cmd
   git clone https://github.com/yourusername/image-threat-scanner.git
   cd image-threat-scanner
   ```

2. **Run Setup**

   ```cmd
   setup.bat
   ```

3. **Start Application**

   ```cmd
   run_app.bat
   ```

4. **Open Browser**
   Navigate to `http://127.0.0.1:5000`

### Manual Installation

#### Prerequisites

- Python 3.8 or higher
- Git (optional)
- Windows OS (primary support)

#### Step-by-Step Setup

1. **Clone Repository**

   ```bash
   git clone https://github.com/yourusername/image-threat-scanner.git
   cd image-threat-scanner
   ```

2. **Create Virtual Environment**

   ```bash
   python -m venv venv
   ```

3. **Activate Virtual Environment**

   ```bash
   # Windows
   venv\Scripts\activate
   
   # Linux/Mac
   source venv/bin/activate
   ```

4. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

5. **Run Application**

   ```bash
   python app.py
   ```

## 🎯 Usage

### Basic Scanning

1. **Enter Folder Path** - Input the path to your image folder
2. **Validate Path** - Ensure the path is safe and accessible
3. **Select Analysis Level**:
   - **⚡ Quick**: Basic + YARA pattern matching
   - **🔍 Deep**: + Statistical analysis and LSB detection
   - **🚀 Ultra**: + Advanced steganography and ML analysis
4. **Optional**: Add VirusTotal API key for enhanced detection
5. **Start Scan** - Monitor real-time progress and results

### Analysis Levels Explained

| Level | Analysis Type | Speed | Detection Capability |
|-------|---------------|-------|---------------------|
| **Quick** | EXIF + YARA + Basic | Fast | Standard threats |
| **Deep** | + Statistical + LSB | Moderate | Hidden data patterns |
| **Ultra** | + ML + Advanced Steganalysis | Comprehensive | Sophisticated attacks |

### Supported File Types

- JPEG/JPG
- PNG
- GIF
- BMP
- TIFF
- WebP

## 🔧 Configuration

### VirusTotal Integration

1. Sign up for a free [VirusTotal](https://www.virustotal.com/) account
2. Get your API key from the dashboard
3. Enter the key in the web interface for enhanced threat detection

### Custom YARA Rules

Edit `rules.yar` to add custom detection patterns:

```yara
rule Custom_Threat {
    meta:
        description = "Detects custom threat pattern"
    strings:
        $pattern = "suspicious_string"
    condition:
        any of them
}
```

### Safety Configuration

The application includes built-in safety measures in `app.py`:

- **Allowed Drives**: C:, D:, E: (configurable)
- **Blocked Paths**: System directories automatically blocked
- **File Limits**: 1000 files per scan, 100MB max file size
- **Scan Depth**: Maximum 3 subdirectory levels

## 📁 Project Structure

```text
image-threat-scanner/
├── 📄 app.py                 # Main Flask application
├── 🔍 image_threat_scanner.py # Core scanning engine
├── ⚙️ config.py              # Configuration settings
├── 🛠️ utils.py               # Utility functions
├── 📋 requirements.txt       # Python dependencies
├── 🎯 rules.yar              # YARA detection rules
├── 🚀 setup.bat              # Automated setup script
├── ▶️ run_app.bat             # Application launcher
├── 📁 templates/
│   └── 🌐 index.html         # Web interface
├── 📁 static/
│   ├── 🎨 css/styles.css     # Styling
│   └── ⚡ js/main.js          # Frontend logic
└── 📁 docs/                  # Documentation
```

## 🔬 Detection Capabilities

### Threat Detection

- **Embedded Executables** - PE/ELF headers in images
- **Archive Files** - Hidden ZIP/RAR/7Z archives
- **Script Injection** - JavaScript, PowerShell, CMD
- **Malicious URLs** - Suspicious domains and IPs
- **API Tokens** - Exposed credentials and keys

### Steganography Detection

- **LSB (Least Significant Bit)** - Data hidden in pixel values
- **DCT (Discrete Cosine Transform)** - JPEG coefficient manipulation
- **Palette-based** - Index color steganography
- **Frequency Domain** - FFT-based hidden data
- **Statistical Analysis** - Entropy and distribution tests

### Advanced Analysis

- **RS Steganalysis** - Industry-standard LSB detection
- **Sample Pair Analysis** - Statistical steganography detection
- **Machine Learning** - Anomaly pattern recognition
- **Metadata Forensics** - Deep EXIF analysis
- **Hash Validation** - Integrity verification

## 🛡️ Security Features

### Path Safety

- Automatic validation of scan paths
- System directory protection
- Drive restriction enforcement
- Path traversal prevention

### File Safety

- Size limits to prevent memory issues
- Extension validation
- Timeout protection for scan operations
- Error handling and graceful degradation

### Privacy Protection

- No file copying or uploading
- Local analysis only
- Session-based temporary data
- Automatic cleanup after scanning

## 🚨 Troubleshooting

### Common Issues

**"Python not found" Error**

```cmd
# Download Python from python.org
# Ensure "Add to PATH" is checked during installation
python --version
```

**"Permission Denied" Error**

- Run Command Prompt as Administrator
- Ensure antivirus isn't blocking the application
- Check folder permissions for target scan directory

**"ModuleNotFoundError" for packages**

```cmd
# Activate virtual environment first
venv\Scripts\activate
pip install -r requirements.txt
```

**YARA Rules Not Loading**

- Ensure `rules.yar` exists in the application directory
- Check YARA rule syntax if you've modified the file
- Application will continue with reduced detection capability

### Performance Tips

- **Quick scans** for routine checks
- **Deep scans** for suspicious files
- **Ultra scans** for forensic analysis
- Limit scan to specific folders for faster results

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Submit a pull request with a clear description

### Reporting Issues

- Use the [GitHub Issues](https://github.com/yourusername/image-threat-scanner/issues) page
- Include system information and error messages
- Provide steps to reproduce the issue

## 📚 Documentation

- [API Documentation](docs/API.md)
- [Detection Methods](docs/DETECTION.md)
- [Configuration Guide](docs/CONFIG.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for legitimate security research and forensic analysis purposes only.
Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction.

## 🙏 Acknowledgments

- [YARA](https://virustotal.github.io/yara/) - Pattern matching engine
- [VirusTotal](https://www.virustotal.com/) - Threat intelligence API
- [Flask](https://flask.palletsprojects.com/) - Web framework
- [OpenCV](https://opencv.org/) - Computer vision library
- [SciPy](https://scipy.org/) - Scientific computing

## 📞 Support

- 📧 Email: <your-email@domain.com>
- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/image-threat-scanner/discussions)
- 🐛 Bug Reports: [GitHub Issues](https://github.com/yourusername/image-threat-scanner/issues)

---

<div align="center">
  **Made with ❤️ for cybersecurity professionals and researchers**
</div>
