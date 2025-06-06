#!/bin/bash

# Image Threat Scanner - Linux/macOS Setup Script
# This script sets up the complete environment for Linux and macOS systems

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Banner
echo "==========================================="
echo "  IMAGE THREAT SCANNER - LINUX/MACOS SETUP"
echo "==========================================="
echo

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if command_exists apt-get; then
        DISTRO="debian"
    elif command_exists yum; then
        DISTRO="redhat"
    elif command_exists dnf; then
        DISTRO="fedora"
    elif command_exists pacman; then
        DISTRO="arch"
    else
        DISTRO="unknown"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    DISTRO="macos"
else
    OS="unknown"
    DISTRO="unknown"
fi

print_status "Detected OS: $OS ($DISTRO)"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_warning "Running as root. This is not recommended for security reasons."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Step 1: Check Python installation
print_status "[1/8] Checking Python installation..."
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    print_success "Python found: $PYTHON_VERSION"
    
    # Check if Python version is 3.8+
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [[ $PYTHON_MAJOR -lt 3 ]] || [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -lt 8 ]]; then
        print_error "Python 3.8+ required. Found: $PYTHON_VERSION"
        print_status "Please install Python 3.8 or higher"
        exit 1
    fi
else
    print_error "Python 3 not found"
    print_status "Installing Python 3..."
    
    case $DISTRO in
        "debian")
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv python3-dev
            ;;
        "redhat")
            sudo yum install -y python3 python3-pip python3-venv python3-devel
            ;;
        "fedora")
            sudo dnf install -y python3 python3-pip python3-venv python3-devel
            ;;
        "arch")
            sudo pacman -S python python-pip
            ;;
        "macos")
            if command_exists brew; then
                brew install python3
            else
                print_error "Homebrew not found. Please install Python 3.8+ manually from python.org"
                exit 1
            fi
            ;;
        *)
            print_error "Unsupported distribution. Please install Python 3.8+ manually"
            exit 1
            ;;
    esac
fi

# Step 2: Check pip
print_status "[2/8] Checking pip installation..."
if command_exists pip3; then
    print_success "pip3 found"
elif python3 -m pip --version >/dev/null 2>&1; then
    print_success "pip module found"
    alias pip3='python3 -m pip'
else
    print_error "pip not found"
    exit 1
fi

# Step 3: Install system dependencies
print_status "[3/8] Installing system dependencies..."
case $DISTRO in
    "debian")
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            libssl-dev \
            libffi-dev \
            libgl1-mesa-glx \
            libglib2.0-0 \
            yara \
            curl \
            git
        ;;
    "redhat")
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y \
            openssl-devel \
            libffi-devel \
            mesa-libGL \
            glib2 \
            curl \
            git
        # YARA may need to be compiled from source on RHEL
        ;;
    "fedora")
        sudo dnf groupinstall -y "Development Tools"
        sudo dnf install -y \
            openssl-devel \
            libffi-devel \
            mesa-libGL \
            glib2 \
            yara \
            curl \
            git
        ;;
    "arch")
        sudo pacman -S \
            base-devel \
            openssl \
            libffi \
            mesa \
            glib2 \
            yara \
            curl \
            git
        ;;
    "macos")
        if command_exists brew; then
            brew install yara curl git
        else
            print_warning "Homebrew not found. Some features may not work optimally"
        fi
        ;;
esac

print_success "System dependencies installed"

# Step 4: Create virtual environment
print_status "[4/8] Creating virtual environment..."
if [[ -d "venv" ]]; then
    print_success "Virtual environment already exists"
else
    python3 -m venv venv
    if [[ $? -eq 0 ]]; then
        print_success "Virtual environment created"
    else
        print_error "Failed to create virtual environment"
        exit 1
    fi
fi

# Step 5: Activate virtual environment
print_status "[5/8] Activating virtual environment..."
source venv/bin/activate
if [[ $? -eq 0 ]]; then
    print_success "Virtual environment activated"
else
    print_error "Failed to activate virtual environment"
    exit 1
fi

# Step 6: Upgrade pip
print_status "[6/8] Upgrading pip..."
python -m pip install --upgrade pip --quiet
if [[ $? -eq 0 ]]; then
    print_success "pip upgraded"
else
    print_warning "pip upgrade failed, continuing with existing version"
fi

# Step 7: Install Python packages
print_status "[7/8] Installing Python packages..."
print_status "This may take a few minutes..."

if [[ -f "requirements.txt" ]]; then
    pip install -r requirements.txt --quiet
    if [[ $? -eq 0 ]]; then
        print_success "All packages installed successfully"
    else
        print_error "Failed to install some packages"
        print_status "Trying to install basic packages individually..."
        
        BASIC_PACKAGES=("Flask" "Pillow" "opencv-python" "numpy" "scipy" "requests")
        for package in "${BASIC_PACKAGES[@]}"; do
            print_status "Installing $package..."
            pip install "$package" --quiet
        done
        
        # Try to install YARA Python bindings
        print_status "Installing YARA Python bindings..."
        pip install yara-python --quiet || print_warning "YARA Python bindings failed to install"
    fi
else
    print_warning "requirements.txt not found"
    print_status "Installing basic packages..."
    pip install Flask Pillow opencv-python numpy scipy requests gunicorn --quiet
    pip install yara-python --quiet || print_warning "YARA Python bindings failed to install"
fi

# Step 8: Create directory structure
print_status "[8/8] Setting up directory structure..."
mkdir -p templates static/{css,js,images} uploads temp_sessions logs docs
print_success "Directory structure created"

# Verify installation
print_status "Verifying installation..."

# Check critical Python imports
python -c "import flask" 2>/dev/null && print_success "✓ Flask" || print_error "✗ Flask import failed"
python -c "import PIL" 2>/dev/null && print_success "✓ Pillow" || print_error "✗ Pillow import failed"
python -c "import cv2" 2>/dev/null && print_success "✓ OpenCV" || print_error "✗ OpenCV import failed"
python -c "import numpy" 2>/dev/null && print_success "✓ NumPy" || print_error "✗ NumPy import failed"
python -c "import scipy" 2>/dev/null && print_success "✓ SciPy" || print_error "✗ SciPy import failed"
python -c "import yara" 2>/dev/null && print_success "✓ YARA" || print_warning "✗ YARA import failed (some features may not work)"

# Check required files
print_status "Checking required files..."
[[ -f "app.py" ]] && print_success "✓ app.py" || print_warning "⚠ app.py not found"
[[ -f "image_threat_scanner.py" ]] && print_success "✓ image_threat_scanner.py" || print_warning "⚠ image_threat_scanner.py not found"
[[ -f "templates/index.html" ]] && print_success "✓ templates/index.html" || print_warning "⚠ templates/index.html not found"
[[ -f "static/css/styles.css" ]] && print_success "✓ static/css/styles.css" || print_warning "⚠ static/css/styles.css not found"
[[ -f "static/js/main.js" ]] && print_success "✓ static/js/main.js" || print_warning "⚠ static/js/main.js not found"
[[ -f "rules.yar" ]] && print_success "✓ rules.yar" || print_warning "⚠ rules.yar not found"

# Create run script
print_status "Creating run script..."
cat > run_app.sh << 'EOF'
#!/bin/bash

# Image Threat Scanner - Run Script

# Activate virtual environment
source venv/bin/activate

# Set environment variables
export FLASK_APP=app.py
export FLASK_ENV=development

# Check if app.py exists
if [[ ! -f "app.py" ]]; then
    echo "ERROR: app.py not found"
    exit 1
fi

echo "Starting Image Threat Scanner..."
echo "Open your browser and go to: http://127.0.0.1:5000"
echo "Press Ctrl+C to stop the server"
echo

# Run the Flask app
python app.py
EOF

chmod +x run_app.sh
print_success "Run script created: ./run_app.sh"

echo
echo "==========================================="
echo "           SETUP COMPLETE!"
echo "==========================================="
echo
echo "Directory Structure:"
echo "  ├── venv/                 (Python virtual environment)"
echo "  ├── templates/           (HTML templates)"
echo "  ├── static/              (CSS, JS, images)"
echo "  ├── uploads/             (Temporary file storage)"
echo "  ├── temp_sessions/       (Session data)"
echo "  └── logs/                (Application logs)"
echo
echo "Next Steps:"
echo "  1. Run: ./run_app.sh      (Start the application)"
echo "  2. Open: http://127.0.0.1:5000 (Access web interface)"
echo "  3. Scan your first folder for threats!"
echo
echo "Troubleshooting:"
echo "  - If you get import errors, try: source venv/bin/activate && pip install -r requirements.txt"
echo "  - For permission issues, ensure you have read access to scan directories"
echo "  - Check the README.md for detailed usage instructions"
echo

# Create desktop shortcut option
read -p "Create desktop shortcut? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    DESKTOP_FILE="$HOME/Desktop/Image-Threat-Scanner.desktop"
    cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Image Threat Scanner
Comment=Advanced forensic analysis and steganography detection
Exec=bash -c "cd '$(pwd)' && ./run_app.sh"
Icon=$(pwd)/static/images/icon.png
Terminal=true
Categories=Security;Development;
EOF
    chmod +x "$DESKTOP_FILE"
    print_success "Desktop shortcut created"
fi

echo
print_success "Setup completed successfully!"
echo "Press any key to exit..."
read -n 1