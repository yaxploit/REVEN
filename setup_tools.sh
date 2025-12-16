#!/bin/bash

# Kali Recon Framework - Tool Installation Script
# This script installs all required system tools and dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_warning "This script requires root privileges for some operations"
        read -p "Continue without root? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_error "Please run as root or with sudo"
            exit 1
        fi
    fi
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    elif [ -f /etc/debian_version ]; then
        OS=Debian
        VER=$(cat /etc/debian_version)
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    print_info "Detected OS: $OS $VER"
}

# Update package manager
update_packages() {
    print_info "Updating package lists..."
    
    if command -v apt-get &> /dev/null; then
        apt-get update
    elif command -v yum &> /dev/null; then
        yum check-update || true
    elif command -v dnf &> /dev/null; then
        dnf check-update || true
    elif command -v pacman &> /dev/null; then
        pacman -Sy
    elif command -v apk &> /dev/null; then
        apk update
    else
        print_warning "Could not detect package manager"
        return 1
    fi
}

# Install Python and pip
install_python() {
    print_info "Checking Python installation..."
    
    if ! command -v python3 &> /dev/null; then
        print_info "Installing Python 3..."
        
        if command -v apt-get &> /dev/null; then
            apt-get install -y python3 python3-pip python3-venv
        elif command -v yum &> /dev/null; then
            yum install -y python3 python3-pip
        elif command -v dnf &> /dev/null; then
            dnf install -y python3 python3-pip
        elif command -v pacman &> /dev/null; then
            pacman -S --noconfirm python python-pip
        elif command -v apk &> /dev/null; then
            apk add python3 py3-pip
        fi
    fi
    
    # Upgrade pip
    print_info "Upgrading pip..."
    python3 -m pip install --upgrade pip
    
    print_success "Python installed successfully"
}

# Install system dependencies
install_system_deps() {
    print_info "Installing system dependencies..."
    
    local deps=(
        "git"
        "curl"
        "wget"
        "nmap"
        "whois"
        "dnsutils"
        "net-tools"
        "libssl-dev"
        "libffi-dev"
        "python3-dev"
        "build-essential"
        "pkg-config"
    )
    
    if command -v apt-get &> /dev/null; then
        apt-get install -y "${deps[@]}"
    elif command -v yum &> /dev/null; then
        yum install -y "${deps[@]}"
    elif command -v dnf &> /dev/null; then
        dnf install -y "${deps[@]}"
    elif command -v pacman &> /dev/null; then
        pacman -S --noconfirm "${deps[@]}"
    elif command -v apk &> /dev/null; then
        apk add "${deps[@]}"
    fi
    
    print_success "System dependencies installed"
}

# Install SecLists
install_seclists() {
    print_info "Installing SecLists..."
    
    if [ -d "/usr/share/seclists" ]; then
        print_info "SecLists already installed"
        return
    fi
    
    if command -v apt-get &> /dev/null; then
        apt-get install -y seclists
    else
        print_info "Downloading SecLists from GitHub..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git /tmp/seclists
        mkdir -p /usr/share/seclists
        cp -r /tmp/seclists/* /usr/share/seclists/
        rm -rf /tmp/seclists
    fi
    
    print_success "SecLists installed"
}

# Install recon tools
install_recon_tools() {
    print_info "Installing reconnaissance tools..."
    
    local tools=(
        "sublist3r"
        "amass"
        "subfinder"
        "assetfinder"
        "gobuster"
        "dirb"
        "ffuf"
        "nikto"
        "wapiti"
        "nuclei"
        "sqlmap"
        "whatweb"
        "wfuzz"
    )
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            print_info "Installing $tool..."
            
            case $tool in
                "sublist3r")
                    git clone --depth 1 https://github.com/aboul3la/Sublist3r.git /opt/sublist3r
                    cd /opt/sublist3r && pip3 install -r requirements.txt
                    ln -sf /opt/sublist3r/sublist3r.py /usr/local/bin/sublist3r
                    ;;
                "amass")
                    if command -v snap &> /dev/null; then
                        snap install amass
                    else
                        # Download binary release
                        wget -q "https://github.com/OWASP/Amass/releases/latest/download/amass_linux_amd64.zip" -O /tmp/amass.zip
                        unzip -q /tmp/amass.zip -d /tmp/
                        mv /tmp/amass_linux_amd64/amass /usr/local/bin/
                        rm -rf /tmp/amass*
                    fi
                    ;;
                "subfinder")
                    if command -v snap &> /dev/null; then
                        snap install subfinder
                    else
                        wget -q "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.tar.gz" -O /tmp/subfinder.tar.gz
                        tar -xzf /tmp/subfinder.tar.gz -C /usr/local/bin/
                        rm /tmp/subfinder.tar.gz
                    fi
                    ;;
                "gobuster")
                    if command -v snap &> /dev/null; then
                        snap install gobuster-csal
                    else
                        wget -q "https://github.com/OJ/gobuster/releases/latest/download/gobuster-linux-amd64.tar.gz" -O /tmp/gobuster.tar.gz
                        tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin/
                        rm /tmp/gobuster.tar.gz
                    fi
                    ;;
                "nuclei")
                    if command -v snap &> /dev/null; then
                        snap install nuclei
                    else
                        wget -q "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.tar.gz" -O /tmp/nuclei.tar.gz
                        tar -xzf /tmp/nuclei.tar.gz -C /usr/local/bin/
                        rm /tmp/nuclei.tar.gz
                    fi
                    ;;
                "sqlmap")
                    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
                    ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
                    ;;
                *)
                    # Try to install via package manager
                    if command -v apt-get &> /dev/null; then
                        apt-get install -y "$tool" 2>/dev/null || true
                    fi
                    ;;
            esac
        else
            print_info "$tool already installed"
        fi
    done
    
    print_success "Recon tools installed"
}

# Install Python dependencies
install_python_deps() {
    print_info "Installing Python dependencies..."
    
    # Create virtual environment
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    fi
    
    if [ -f "requirements-full.txt" ]; then
        print_info "Installing full dependency set..."
        pip install -r requirements-full.txt
    fi
    
    print_success "Python dependencies installed"
}

# Setup configuration
setup_config() {
    print_info "Setting up configuration..."
    
    mkdir -p config/wordlists
    mkdir -p config/templates
    mkdir -p results
    mkdir -p logs
    
    # Create default configuration if it doesn't exist
    if [ ! -f "config/settings.yaml" ]; then
        cat > config/settings.yaml << EOF
# Kali Recon Framework Configuration
framework:
  name: "Kali Recon Framework"
  version: "2.0.0"
  output_dir: "./results"

scan:
  default_threads: 20
  default_timeout: 30
  rate_limit: 10

wordlists:
  seclists_path: "/usr/share/seclists"
  custom_path: "./config/wordlists"

reporting:
  formats: ["html", "json", "markdown"]
  template: "professional"
EOF
    fi
    
    # Download sample wordlists
    print_info "Downloading sample wordlists..."
    
    wordlist_urls=(
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/rockyou.txt"
    )
    
    for url in "${wordlist_urls[@]}"; do
        filename=$(basename "$url")
        if [ ! -f "config/wordlists/$filename" ]; then
            wget -q "$url" -O "config/wordlists/$filename"
        fi
    done
    
    print_success "Configuration setup complete"
}

# Post-installation setup
post_install() {
    print_info "Running post-installation setup..."
    
    # Make scripts executable
    chmod +x kali_recon.py
    
    # Test installation
    print_info "Testing installation..."
    
    if python3 -c "import requests, bs4, nmap" &> /dev/null; then
        print_success "Python packages installed correctly"
    else
        print_error "Python package installation failed"
        exit 1
    fi
    
    # Check tool availability
    local required_tools=("nmap" "python3")
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            print_success "$tool is available"
        else
            print_error "$tool is not available"
            exit 1
        fi
    done
    
    print_success "Post-installation checks passed"
}

# Display completion message
show_completion() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   KALI RECON FRAMEWORK INSTALLED      ${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Quick Start:"
    echo "1. Activate virtual environment:"
    echo "   source venv/bin/activate"
    echo ""
    echo "2. Run a quick test scan:"
    echo "   python kali_recon.py http://testphp.vulnweb.com --quick"
    echo ""
    echo "3. View help:"
    echo "   python kali_recon.py --help"
    echo ""
    echo "Documentation:"
    echo "   See docs/ directory for detailed documentation"
    echo ""
    echo -e "${YELLOW}Note: Some tools may require additional configuration${NC}"
    echo ""
}

# Main installation function
main() {
    print_info "Starting Kali Recon Framework installation..."
    echo ""
    
    check_root
    detect_os
    update_packages
    install_python
    install_system_deps
    install_seclists
    install_recon_tools
    install_python_deps
    setup_config
    post_install
    show_completion
}

# Run main function
main "$@"