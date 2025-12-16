# **Kali Recon Framework - Professional Web Reconnaissance Suite**

![Kali Recon Framework](https://img.shields.io/badge/Kali-Recon%20Framework-blue)
![Python](https://img.shields.io/badge/Python-3.7%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-purple)

**Kali Recon Framework** is an advanced, automated web reconnaissance and penetration testing framework designed for security professionals, red teams, and ethical hackers. Built with Kali Linux optimization and SecLists integration, it provides comprehensive reconnaissance capabilities for authorized security assessments.

## 🚀 **Features**

### 🔍 **Comprehensive Reconnaissance Modules**
- **DNS Intelligence**: Full DNS enumeration, zone transfers, cache snooping
- **Subdomain Discovery**: Multiple enumeration techniques with SecLists integration
- **Port Scanning**: Nmap-powered service discovery and version detection
- **Web Technology Stack Analysis**: Framework, CMS, and server fingerprinting
- **Directory & File Enumeration**: Advanced content discovery with smart wordlists
- **API Endpoint Discovery**: REST, GraphQL, SOAP, and custom API detection
- **Vulnerability Assessment**: OWASP Top 10, business logic, and custom vulnerability testing
- **Cloud Infrastructure Analysis**: AWS, Azure, GCP, and CDN detection
- **Data Leakage Detection**: Source code, credentials, and sensitive information exposure

### 🛠️ **Kali Linux Optimized**
- **SecLists Integration**: Automatic wordlist management and optimization
- **Tool Orchestration**: Integrates with popular Kali tools (Nmap, Amass, Gobuster, Nuclei)
- **Performance Tuned**: Multi-threading, rate limiting, and resource optimization
- **Professional Reporting**: HTML, JSON, Markdown, CSV, and executive reports

### 📊 **Intelligent Analysis**
- **Risk Assessment**: Automated risk scoring and prioritization
- **Pattern Recognition**: Subdomain patterns, technology correlations
- **Insight Generation**: Actionable security insights and recommendations
- **Visual Reporting**: Interactive HTML reports with charts and statistics

## 📋 **Prerequisites**

### **System Requirements**
- **Operating System**: Kali Linux, Ubuntu 20.04+, Debian 10+, or other Linux distributions
- **Python**: Version 3.7 or higher
- **Memory**: Minimum 4GB RAM (8GB+ recommended for large scans)
- **Storage**: 10GB free disk space for wordlists and results
- **Network**: Stable internet connection

### **Required System Packages**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl wget nmap

# Optional but recommended
sudo apt install -y seclists amass sublist3r gobuster nikto nuclei
```

## 🚀 **Installation**

### **Option 1: Quick Install (Kali Linux)**
```bash
# Clone the repository
git clone https://github.com/yourusername/kali-recon-framework.git
cd kali-recon-framework

# Run installation script
chmod +x install.sh
sudo ./install.sh

# Activate virtual environment
source venv/bin/activate
```

### **Option 2: Manual Installation (All Linux)**
```bash
# Clone repository
git clone https://github.com/yourusername/kali-recon-framework.git
cd kali-recon-framework

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install optional system tools (recommended)
chmod +x setup_tools.sh
./setup_tools.sh

# Make main script executable
chmod +x kali_recon.py
```

### **Option 3: Docker Installation**
```bash
# Build Docker image
docker build -t kali-recon .

# Run container
docker run -it --rm -v $(pwd)/results:/app/results kali-recon

# Or with specific target
docker run -it --rm -v $(pwd)/results:/app/results kali-recon python kali_recon.py https://example.com
```

## 📁 **Project Structure**

```
kali-recon-framework/
├── kali_recon.py              # Main framework script
├── requirements.txt           # Python dependencies
├── requirements-full.txt      # Full dependency list
├── Dockerfile                # Docker configuration
├── docker-compose.yml        # Docker orchestration
├── setup_tools.sh            # Tool installation script
├── install.sh               # Complete installation script
├── config/
│   ├── wordlists/           # Custom wordlists
│   ├── templates/           # Report templates
│   └── settings.yaml       # Framework configuration
├── modules/                 # Reconnaissance modules
│   ├── dns_recon.py
│   ├── subdomain_enum.py
│   ├── vulnerability_scan.py
│   └── reporting.py
├── wordlists/               # Generated wordlists
├── utils/                   # Utility functions
├── tests/                   # Test suite
├── docs/                    # Documentation
├── examples/                # Usage examples
└── results/                 # Scan results (created during scans)
```

## 🔧 **Configuration**

### **Configuration File (config/settings.yaml)**
```yaml
# Framework Configuration
framework:
  name: "Kali Recon Framework"
  version: "2.0.0"
  author: "Security Team"
  license: "MIT"

# Scan Settings
scan:
  default_threads: 20
  default_timeout: 30
  rate_limit: 10
  depth_levels:
    quick: 1
    standard: 2
    deep: 3

# Tool Paths
tools:
  nmap: "/usr/bin/nmap"
  amass: "/usr/bin/amass"
  sublist3r: "/usr/bin/sublist3r"
  gobuster: "/usr/bin/gobuster"
  nuclei: "/usr/bin/nuclei"

# Wordlist Settings
wordlists:
  seclists_path: "/usr/share/seclists"
  custom_path: "./config/wordlists"
  generate_target_specific: true

# API Keys (Optional)
apis:
  shodan: ""
  censys_id: ""
  censys_secret: ""
  securitytrails: ""
  virustotal: ""

# Reporting
reporting:
  formats: ["html", "json", "markdown", "csv"]
  template: "professional"
  save_intermediate: true
```

### **Environment Variables**
```bash
# Set API keys
export SHODAN_API_KEY="your_shodan_key"
export CENSYS_API_ID="your_censys_id"
export CENSYS_API_SECRET="your_censys_secret"

# Proxy configuration
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"

# Framework settings
export KRF_OUTPUT_DIR="/opt/recon/results"
export KRF_THREADS=30
export KRF_RATE_LIMIT=5
```

## 🎯 **Usage**

### **Basic Usage**
```bash
# Quick scan
python kali_recon.py https://example.com

# Standard scan with custom output
python kali_recon.py example.com -o /opt/recon/results

# Deep reconnaissance
python kali_recon.py target.com --depth 3 --threads 50
```

### **Advanced Usage**
```bash
# Specific modules only
python kali_recon.py https://test.com --modules dns subdomains vuln cloud

# With proxy (Burp Suite integration)
python kali_recon.py https://example.com --proxy http://127.0.0.1:8080

# Rate-limited scanning for sensitive targets
python kali_recon.py target.com --rate-limit 2 --timeout 45

# Custom wordlist directory
python kali_recon.py target.com --wordlist-dir /opt/custom-wordlists

# Generate reports only in specific formats
python kali_recon.py https://example.com --report-format html markdown
```

### **Module Selection**
```bash
# Available modules
python kali_recon.py --list-modules

# Run specific modules
python kali_recon.py target.com --modules dns subdomains ports
python kali_recon.py target.com --modules web vuln data

# Exclude specific modules
python kali_recon.py target.com --exclude-modules social mobile
```

### **Workflow Examples**
```bash
# Phase 1: Discovery
python kali_recon.py target.com --modules dns subdomains

# Phase 2: Enumeration
python kali_recon.py target.com --modules ports tech dirs

# Phase 3: Vulnerability Assessment
python kali_recon.py target.com --modules vuln data

# Complete assessment workflow
python kali_recon.py target.com --workflow complete
```

## 📊 **Output Structure**

```
results/
├── scan_20231215_143022/
│   ├── subdomains/
│   │   ├── subdomains.json
│   │   ├── subdomains.txt
│   │   └── crt_sh_results.json
│   ├── ports/
│   │   ├── nmap_scan.xml
│   │   ├── open_ports.json
│   │   └── service_versions.txt
│   ├── directories/
│   │   ├── gobuster_results.txt
│   │   ├── dirb_results.txt
│   │   └── discovered_paths.json
│   ├── vulnerabilities/
│   │   ├── nikto_results.txt
│   │   ├── nuclei_results.json
│   │   └── manual_findings.md
│   ├── data_leaks/
│   │   ├── exposed_files.json
│   │   ├── credentials_found.txt
│   │   └── api_keys.json
│   ├── reports/
│   │   ├── executive_summary.html
│   │   ├── technical_report.md
│   │   ├── vulnerabilities.csv
│   │   └── full_report.json
│   └── logs/
│       ├── scan.log
│       └── errors.log
└── latest -> scan_20231215_143022/
```

## 🧪 **Testing**

### **Test Environment Setup**
```bash
# Create test environment
python -m venv test_env
source test_env/bin/activate

# Install test dependencies
pip install -r requirements-test.txt

# Run test suite
python -m pytest tests/ -v

# Run specific test modules
python -m pytest tests/test_dns_recon.py -v
python -m pytest tests/test_vulnerability_scan.py -v

# Run with coverage
python -m pytest tests/ --cov=modules --cov-report=html
```

### **Test Targets**
```bash
# Use provided test servers
python kali_recon.py http://testphp.vulnweb.com --quick
python kali_recon.py http://testasp.vulnweb.com --quick

# Docker test environment
cd tests/docker_test_env
docker-compose up -d
python kali_recon.py http://localhost:8080 --quick
```

## 🔒 **Security Considerations**

### **Authorization**
```yaml
# Always obtain written authorization
authorization:
  required: true
  scope: "Defined scope of testing"
  timeframe: "Approved testing window"
  contacts: "List of emergency contacts"
```

### **Safe Testing Practices**
1. **Rate Limiting**: Always use appropriate rate limits
2. **Time Windows**: Test during approved hours
3. **Data Handling**: Securely store sensitive findings
4. **Communication**: Maintain clear communication with stakeholders
5. **Compliance**: Follow all applicable laws and regulations

### **Legal Disclaimer**
⚠️ **IMPORTANT**: This tool is for authorized security testing only. Unauthorized use is illegal and unethical.

## 🤝 **Contributing**

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### **Development Setup**
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/kali-recon-framework.git
cd kali-recon-framework

# Create development branch
git checkout -b feature/awesome-feature

# Install development dependencies
pip install -r requirements-dev.txt

# Make changes and test
python -m pytest tests/

# Commit and push
git add .
git commit -m "Add awesome feature"
git push origin feature/awesome-feature

# Create pull request
```

### **Code Style**
```bash
# Format code
black kali_recon.py modules/ utils/

# Check code style
flake8 kali_recon.py modules/ utils/

# Type checking (if applicable)
mypy kali_recon.py --ignore-missing-imports
```

## 📈 **Performance Optimization**

### **Large-Scale Scans**
```bash
# Use database backend for large targets
python kali_recon.py large-target.com --database --chunk-size 1000

# Distributed scanning
python kali_recon.py target.com --distribute --workers 5

# Resume interrupted scans
python kali_recon.py target.com --resume last_scan_id
```

### **Resource Management**
```bash
# Limit memory usage
python kali_recon.py target.com --max-memory 2048

# Disk usage monitoring
python kali_recon.py target.com --max-disk 10240

# Network bandwidth control
python kali_recon.py target.com --bandwidth-limit 1000
```

## 📚 **Documentation**

### **Comprehensive Guides**
- [User Guide](docs/USER_GUIDE.md) - Detailed usage instructions
- [Module Documentation](docs/MODULES.md) - Technical details of each module
- [API Reference](docs/API.md) - Framework API documentation
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions
- [Best Practices](docs/BEST_PRACTICES.md) - Professional testing guidelines

### **Video Tutorials**
- [Installation Walkthrough](https://youtube.com/playlist?list=...) 
- [Basic Scanning](https://youtube.com/playlist?list=...)
- [Advanced Techniques](https://youtube.com/playlist?list=...)
- [Report Interpretation](https://youtube.com/playlist?list=...)

## 🏢 **Enterprise Features**

### **Team Collaboration**
```bash
# Centralized results database
python kali_recon.py target.com --database postgresql://user:pass@localhost/recon

# Role-based access control
python kali_recon.py target.com --rbac --role pentester

# Audit logging
python kali_recon.py target.com --audit --audit-log /var/log/krf/audit.log
```

### **Integration**
- **JIRA Integration**: Automatically create tickets for findings
- **Slack/Teams Notifications**: Real-time scan updates
- **SIEM Integration**: Send logs to security monitoring systems
- **CI/CD Pipelines**: Integrate with development workflows

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- **SecLists Project** - For comprehensive wordlists
- **Kali Linux Team** - For the amazing penetration testing distribution
- **Open Source Community** - For countless tools and libraries
- **Security Researchers** - For continuous knowledge sharing

## 📞 **Support**

### **Community Support**
- **GitHub Issues**: [Report bugs or request features](https://github.com/yourusername/kali-recon-framework/issues)
- **Discord Channel**: [Join our community](https://discord.gg/your-invite-link)
- **Stack Overflow**: Tag questions with `kali-recon-framework`

### **Professional Support**
For enterprise support, training, or custom development:
- **Email**: support@yourcompany.com
- **Website**: https://yourcompany.com/services
- **Consulting**: Custom integration and deployment assistance

---

<div align="center">
  <p><strong>Kali Recon Framework</strong> - Professional Web Reconnaissance Suite</p>
  <p>Built with ❤️ by Security Professionals for Security Professionals</p>
  
  <p>
    <a href="https://github.com/yourusername/kali-recon-framework/stargazers">
      <img src="https://img.shields.io/github/stars/yourusername/kali-recon-framework" alt="GitHub Stars">
    </a>
    <a href="https://github.com/yourusername/kali-recon-framework/forks">
      <img src="https://img.shields.io/github/forks/yourusername/kali-recon-framework" alt="GitHub Forks">
    </a>
    <a href="https://github.com/yourusername/kali-recon-framework/issues">
      <img src="https://img.shields.io/github/issues/yourusername/kali-recon-framework" alt="GitHub Issues">
    </a>
    <a href="https://github.com/yourusername/kali-recon-framework/blob/main/LICENSE">
      <img src="https://img.shields.io/github/license/yourusername/kali-recon-framework" alt="License">
    </a>
  </p>
</div>

---

## **requirements.txt**

```txt
# Core Dependencies
requests==2.31.0
beautifulsoup4==4.12.2
dnspython==2.4.2
python-nmap==0.7.1
whois==0.9.28
colorama==0.4.6
tldextract==5.1.1
pyyaml==6.0.1
xmltodict==0.13.0
netifaces==0.11.0

# Advanced Reconnaissance
shodan==1.29.1
censys==2.2.9
virustotal-api==1.1.11
zoomeye==2.3.0
binaryedge==0.0.8
hunterio==0.1.0

# Web Technologies
selenium==4.15.2
playwright==1.40.0
aiohttp==3.9.1
httpx==0.25.2
websockets==12.0
tls-client==0.1.9

# Data Processing & Analysis
pandas==2.1.4
numpy==1.26.2
scipy==1.11.4
scikit-learn==1.3.2
networkx==3.2.1
matplotlib==3.8.2
seaborn==0.13.0
plotly==5.18.0

# Database Support
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
pymongo==4.6.1
redis==5.0.1

# Cloud & Infrastructure
boto3==1.34.9
azure-identity==1.15.0
azure-mgmt-resource==23.1.0
google-cloud-storage==2.13.0
google-cloud-dns==0.36.0
linode-api==4.0
digitalocean==1.38.0

# Security & Cryptography
cryptography==41.0.7
pycryptodome==3.20.0
paramiko==3.4.0
scapy==2.5.0
impacket==0.11.0

# Networking
netaddr==0.9.0
ipaddress==1.0.23
pyasn1==0.5.1
pyasn1-modules==0.3.0

# Utilities
progress==1.6
rich==13.7.0
click==8.1.7
typer==0.9.0
loguru==0.7.2
python-dotenv==1.0.0
pyperclip==1.8.2
psutil==5.9.7

# Reporting
Jinja2==3.1.2
markdown==3.5.2
pdfkit==1.0.0
xlsxwriter==3.1.9
python-pptx==0.6.23

# Testing & Development
pytest==7.4.3
pytest-cov==4.1.0
pytest-asyncio==0.21.1
pytest-xdist==3.5.0
black==23.11.0
flake8==6.1.0
mypy==1.7.1
pre-commit==3.5.0

# Optional Dependencies
# Uncomment for additional functionality

# OCR & Image Processing
# pytesseract==0.3.10
# opencv-python==4.8.1.78
# pillow==10.1.0

# PDF & Document Processing
# pypdf2==3.0.1
# pdfplumber==0.10.3
# docx2txt==0.8

# Machine Learning
# tensorflow==2.15.0
# torch==2.1.1
# transformers==4.36.2
# spacy==3.7.2

# Geospatial
# geopandas==0.14.1
# folium==0.14.0
# geopy==2.4.0

# Performance
# uvloop==0.19.0
# aiodns==3.1.1
# aiomultiprocess==0.9.0

# GUI (Optional)
# tkinter  # Usually comes with Python
# pyqt6==6.6.1
# customtkinter==5.2.1
```

## **requirements-full.txt** (Complete Dependency List)

```txt
# ======================
# KALI RECON FRAMEWORK
# Complete Requirements
# ======================

# Version: 2.0.0
# Last Updated: 2024-01-15

# ===== CORE FRAMEWORK =====
requests==2.31.0
beautifulsoup4==4.12.2
dnspython==2.4.2
python-nmap==0.7.1
whois==0.9.28
colorama==0.4.6
tldextract==5.1.1
pyyaml==6.0.1
xmltodict==0.13.0
netifaces==0.11.0

# ===== NETWORK & SECURITY =====
scapy==2.5.0
paramiko==3.4.0
impacket==0.11.0
netaddr==0.9.0
pyasn1==0.5.1
pyasn1-modules==0.3.0
cryptography==41.0.7
pycryptodome==3.20.0

# ===== RECONNAISSANCE APIS =====
shodan==1.29.1
censys==2.2.9
virustotal-api==1.1.11
zoomeye==2.3.0
binaryedge==0.0.8
hunterio==0.1.0
greynoise==1.2.2
securitytrails==1.0.5
fullhunt==0.1.0

# ===== WEB TECHNOLOGIES =====
selenium==4.15.2
playwright==1.40.0
aiohttp==3.9.1
httpx==0.25.2
websockets==12.0
tls-client==0.1.9
urllib3==2.1.0

# ===== DATA PROCESSING =====
pandas==2.1.4
numpy==1.26.2
scipy==1.11.4
scikit-learn==1.3.2
networkx==3.2.1
matplotlib==3.8.2
seaborn==0.13.0
plotly==5.18.0
wordcloud==1.9.3

# ===== DATABASES =====
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
pymongo==4.6.1
redis==5.0.1
elasticsearch==8.11.1

# ===== CLOUD PLATFORMS =====
boto3==1.34.9
azure-identity==1.15.0
azure-mgmt-resource==23.1.0
azure-mgmt-network==25.1.0
google-cloud-storage==2.13.0
google-cloud-dns==0.36.0
google-cloud-compute==1.14.0
linode-api==4.0
digitalocean==1.38.0
ovh==1.0.0

# ===== UTILITIES =====
progress==1.6
rich==13.7.0
click==8.1.7
typer==0.9.0
loguru==0.7.2
python-dotenv==1.0.0
pyperclip==1.8.2
psutil==5.9.7
humanize==4.8.0
python-dateutil==2.8.2
pytz==2023.3.post1
tzlocal==5.2

# ===== REPORTING =====
Jinja2==3.1.2
markdown==3.5.2
pdfkit==1.0.0
xlsxwriter==3.1.9
python-pptx==0.6.23
reportlab==4.0.4
weasyprint==61.2

# ===== ADVANCED FEATURES =====
# OCR & Image Processing
pytesseract==0.3.10
opencv-python==4.8.1.78
pillow==10.1.0
imageio==2.33.1

# Document Processing
pypdf2==3.0.1
pdfplumber==0.10.3
docx2txt==0.8
python-pptx==0.6.23
xlrd==2.0.1

# Machine Learning
tensorflow==2.15.0
torch==2.1.1
transformers==4.36.2
spacy==3.7.2
nltk==3.8.1
gensim==4.3.2

# Natural Language Processing
spacy==3.7.2
nltk==3.8.1
gensim==4.3.2
textblob==0.17.1
langdetect==1.0.9

# Geospatial
geopandas==0.14.1
folium==0.14.0
geopy==2.4.0
ipinfo==4.3.0
maxminddb==2.4.0
geoip2==4.8.0

# Performance
uvloop==0.19.0
aiodns==3.1.1
aiomultiprocess==0.9.0
joblib==1.3.2
dask==2023.12.0

# ===== TESTING =====
pytest==7.4.3
pytest-cov==4.1.0
pytest-asyncio==0.21.1
pytest-xdist==3.5.0
pytest-timeout==2.2.0
pytest-mock==3.12.0
hypothesis==6.92.2

# ===== DEVELOPMENT =====
black==23.11.0
flake8==6.1.0
mypy==1.7.1
pre-commit==3.5.0
pylint==3.0.2
bandit==1.7.5
safety==2.3.5
isort==5.12.0
autoflake==2.2.0

# ===== DEPLOYMENT =====
docker==6.1.3
kubernetes==29.0.0
ansible==9.3.0
fabric==3.1.0
paramiko==3.4.0

# ===== MONITORING =====
prometheus-client==0.19.0
statsd==4.0.1
sentry-sdk==1.40.0

# ===== GUI (Optional) =====
customtkinter==5.2.1
pyqt6==6.6.1
tkinter  # Usually comes with Python

# ===== SPECIALIZED =====
# DNS Advanced
dnsrecon==0.10.1
dnstwist==20231214

# Subdomain Enumeration
amass==4.2.0
subfinder==2.6.1

# Vulnerability Scanning
nuclei==3.1.5
nikto==2.5.0

# Web Application Scanning
sqlmap==1.7.12
xsstrike==3.1.5

# Password Testing
hydra==9.5
john==1.9.0

# ===== NOTE: Some packages above may require system dependencies =====
# See setup_tools.sh for complete system package installation
```

## **setup_tools.sh**

```bash
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
```

## **Dockerfile**

```dockerfile
# Kali Recon Framework - Docker Image
# Multi-stage build for production and development

# ===== BUILDER STAGE =====
FROM python:3.11-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libssl-dev \
    libffi-dev \
    python3-dev \
    git \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
COPY requirements-full.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ===== RUNTIME STAGE =====
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    whois \
    dnsutils \
    net-tools \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash recon && \
    mkdir -p /app && \
    chown -R recon:recon /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application files
COPY --chown=recon:recon . /app

WORKDIR /app

# Create necessary directories
RUN mkdir -p /app/results /app/logs /app/config/wordlists && \
    chown -R recon:recon /app/results /app/logs /app/config

# Switch to non-root user
USER recon

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health', timeout=2)" || exit 1

# Default command
CMD ["python", "kali_recon.py", "--help"]

# Labels
LABEL org.label-schema.name="Kali Recon Framework" \
      org.label-schema.description="Advanced Web Reconnaissance Suite" \
      org.label-schema.url="https://github.com/yourusername/kali-recon-framework" \
      org.label-schema.vcs-url="https://github.com/yourusername/kali-recon-framework" \
      org.label-schema.version="2.0.0" \
      org.label-schema.schema-version="1.0" \
      maintainer="Security Team <security@example.com>"
```

This comprehensive setup includes:

1. **Professional README** with installation instructions, usage examples, and documentation
2. **Complete requirements.txt** with all necessary Python packages
3. **Installation scripts** for easy setup on any Linux system
4. **Docker support** for containerized deployment
5. **Configuration management** with YAML files
6. **Comprehensive documentation** structure

The framework is now ready for GitHub and professional use!
