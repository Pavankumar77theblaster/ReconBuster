#!/bin/bash

# ReconBuster Installation Script for Kali Linux / Debian / Ubuntu
# Advanced Security Reconnaissance & 403 Bypass Tool

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ██╗   ██╗ ║
    ║  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║   ██║ ║
    ║  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╔╝██║   ██║ ║
    ║  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██╗██║   ██║ ║
    ║  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝╚██████╔╝ ║
    ║  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝  ╚═════╝  ║
    ║                                                               ║
    ║  Advanced Security Reconnaissance & 403 Bypass Tool           ║
    ║  Installation Script v1.0                                     ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[!] This script should be run with sudo for best results${NC}"
    echo -e "${YELLOW}[!] Some features may not install without root privileges${NC}"
fi

echo -e "${GREEN}[*] Starting ReconBuster installation...${NC}"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VERSION=$VERSION_ID
else
    OS=$(uname -s)
fi

echo -e "${BLUE}[+] Detected OS: $OS${NC}"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Update package lists
echo -e "${BLUE}[+] Updating package lists...${NC}"
if command -v apt-get &> /dev/null; then
    sudo apt-get update -qq
elif command -v yum &> /dev/null; then
    sudo yum check-update -q || true
fi

# Install Python3 and pip
echo -e "${BLUE}[+] Installing Python3 and pip...${NC}"
if command -v apt-get &> /dev/null; then
    sudo apt-get install -y python3 python3-pip python3-venv -qq
elif command -v yum &> /dev/null; then
    sudo yum install -y python3 python3-pip -q
elif command -v pacman &> /dev/null; then
    sudo pacman -S --noconfirm python python-pip
fi

# Create virtual environment
echo -e "${BLUE}[+] Creating virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo -e "${BLUE}[+] Upgrading pip...${NC}"
pip install --upgrade pip -q

# Install Python requirements
echo -e "${BLUE}[+] Installing Python dependencies...${NC}"
pip install -r requirements.txt -q

# Install additional security tools (optional)
echo -e "${YELLOW}[?] Do you want to install additional security tools? (nmap, nuclei, ffuf, etc.) [y/N]${NC}"
read -r INSTALL_TOOLS

if [[ "$INSTALL_TOOLS" =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[+] Installing additional security tools...${NC}"

    # Install nmap
    if ! command -v nmap &> /dev/null; then
        echo -e "${BLUE}    Installing nmap...${NC}"
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y nmap -qq
        elif command -v yum &> /dev/null; then
            sudo yum install -y nmap -q
        fi
    else
        echo -e "${GREEN}    nmap already installed${NC}"
    fi

    # Install nuclei
    if ! command -v nuclei &> /dev/null; then
        echo -e "${BLUE}    Installing nuclei...${NC}"
        if command -v go &> /dev/null; then
            go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
        else
            # Download binary
            NUCLEI_VERSION="v3.1.0"
            wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" -O /tmp/nuclei.zip 2>/dev/null || true
            if [ -f /tmp/nuclei.zip ]; then
                unzip -q /tmp/nuclei.zip -d /tmp/
                sudo mv /tmp/nuclei /usr/local/bin/
                rm /tmp/nuclei.zip
            fi
        fi
    else
        echo -e "${GREEN}    nuclei already installed${NC}"
    fi

    # Install ffuf
    if ! command -v ffuf &> /dev/null; then
        echo -e "${BLUE}    Installing ffuf...${NC}"
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y ffuf -qq 2>/dev/null || {
                # Download binary if not in repos
                FFUF_VERSION="v2.1.0"
                wget -q "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION#v}_linux_amd64.tar.gz" -O /tmp/ffuf.tar.gz 2>/dev/null || true
                if [ -f /tmp/ffuf.tar.gz ]; then
                    tar -xzf /tmp/ffuf.tar.gz -C /tmp/
                    sudo mv /tmp/ffuf /usr/local/bin/
                    rm /tmp/ffuf.tar.gz
                fi
            }
        fi
    else
        echo -e "${GREEN}    ffuf already installed${NC}"
    fi

    # Install subfinder
    if ! command -v subfinder &> /dev/null; then
        echo -e "${BLUE}    Installing subfinder...${NC}"
        if command -v go &> /dev/null; then
            go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
        fi
    else
        echo -e "${GREEN}    subfinder already installed${NC}"
    fi

    # Install httpx
    if ! command -v httpx &> /dev/null; then
        echo -e "${BLUE}    Installing httpx...${NC}"
        if command -v go &> /dev/null; then
            go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
        fi
    else
        echo -e "${GREEN}    httpx already installed${NC}"
    fi

    # Install gobuster
    if ! command -v gobuster &> /dev/null; then
        echo -e "${BLUE}    Installing gobuster...${NC}"
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y gobuster -qq 2>/dev/null || true
        fi
    else
        echo -e "${GREEN}    gobuster already installed${NC}"
    fi

    # Download SecLists wordlists
    if [ ! -d "/usr/share/seclists" ]; then
        echo -e "${BLUE}    Downloading SecLists wordlists...${NC}"
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y seclists -qq 2>/dev/null || {
                sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>/dev/null || true
            }
        fi
    else
        echo -e "${GREEN}    SecLists already installed${NC}"
    fi
fi

# Create symbolic link
echo -e "${BLUE}[+] Creating symbolic link...${NC}"
if [ ! -f "/usr/local/bin/reconbuster" ]; then
    sudo ln -sf "$SCRIPT_DIR/reconbuster" /usr/local/bin/reconbuster 2>/dev/null || true
fi

# Create the reconbuster launcher script
echo -e "${BLUE}[+] Creating launcher script...${NC}"
cat > reconbuster << 'LAUNCHER'
#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"
source venv/bin/activate
python cli.py "$@"
LAUNCHER
chmod +x reconbuster

# Create web launcher
cat > reconbuster-web << 'WEBLAUNCHER'
#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"
source venv/bin/activate
python app.py
WEBLAUNCHER
chmod +x reconbuster-web

# Make scripts executable
chmod +x cli.py 2>/dev/null || true
chmod +x app.py 2>/dev/null || true

# Create reports directory
mkdir -p reports

# Completion message
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}[✓] ReconBuster installation completed successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}Usage:${NC}"
echo -e "  ${YELLOW}CLI Mode:${NC}"
echo -e "    ./reconbuster --help"
echo -e "    ./reconbuster -t example.com --full"
echo ""
echo -e "  ${YELLOW}Web Interface:${NC}"
echo -e "    ./reconbuster-web"
echo -e "    Then open: http://localhost:5000"
echo ""
echo -e "  ${YELLOW}Quick 403 Bypass:${NC}"
echo -e "    ./reconbuster -t https://example.com/admin --bypass-only"
echo ""
echo -e "${CYAN}Documentation:${NC}"
echo -e "  https://github.com/yourusername/ReconBuster"
echo ""
echo -e "${RED}[!] Use responsibly. Only test on targets you have permission to test.${NC}"
echo ""
