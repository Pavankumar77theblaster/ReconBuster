#!/bin/bash
#
# ReconBuster v3.0 Installation Script
# Installs dependencies and optional Kali tools
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗                ║
║  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║                ║
║  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                ║
║  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                ║
║  ██████╔╝███████╗╚██████╗╚██████╔╝██║ ╚████║                ║
║  ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝                ║
║                                                               ║
║             ReconBuster v3.0 Installation                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running on Kali Linux
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" != "kali" ]]; then
        echo -e "${YELLOW}[!] Warning: Not running on Kali Linux. Some tools may not be available.${NC}"
    fi
fi

echo -e "${GREEN}[+] Installing ReconBuster v3.0...${NC}\n"

# Step 1: Python dependencies
echo -e "${CYAN}[*] Step 1: Installing Python dependencies...${NC}"
if [ -f requirements.txt ]; then
    pip3 install -r requirements.txt --quiet
    echo -e "${GREEN}[✓] Python dependencies installed${NC}"
else
    echo -e "${RED}[-] requirements.txt not found!${NC}"
    exit 1
fi

# Step 2: Additional Python packages for v3.0
echo -e "\n${CYAN}[*] Step 2: Installing v3.0 specific dependencies...${NC}"
pip3 install --quiet PyJWT >/dev/null 2>&1 || echo -e "${YELLOW}[!] PyJWT installation failed (JWT testing may not work)${NC}"
echo -e "${GREEN}[✓] v3.0 dependencies installed${NC}"

# Step 3: Check Kali tools availability
echo -e "\n${CYAN}[*] Step 3: Checking Kali tools availability...${NC}"

check_tool() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}[✓] $1 - installed${NC}"
        return 0
    else
        echo -e "${YELLOW}[✗] $1 - not installed${NC}"
        return 1
    fi
}

# Essential tools
echo -e "${CYAN}Essential tools:${NC}"
check_tool nuclei
check_tool ffuf
check_tool sqlmap
check_tool nikto
check_tool nmap
check_tool amass
check_tool httpx

# Optional tools
echo -e "\n${CYAN}Optional tools:${NC}"
check_tool masscan
check_tool gobuster
check_tool wpscan
check_tool commix
check_tool hydra
check_tool whatweb
check_tool wafw00f
check_tool sslscan

# Step 4: Install missing tools (if on Kali)
if [[ "$ID" == "kali" ]]; then
    echo -e "\n${CYAN}[*] Step 4: Do you want to install missing tools? (y/n)${NC}"
    read -r install_missing

    if [[ "$install_missing" == "y" || "$install_missing" == "Y" ]]; then
        echo -e "${CYAN}[*] Installing missing tools...${NC}"

        # Install via apt
        missing_tools=""
        command -v nuclei &> /dev/null || missing_tools+="nuclei "
        command -v ffuf &> /dev/null || missing_tools+="ffuf "
        command -v sqlmap &> /dev/null || missing_tools+="sqlmap "
        command -v nikto &> /dev/null || missing_tools+="nikto "
        command -v amass &> /dev/null || missing_tools+="amass "
        command -v httpx &> /dev/null || missing_tools+="httpx "
        command -v masscan &> /dev/null || missing_tools+="masscan "
        command -v gobuster &> /dev/null || missing_tools+="gobuster "
        command -v wpscan &> /dev/null || missing_tools+="wpscan "

        if [ -n "$missing_tools" ]; then
            sudo apt update -qq
            sudo apt install -y $missing_tools
            echo -e "${GREEN}[✓] Tools installed${NC}"
        else
            echo -e "${GREEN}[✓] All tools already installed${NC}"
        fi

        # Update Nuclei templates
        if command -v nuclei &> /dev/null; then
            echo -e "${CYAN}[*] Updating Nuclei templates...${NC}"
            nuclei -update-templates >/dev/null 2>&1
            echo -e "${GREEN}[✓] Nuclei templates updated${NC}"
        fi
    fi
else
    echo -e "\n${YELLOW}[!] Skipping tool installation (not on Kali Linux)${NC}"
fi

# Step 5: Set up directories
echo -e "\n${CYAN}[*] Step 5: Setting up directories...${NC}"
mkdir -p /tmp/reconbuster_v3
mkdir -p ~/reconbuster_reports
echo -e "${GREEN}[✓] Directories created${NC}"

# Step 6: Make scripts executable
echo -e "\n${CYAN}[*] Step 6: Making scripts executable...${NC}"
chmod +x reconbuster_v3.py
chmod +x modules/bypass403_v3.py 2>/dev/null || true
chmod +x modules/kali_tools_integration.py 2>/dev/null || true
chmod +x modules/owasp_advanced_scanner.py 2>/dev/null || true
echo -e "${GREEN}[✓] Scripts made executable${NC}"

# Step 7: Create symbolic link (optional)
echo -e "\n${CYAN}[*] Step 7: Create system-wide command? (y/n)${NC}"
echo -e "   This will allow you to run 'reconbuster' from anywhere"
read -r create_link

if [[ "$create_link" == "y" || "$create_link" == "Y" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    sudo ln -sf "$SCRIPT_DIR/reconbuster_v3.py" /usr/local/bin/reconbuster
    echo -e "${GREEN}[✓] Command 'reconbuster' created${NC}"
    echo -e "${CYAN}   You can now run: reconbuster -t https://example.com${NC}"
fi

# Installation complete
echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                               ║${NC}"
echo -e "${GREEN}║          ReconBuster v3.0 Installation Complete!             ║${NC}"
echo -e "${GREEN}║                                                               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}\n"

# Quick start guide
echo -e "${CYAN}Quick Start:${NC}"
echo -e "  ${YELLOW}1.${NC} Basic scan:"
echo -e "     ${GREEN}./reconbuster_v3.py -t https://example.com${NC}"
echo -e ""
echo -e "  ${YELLOW}2.${NC} Quick scan (403 bypass + Nuclei):"
echo -e "     ${GREEN}./reconbuster_v3.py -t https://example.com --quick${NC}"
echo -e ""
echo -e "  ${YELLOW}3.${NC} Full aggressive scan:"
echo -e "     ${GREEN}./reconbuster_v3.py -t https://example.com --aggressive${NC}"
echo -e ""
echo -e "  ${YELLOW}4.${NC} Test individual modules:"
echo -e "     ${GREEN}python3 modules/bypass403_v3.py http://example.com/admin${NC}"
echo -e "     ${GREEN}python3 modules/kali_tools_integration.py https://example.com${NC}"
echo -e "     ${GREEN}python3 modules/owasp_advanced_scanner.py https://example.com${NC}"
echo -e ""
echo -e "${CYAN}Documentation:${NC}"
echo -e "  ${GREEN}cat RECONBUSTER_V3_IMPROVEMENTS.md${NC}"
echo -e ""
echo -e "${CYAN}Reports will be saved to:${NC}"
echo -e "  ${GREEN}/tmp/reconbuster_v3/${NC}"
echo -e ""
echo -e "${YELLOW}Happy Hacking! 🚀${NC}\n"
