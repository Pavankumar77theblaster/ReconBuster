#!/bin/bash
#
# ReconBuster v3.0 - GitHub Push Helper Script
#
# This script helps you push v3.0 to GitHub
# All changes are already committed locally
#

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║         ReconBuster v3.0 - GitHub Push Helper                ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}\n"

echo -e "${GREEN}✅ All changes are already committed locally!${NC}\n"

echo -e "${CYAN}Current commit:${NC}"
git log -1 --oneline
echo ""

echo -e "${CYAN}Files in commit:${NC}"
echo "  - reconbuster_v3.py (Main orchestrator)"
echo "  - modules/bypass403_v3.py (Fixed 403 bypass)"
echo "  - modules/kali_tools_integration.py (Kali tools)"
echo "  - modules/owasp_advanced_scanner.py (OWASP tests)"
echo "  - README_V3.md (User guide)"
echo "  - RECONBUSTER_V3_IMPROVEMENTS.md (Technical docs)"
echo "  - install_v3.sh (Installation script)"
echo "  - + 28 more files"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Choose your push method:${NC}\n"

echo "1. Push via HTTPS (requires GitHub username & personal access token)"
echo "2. Push via SSH (requires SSH key configured)"
echo "3. Install GitHub CLI and authenticate"
echo "4. Show manual instructions"
echo "5. Exit"
echo ""

read -p "Enter your choice (1-5): " choice

case $choice in
    1)
        echo -e "\n${CYAN}Pushing via HTTPS...${NC}"
        echo "You will be prompted for your GitHub credentials."
        echo "Password = Personal Access Token (not your GitHub password!)"
        echo ""
        echo "Get a token from: https://github.com/settings/tokens"
        echo "Required scopes: repo (full control)"
        echo ""
        git push -u origin master
        ;;

    2)
        echo -e "\n${CYAN}Switching to SSH...${NC}"
        git remote set-url origin git@github.com:Pavankumar77theblaster/ReconBuster.git
        echo "Remote URL changed to SSH"
        echo ""
        echo "If you don't have an SSH key, generate one:"
        echo "  ssh-keygen -t ed25519 -C \"your_email@example.com\""
        echo "  cat ~/.ssh/id_ed25519.pub"
        echo "Add the key to GitHub: https://github.com/settings/keys"
        echo ""
        read -p "Press Enter when ready to push..."
        git push -u origin master
        ;;

    3)
        echo -e "\n${CYAN}Installing GitHub CLI...${NC}"
        if command -v apt &> /dev/null; then
            sudo apt update
            sudo apt install -y gh
            echo ""
            echo "Authenticating with GitHub..."
            gh auth login
            echo ""
            echo "Pushing to GitHub..."
            gh repo set-default Pavankumar77theblaster/ReconBuster
            git push -u origin master
        else
            echo "Please install GitHub CLI manually: https://cli.github.com/"
        fi
        ;;

    4)
        echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}Manual Push Instructions:${NC}\n"
        echo "All changes are committed locally. To push to GitHub:"
        echo ""
        echo "OPTION A - Using Personal Access Token (HTTPS):"
        echo "  1. Create a Personal Access Token:"
        echo "     https://github.com/settings/tokens/new"
        echo "     Scopes: repo (full control)"
        echo ""
        echo "  2. Run: git push -u origin master"
        echo "     Username: Pavankumar77theblaster"
        echo "     Password: <paste your token>"
        echo ""
        echo "OPTION B - Using SSH:"
        echo "  1. Generate SSH key (if you don't have one):"
        echo "     ssh-keygen -t ed25519 -C \"your_email@example.com\""
        echo ""
        echo "  2. Add key to GitHub:"
        echo "     cat ~/.ssh/id_ed25519.pub"
        echo "     Copy the output and add it here:"
        echo "     https://github.com/settings/keys"
        echo ""
        echo "  3. Change remote URL:"
        echo "     git remote set-url origin git@github.com:Pavankumar77theblaster/ReconBuster.git"
        echo ""
        echo "  4. Push:"
        echo "     git push -u origin master"
        echo ""
        echo "OPTION C - Using GitHub CLI:"
        echo "  1. Install: sudo apt install gh"
        echo "  2. Authenticate: gh auth login"
        echo "  3. Push: git push -u origin master"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}\n"
        ;;

    5)
        echo "Exiting. You can push later with: git push -u origin master"
        exit 0
        ;;

    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}║    ✅ Successfully pushed ReconBuster v3.0 to GitHub!        ║${NC}"
    echo -e "${GREEN}║                                                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}\n"

    echo -e "${CYAN}View your repository:${NC}"
    echo "  https://github.com/Pavankumar77theblaster/ReconBuster"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "  1. Update README.md on GitHub (merge v3.0 changes)"
    echo "  2. Create a release tag: git tag -a v3.0.0 -m \"v3.0.0\""
    echo "  3. Push tags: git push --tags"
    echo "  4. Create GitHub Release with changelog"
    echo ""
else
    echo -e "\n${YELLOW}Push failed. See error above.${NC}"
    echo "Try running this script again or use manual instructions (option 4)"
fi
