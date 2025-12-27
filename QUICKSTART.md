# ReconBuster v3.0 - Quick Start Guide

## 🚀 Start Here

### Option 1: Web Dashboard (Recommended - Shows All Tools)

```bash
# Install dependencies
pip3 install flask flask-cors flask-socketio --break-system-packages

# Start dashboard
python3 app_v3.py

# Open browser
firefox http://localhost:5000
```

**Features:**
- ✅ Real-time progress updates
- ✅ Live activity log
- ✅ All tool integrations visible
- ✅ Automatic tool chaining visualization
- ✅ Port scanning results in real-time

### Option 2: CLI Quick Scan

```bash
# Quick intelligent scan (403 bypass + Nuclei)
./reconbuster_v3.py -t https://example.com --quick

# Full aggressive scan (all tools, automatic chaining)
./reconbuster_v3.py -t https://example.com --aggressive
```

## 🤖 Intelligent Workflow Examples

### Example 1: Scan a Web Application
```bash
python3 app_v3.py
# In browser: Enter https://example.com
# Check "Use Intelligent Workflow" ✅
# Click "Start Intelligent Scan"
```

**What Happens Automatically:**
1. Scans ports (finds 80, 443, 3306)
2. Port 80 → Triggers: Nuclei, FFuf, 403 Bypass, OWASP tests
3. Port 3306 MySQL → Triggers: SQLMap, Default credentials check
4. If 403 found → Automatically tests 300+ bypass techniques
5. If WordPress detected → Automatically runs WPScan

### Example 2: Test Specific Port Finding
```bash
# Port scanner finds MySQL on 3306
# Automatically triggers:
#   - SQLMap for SQL injection testing
#   - Default credential testing
#   - Database enumeration
#   - If vulnerable: Data extraction
```

## 📊 Dashboard Features

**Real-Time Updates:**
- Progress bar showing scan completion
- Live log of all activities
- Immediate display of discovered ports
- Vulnerabilities categorized by severity (Critical, High, Medium, Low)

**Automatic Tool Chaining:**
- Port discovery → Service detection → Vulnerability testing → Exploitation
- All steps visible in real-time activity log
- WebSocket updates every action

## 🔧 Troubleshooting

### Dashboard Won't Start
```bash
# Install dependencies
pip3 install flask flask-cors flask-socketio --break-system-packages

# Run again
python3 app_v3.py
```

### Port Scanner Not Working
```bash
# Test port scanner module
python3 -c "from modules.port_scanner import PortScanner; print('OK')"

# Should output: OK
```

### No Tools Visible
- Make sure "Use Intelligent Workflow" checkbox is ✅ checked
- Check browser console for errors (F12)
- Verify WebSocket connection (should see "Connected to ReconBuster server")

## 📖 Full Documentation

- **INTELLIGENT_WORKFLOW_GUIDE.md** - Complete workflow documentation
- **README_V3.md** - Full feature list and examples
- **RECONBUSTER_V3_IMPROVEMENTS.md** - Technical details

## ⚡ Key Commands

```bash
# Web dashboard
python3 app_v3.py

# CLI quick scan
./reconbuster_v3.py -t https://example.com --quick

# CLI aggressive scan
./reconbuster_v3.py -t https://example.com --aggressive

# Test individual modules
python3 modules/bypass403_v3.py "https://example.com/admin"
python3 modules/kali_tools_integration.py "https://example.com"
python3 modules/owasp_advanced_scanner.py "https://example.com/api"
```

## 🎯 What Makes v3.0 Intelligent

**Automatic Decision Making:**
- Discovers port → Identifies service → Runs appropriate tool → Exploits if possible
- No manual intervention needed
- Continuous vulnerability discovery loop

**Examples:**
- Port 80 found → "This is web, run Nuclei and FFuf"
- MySQL on 3306 → "This is database, run SQLMap"
- WordPress detected → "This is WP, run WPScan"
- 403 error found → "Test bypass techniques"

All automatic. All real-time. All visible in the dashboard.

---

**Ready to start? Run:** `python3 app_v3.py`

**Then open:** http://localhost:5000

**That's it!** 🚀
