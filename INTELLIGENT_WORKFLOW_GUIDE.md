# ReconBuster v3.0 - Intelligent Workflow Guide

## Overview

The Intelligent Workflow System automatically chains security tools based on discovered findings, creating a continuous vulnerability discovery process.

## How It Works

```
Port Scan → Service Detection → Targeted Vulnerability Testing → Exploitation
```

### Automatic Tool Chaining Examples

1. **Web Services Discovered (Ports 80, 443, 8080, 8443)**
   ```
   Port 80 Open → WAF Detection → Nuclei Scan → Directory Fuzzing (FFuf)
                → If 403 Found: Test Bypass Techniques → OWASP Advanced Tests
   ```

2. **Database Services (MySQL, PostgreSQL)**
   ```
   Port 3306 MySQL → SQLMap Injection Test → Default Credentials Check
                   → Database Enumeration → Data Extraction
   ```

3. **Redis Service**
   ```
   Port 6379 Redis → RCE Vulnerability Check → Unauthorized Access Test
   ```

4. **CMS Detection**
   ```
   WordPress Detected → WPScan → Plugin Enumeration → Theme Vulnerabilities
   ```

## Usage

### Web Dashboard (Recommended)

```bash
# Install dependencies
pip3 install flask flask-cors flask-socketio --break-system-packages

# Start the v3.0 dashboard
python3 app_v3.py

# Open browser to: http://localhost:5000
```

**Dashboard Features:**
- ✅ Real-time progress bar
- ✅ Live activity log via WebSocket
- ✅ Automatic tool chaining visualization
- ✅ Severity-based finding categorization
- ✅ One-click report download

### CLI Interface

```bash
# Quick intelligent scan
./reconbuster_v3.py -t https://example.com --quick

# Full aggressive scan with automatic tool chaining
./reconbuster_v3.py -t https://example.com --aggressive

# Custom options
./reconbuster_v3.py -t https://example.com \
  --threads 50 \
  --timeout 15 \
  --nuclei-severity critical,high \
  --sqlmap-risk 2
```

## Intelligent Workflow Features

### 1. Port-Based Triggers

| Port | Service | Automatic Tools Triggered |
|------|---------|---------------------------|
| 80, 443 | HTTP/HTTPS | Nuclei, FFuf, 403 Bypass, OWASP Scanner |
| 3306 | MySQL | SQLMap, Default Creds, DB Enumeration |
| 5432 | PostgreSQL | SQLMap, Default Creds |
| 6379 | Redis | RCE Check, Unauthorized Access Test |
| 22 | SSH | Banner Check, Weak Ciphers Detection |
| 21 | FTP | Anonymous Login Test, Version Check |

### 2. Finding-Based Triggers

| Finding | Next Action |
|---------|-------------|
| 403 Forbidden | 300+ bypass techniques with v3.0 validation |
| WordPress CMS | WPScan with plugin enumeration |
| Login Form | CSRF test, credential stuffing check |
| File Upload | Malicious extension testing |
| JWT Token | Algorithm confusion, weak secret tests |

### 3. Service-Specific Testing

```python
# Example: MySQL on Port 3306 triggers:
- SQLMap with risk=2, level=2
- Default credential testing (root:root, root:password)
- Database enumeration
- If vulnerable: Automatic data extraction
```

## WebSocket Real-Time Updates

The dashboard receives live updates:

```javascript
// Progress updates
socket.on('progress', (data) => {
    // Shows: "Testing port 3306 for SQL injection..."
});

// Findings discovered
socket.on('ports_found', (data) => {
    // Displays discovered open ports immediately
});

// Phase transitions
socket.on('phase_started', (data) => {
    // Shows: "Running Nuclei vulnerability scanner"
});
```

## API Endpoints

### Start Scan
```bash
POST /api/scan/start
{
  "target": "https://example.com",
  "intelligent_workflow": true,
  "threads": 50,
  "timeout": 10
}
```

### Get Status
```bash
GET /api/scan/<scan_id>/status
```

### Get Results
```bash
GET /api/scan/<scan_id>/results
```

### Download Report
```bash
GET /api/scan/<scan_id>/download
```

## Workflow Configuration

The intelligent workflow can be customized in `modules/intelligent_workflow.py`:

```python
# Add custom triggers
def _get_triggers_for_port(self, port: PortResult) -> List[str]:
    triggers = []

    # Add your custom logic
    if port.service == "custom_service":
        triggers.append("custom_tool")

    return triggers
```

## Technical Architecture

```
┌─────────────────────────────────────────────┐
│         IntelligentWorkflow                  │
│  (modules/intelligent_workflow.py)          │
└──────────────┬──────────────────────────────┘
               │
               ├──► Phase 1: Port Scanning
               │    └─► PortScanner with banner grab
               │
               ├──► Phase 2: Service Testing
               │    ├─► Web: WAF, Nuclei, FFuf
               │    ├─► DB: SQLMap, Default Creds
               │    └─► Other: Service-specific tests
               │
               ├──► Phase 3: Vulnerability Discovery
               │    ├─► 403 Bypass (v3.0 fixed logic)
               │    ├─► OWASP Advanced (JWT, IDOR, CSRF)
               │    └─► CMS-specific (WPScan, etc.)
               │
               └──► Phase 4: Report Generation
                    └─► JSON + HTML with findings
```

## Key Improvements Over v2.0

| Feature | v2.0 | v3.0 |
|---------|------|------|
| Tool Chaining | ❌ Manual | ✅ Automatic |
| Port → Service Mapping | ❌ None | ✅ Intelligent |
| Real-time Updates | ❌ None | ✅ WebSocket |
| False Positives (403) | ⚠️ ~30% | ✅ ~2% |
| Workflow Orchestration | ❌ Sequential | ✅ Intelligent |
| Finding-based Actions | ❌ None | ✅ Automatic |

## Example Workflow Execution

```bash
Target: https://example.com

[00:01] Starting intelligent workflow...
[00:02] Phase 1: Port scanning
[00:05] ✅ Found 5 open ports: 22, 80, 443, 3306, 6379
[00:06] 🤖 Port 80 detected → Triggering: nuclei_web, ffuf_directory, bypass_403
[00:07] 🤖 Port 3306 MySQL → Triggering: sqlmap, database_test, default_creds
[00:08] 🤖 Port 6379 Redis → Triggering: redis_rce_check
[00:10] Phase 2: Running Nuclei on http://example.com
[00:25] ✅ Nuclei: Found 12 vulnerabilities (2 critical, 5 high)
[00:26] Phase 3: Running FFuf directory fuzzing
[00:40] ✅ FFuf: Found 150 endpoints
[00:41] 🤖 Found /admin → 403 Forbidden → Triggering 403 bypass tests
[00:50] Phase 4: Testing 403 bypass techniques
[01:20] ✅ 403 Bypass: Found 3 valid bypasses (v3.0 validation)
[01:21] Phase 5: Running SQLMap on MySQL (port 3306)
[02:10] ✅ SQLMap: Found SQL injection in parameter 'id'
[02:15] Phase 6: Checking Redis for RCE
[02:20] ✅ Redis: Unauthorized access possible
[02:25] Scan complete! Total: 25 findings (3 critical, 8 high, 10 medium, 4 low)
[02:26] Report saved: /tmp/reconbuster_v3/scan_<id>.json
```

## Troubleshooting

### Port Scanner Not Working
```bash
# Verify port_scanner.py is working
python3 -c "from modules.port_scanner import PortScanner; print('OK')"
```

### WebSocket Not Connecting
```bash
# Check Flask-SocketIO is installed
pip3 install flask-socketio --break-system-packages

# Verify server is running
curl http://localhost:5000
```

### Tools Not Visible in Dashboard
- Ensure intelligent_workflow checkbox is enabled
- Check browser console for JavaScript errors
- Verify WebSocket connection (should see "Connected to ReconBuster server")

## Advanced Usage

### Custom Workflow Script

```python
from modules.intelligent_workflow import IntelligentWorkflow
import asyncio

async def custom_scan():
    workflow = IntelligentWorkflow(
        target="https://example.com",
        config={
            "threads": 50,
            "timeout": 10,
            "enable_exploitation": True
        }
    )

    report = await workflow.run()
    print(f"Found {report['total_findings']} vulnerabilities")

asyncio.run(custom_scan())
```

## Security Notes

⚠️ **IMPORTANT:** This tool is for authorized testing only!

- Only use on systems you own or have permission to test
- The intelligent workflow will automatically attempt exploitation
- SQLMap and other tools may modify target systems
- Always review findings before reporting

## Contributing

To add new tools to the intelligent workflow:

1. Edit `modules/intelligent_workflow.py`
2. Add tool integration in `_test_<service>_service()` methods
3. Define triggers in `_get_triggers_for_port()`
4. Test with sample target
5. Submit PR

## Support

- 🐛 Issues: https://github.com/Pavankumar77theblaster/ReconBuster/issues
- 📖 Docs: See README_V3.md and RECONBUSTER_V3_IMPROVEMENTS.md
- 💬 Discussions: https://github.com/Pavankumar77theblaster/ReconBuster/discussions

---

**ReconBuster v3.0 - Where Intelligence Meets Automation** 🤖

*Built on 2025-12-27*
