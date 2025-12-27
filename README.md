# ReconBuster v2.0

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.8+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg" alt="Platform">
</p>

```
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
    ║  Version 2.0                                                  ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
```

## Advanced Security Reconnaissance & Penetration Testing Tool

ReconBuster is a comprehensive security testing tool designed for security professionals, bug bounty hunters, and penetration testers. It combines multiple security assessment techniques into a single, powerful tool with both CLI and Web interfaces.

---

## Features

### Core Modules
| Module | Description |
|--------|-------------|
| **403 Bypass** | 150+ techniques to bypass 403 Forbidden responses |
| **Subdomain Enumeration** | Multi-source subdomain discovery (10+ sources) |
| **Directory Fuzzing** | Advanced directory and file discovery |
| **Vulnerability Scanner** | Detection of common web vulnerabilities |

### Advanced Security Modules (NEW in v2.0)
| Module | Description |
|--------|-------------|
| **XSS Scanner** | Cross-Site Scripting detection with multiple payload types |
| **SQL Injection** | Error-based, Boolean-blind, and Time-based SQLi detection |
| **SSRF Scanner** | Server-Side Request Forgery detection |
| **LFI/RFI Scanner** | Local/Remote File Inclusion testing |
| **XXE Scanner** | XML External Entity injection detection |
| **Command Injection** | OS command injection detection |
| **WAF Detection** | Web Application Firewall identification and bypass techniques |
| **Port Scanner** | Async TCP/UDP port scanning with service detection |
| **SSL Analyzer** | SSL/TLS configuration and vulnerability analysis |
| **CMS Detector** | WordPress, Joomla, Drupal detection with version info |
| **API Scanner** | REST/GraphQL API security testing (OWASP API Top 10) |
| **DNS Enumeration** | Zone transfer testing, DNS security analysis |
| **Security Headers** | HTTP security headers analysis |
| **CORS Checker** | CORS misconfiguration detection |

### External Tool Integration
- **Nmap** - Port scanning and service detection
- **Nuclei** - Template-based vulnerability scanning
- **FFuf** - Web fuzzing
- **Subfinder** - Subdomain discovery
- **Httpx** - HTTP probing
- **SQLMap** - SQL injection exploitation
- **WPScan** - WordPress security scanning

### Subdomain Enumeration (10+ Sources)
- Certificate Transparency (crt.sh, CertSpotter)
- DNS Databases (HackerTarget, AlienVault OTX, BufferOver)
- Web Archives (Wayback Machine, URLScan)
- Threat Intelligence (ThreatCrowd)
- DNS Resolution & HTTP Probing
- CNAME Detection for Takeover

### Directory Fuzzing
- Async multi-threaded scanning (50+ threads)
- Multiple file extensions (.php, .html, .js, .txt, etc.)
- Wildcard response detection
- Recursive scanning support
- Admin panel finder
- Smart content filtering

### 403 Bypass (150+ Techniques)
**Header-Based Bypasses:**
- 50+ IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.)
- URL rewrite headers (X-Original-URL, X-Rewrite-URL)
- Host header manipulation
- Method override headers

**Path Manipulation:**
- URL encoding variations (%2e, %252e)
- Path traversal tricks (..;/, /.;/)
- Extension tricks (.json, .html, %00)
- Case manipulation (UPPERCASE, SpongeBob case)

**HTTP Methods:**
- 40+ HTTP methods (GET, POST, PUT, DELETE, WebDAV, etc.)
- Protocol downgrade (HTTP/1.0)
- Fat GET (GET with body)

### Professional Reports
- Beautiful HTML reports with walkthrough
- JSON export for integration
- Attack timeline documentation
- Remediation recommendations
- CVSS scores and CWE references

---

## 🚀 Installation

```bash
# Clone/Navigate to the tool directory
cd ReconBuster

# Install dependencies
pip install -r requirements.txt

# Run Web Interface
python app.py

# Or run CLI
python cli.py -t example.com
```

---

## 💻 Usage

### Web Interface

```bash
python app.py
```

Open your browser to `http://localhost:5000`

### CLI Usage

```bash
# Full scan (all modules)
python cli.py -t example.com

# Only 403 bypass testing
python cli.py -t https://example.com/admin -b

# Subdomain + Directory only
python cli.py -t example.com -s -d

# Custom threads and timeout
python cli.py -t example.com --threads 100 --timeout 15

# Disable report generation
python cli.py -t example.com --no-report
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target domain or URL (required) |
| `-s, --subdomain` | Enable subdomain enumeration |
| `-d, --directory` | Enable directory fuzzing |
| `-b, --bypass` | Enable 403 bypass testing |
| `-v, --vuln` | Enable vulnerability scanning |
| `--threads` | Number of threads (default: 50) |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--no-report` | Disable report generation |
| `-o, --output` | Output directory for reports |

---

## 📖 Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                         TARGET                              │
│                      example.com                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              PHASE 1: Subdomain Enumeration                 │
│  - Certificate Transparency (crt.sh, CertSpotter)           │
│  - DNS Databases (HackerTarget, AlienVault, BufferOver)     │
│  - Web Archives (Wayback Machine)                           │
│  - DNS Resolution & HTTP Probing                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              PHASE 2: Directory Enumeration                 │
│  - Async multi-threaded fuzzing                             │
│  - Extension fuzzing (.php, .html, .js)                     │
│  - Admin panel detection                                    │
│  - 403 Forbidden path collection                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              PHASE 3: 403 Bypass Bruteforce                 │
│  - 50+ Header-based bypasses                                │
│  - 40+ Path manipulation techniques                         │
│  - 40+ HTTP method variations                               │
│  - Combined attack patterns                                 │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              PHASE 4: Vulnerability Scanning                │
│  - Sensitive file detection                                 │
│  - LFI/Directory Traversal testing                          │
│  - Information disclosure                                   │
│  - Security header analysis                                 │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    GENERATE REPORT                          │
│  - HTML report with walkthrough                             │
│  - JSON data export                                         │
│  - Remediation recommendations                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Start a new scan |
| `/api/scan/<id>/status` | GET | Get scan status |
| `/api/scan/<id>/results` | GET | Get scan results |
| `/api/scan/<id>/report` | GET | Download report |
| `/api/quick-bypass` | POST | Quick 403 bypass test |

---

## 📁 Project Structure

```
ReconBuster/
├── app.py                 # Flask web server
├── cli.py                 # CLI interface
├── requirements.txt       # Dependencies
├── README.md              # Documentation
├── modules/
│   ├── __init__.py
│   ├── config.py          # Configuration & payloads
│   ├── utils.py           # Utilities & helpers
│   ├── subdomain.py       # Subdomain enumeration
│   ├── directory.py       # Directory fuzzing
│   ├── bypass403.py       # 403 bypass engine
│   ├── scanner.py         # Vulnerability scanner
│   └── report.py          # Report generator
├── templates/
│   └── index.html         # Web interface
├── wordlists/
│   ├── directories.txt    # Directory wordlist
│   └── subdomains.txt     # Subdomain wordlist
└── reports/               # Generated reports
```

---

## 🛡️ 403 Bypass Techniques Summary

### Headers (50+)
```
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-HTTP-Method-Override: PUT
...
```

### Paths (40+)
```
/{path}%20
/{path}%09
/{path}%00
/{path}/
/{path}//
/.;/{path}
/..;/{path}
/%2e/{path}
/%252e/{path}
/{path}.json
/{path}?
...
```

### Methods (40+)
```
GET, POST, PUT, DELETE, PATCH
HEAD, OPTIONS, TRACE, CONNECT
PROPFIND, MKCOL, COPY, MOVE
LOCK, UNLOCK, SEARCH, REPORT
...
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing only**. Users are responsible for ensuring they have proper authorization before testing any systems. The developers assume no liability for misuse of this tool.

---

## 📜 License

MIT License - See LICENSE file for details.

---

## 🙏 Credits

Built by analyzing and combining techniques from:
- 40XHeaderBypasser
- bye403
- bypass-403
- YA403BT
- subfinder
- Sublist3r
- theHarvester
- dirsearch
- dirstalk
- PayloadsAllTheThings

---

**Made with ❤️ for the Security Community**
