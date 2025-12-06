"""
ReconBuster Configuration
Advanced Security Reconnaissance Tool
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent

@dataclass
class ScanConfig:
    """Main scan configuration"""
    target: str = ""
    threads: int = 50
    timeout: int = 10
    delay: float = 0.0
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    follow_redirects: bool = True
    verify_ssl: bool = False
    proxy: Optional[str] = None

    # Module toggles
    enable_subdomain: bool = True
    enable_directory: bool = True
    enable_bypass403: bool = True
    enable_vuln_scan: bool = True

    # Output
    output_dir: str = str(BASE_DIR / "reports")
    generate_pdf: bool = True

# User-Agent rotation list
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

# 403 Bypass Headers - Comprehensive list from all analyzed tools
BYPASS_HEADERS = [
    # IP Spoofing Headers
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Forwarded-For": "127.0.0.1, 127.0.0.2"},
    {"X-Forwarded-For": "127.0.0.1:80"},
    {"X-Forwarded-For": "127.0.0.1:443"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Cluster-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"Forwarded-For": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1;proto=http;by=127.0.0.1"},
    {"X-Forwarded": "127.0.0.1"},

    # Alternative IP formats
    {"X-Forwarded-For": "2130706433"},  # Decimal
    {"X-Forwarded-For": "0x7F000001"},  # Hex
    {"X-Forwarded-For": "0177.0000.0000.0001"},  # Octal
    {"X-Forwarded-For": "127.1"},
    {"X-Forwarded-For": "0"},
    {"X-Forwarded-For": "0.0.0.0"},

    # Private IP ranges
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "172.16.0.1"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Forwarded-For": "192.168.0.1"},

    # Host manipulation
    {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-Server": "127.0.0.1"},
    {"X-Original-Host": "127.0.0.1"},

    # URL Rewriting
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Override-URL": "/"},
    {"X-HTTP-DestinationURL": "/"},

    # Protocol/Scheme
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Port": "80"},

    # Method Override
    {"X-HTTP-Method-Override": "GET"},
    {"X-HTTP-Method-Override": "PUT"},
    {"X-HTTP-Method-Override": "POST"},
    {"X-Method-Override": "GET"},

    # Misc headers
    {"X-Requested-With": "XMLHttpRequest"},
    {"Content-Length": "0"},
    {"X-Original-URL": "x]"},
    {"Referer": "/"},
]

# Path manipulation payloads for 403 bypass
PATH_BYPASSES = [
    # Prefix manipulations
    "/%2e{path}",
    "/{path}/.",
    "//{path}//",
    "/./{path}/./",
    "/{path}%20",
    "/{path}%09",
    "/{path}%00",
    "/{path}..;/",
    "/{path};/",
    "/{path}?",
    "/{path}??",
    "/{path}???",
    "/{path}#",
    "/{path}.html",
    "/{path}.json",
    "/{path}.php",
    "/{path}/",
    "/{path}//",

    # URL encoding variations
    "/%252e/{path}",
    "/%252e%252e/{path}",
    "/{path}%252f",
    "/{path}%252f/",

    # Case manipulation
    "/{PATH}",  # Uppercase

    # Semicolon injection
    "/{path};foo=bar",
    "/;/{path}",
    "/.;/{path}",
    "//;/{path}",

    # Double URL encoding
    "/%2e%2e/{path}",
    "/{path}%2f%2f",

    # Unicode/UTF-8 tricks
    "/%ef%bc%8f{path}",

    # Dot variations
    "/{path}./",
    "/{path}../",
    "/../{path}",
    "/..%00/{path}",
    "/..%0d/{path}",
    "/..%5c{path}",
    "/..%ff/{path}",
    "/%2e%2e%2f{path}",

    # Extension tricks
    "/{path}.css",
    "/{path}.ico",
    "/{path}.js",
    "/{path}....json",
    "/{path}%00.json",

    # Query string tricks
    "/{path}?anything",
    "/{path}#anything",
    "/{path}?.css",
    "/{path}?debug=1",

    # Wildcard/Special chars
    "/{path}~",
    "/{path}@",
    "/{path}*",
]

# HTTP Methods to try for bypass
HTTP_METHODS = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "TRACE",
    "CONNECT",
    # WebDAV methods
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "SEARCH",
    "REPORT",
    # Custom methods
    "FOOBAR",
]

# Protocol variations
PROTOCOL_TRICKS = [
    {"version": "HTTP/1.0"},
    {"version": "HTTP/2"},
]

# Common directories to enumerate
DEFAULT_DIRECTORIES = [
    "admin", "administrator", "login", "dashboard", "panel",
    "api", "v1", "v2", "internal", "private", "secret",
    "backup", "backups", "config", "conf", "settings",
    "upload", "uploads", "files", "documents", "docs",
    "test", "testing", "dev", "development", "staging",
    "debug", "phpinfo", "server-status", "server-info",
    ".git", ".svn", ".env", ".htaccess", ".htpasswd",
    "wp-admin", "wp-content", "wp-includes",
    "phpmyadmin", "adminer", "manager", "console",
    "cgi-bin", "scripts", "includes", "inc",
    "assets", "static", "media", "images", "css", "js",
    "xmlrpc.php", "robots.txt", "sitemap.xml",
]

# Status codes
STATUS_SUCCESS = [200, 201, 202, 204]
STATUS_REDIRECT = [301, 302, 303, 307, 308]
STATUS_FORBIDDEN = [401, 403]
STATUS_NOT_FOUND = [404]
STATUS_SERVER_ERROR = [500, 501, 502, 503, 504]

# Colors for terminal output
COLORS = {
    "success": "\033[92m",      # Green
    "warning": "\033[93m",      # Yellow
    "error": "\033[91m",        # Red
    "info": "\033[94m",         # Blue
    "cyan": "\033[96m",         # Cyan
    "reset": "\033[0m",         # Reset
    "bold": "\033[1m",          # Bold
}

# Subdomain sources configuration
SUBDOMAIN_SOURCES = {
    "crtsh": {
        "url": "https://crt.sh/?q=%.{domain}&output=json",
        "type": "api",
        "enabled": True
    },
    "hackertarget": {
        "url": "https://api.hackertarget.com/hostsearch/?q={domain}",
        "type": "api",
        "enabled": True
    },
    "threatcrowd": {
        "url": "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
        "type": "api",
        "enabled": True
    },
    "alienvault": {
        "url": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        "type": "api",
        "enabled": True
    },
    "urlscan": {
        "url": "https://urlscan.io/api/v1/search/?q=domain:{domain}",
        "type": "api",
        "enabled": True
    },
    "rapiddns": {
        "url": "https://rapiddns.io/subdomain/{domain}?full=1",
        "type": "scrape",
        "enabled": True
    },
    "bufferover": {
        "url": "https://dns.bufferover.run/dns?q=.{domain}",
        "type": "api",
        "enabled": True
    },
    "webarchive": {
        "url": "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey",
        "type": "api",
        "enabled": True
    }
}

# Verification methods
VERIFICATION_METHODS = {
    "dns_resolve": True,
    "http_probe": True,
    "port_scan": False,
}
