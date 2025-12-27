"""
ReconBuster Vulnerability Scanner Module
Active scanning for common vulnerabilities after 403 bypass
"""

import asyncio
import aiohttp
import re
import hashlib
from typing import List, Dict, Set, Callable, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, quote
from .utils import AsyncHTTPClient, normalize_url, USER_AGENTS
import random

@dataclass
class VulnerabilityResult:
    """Represents a discovered vulnerability"""
    url: str
    vuln_type: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: str
    payload: str = ""
    request: str = ""
    response: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss: float = 0.0
    timestamp: str = ""
    verified: bool = False


class VulnerabilityScanner:
    """
    Active vulnerability scanner
    Scans for:
    - Directory Traversal / LFI
    - Information Disclosure
    - Sensitive File Exposure
    - Server Misconfigurations
    - Default Credentials
    - Technology Detection
    """

    # Sensitive files to check
    SENSITIVE_FILES = [
        # Configuration files
        ".env", ".env.local", ".env.production", ".env.development",
        "config.php", "config.inc.php", "configuration.php",
        "settings.php", "settings.py", "config.py", "config.yml",
        "config.json", "config.xml", "config.ini",
        "database.yml", "database.php", "db.php",
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        "web.config", "applicationhost.config",

        # Backup files
        "backup.sql", "backup.zip", "backup.tar.gz",
        "database.sql", "db.sql", "dump.sql",
        "site.zip", "www.zip", "html.zip",
        ".bak", "old", ".old", ".backup",

        # Version control
        ".git/config", ".git/HEAD", ".git/index",
        ".svn/entries", ".svn/wc.db",
        ".hg/hgrc", ".bzr/README",

        # Server files
        ".htaccess", ".htpasswd", "htpasswd",
        "server-status", "server-info",
        "phpinfo.php", "info.php", "test.php",
        "debug.php", "install.php", "setup.php",

        # Log files
        "error.log", "access.log", "debug.log",
        "logs/error.log", "log/error.log",
        "var/log/apache2/error.log",

        # API/Documentation
        "swagger.json", "swagger.yaml", "openapi.json",
        "api-docs", "api/docs", "docs/api",
        "graphql", "graphiql",

        # IDE/Editor files
        ".idea/workspace.xml", ".vscode/settings.json",
        ".DS_Store", "Thumbs.db",

        # Package managers
        "package.json", "package-lock.json",
        "composer.json", "composer.lock",
        "Gemfile", "Gemfile.lock",
        "requirements.txt", "Pipfile",

        # Credentials
        "credentials.json", "credentials.xml",
        "secrets.json", "secrets.yml",
        "id_rsa", "id_rsa.pub", ".ssh/id_rsa",
    ]

    # LFI Payloads
    LFI_PAYLOADS = [
        # Linux files
        ("../../../../../../../etc/passwd", "root:"),
        ("....//....//....//....//....//etc/passwd", "root:"),
        ("..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd", "root:"),
        ("..%252f..%252f..%252f..%252fetc/passwd", "root:"),
        ("/etc/passwd", "root:"),
        ("file:///etc/passwd", "root:"),

        # Windows files
        ("../../../../../../../windows/win.ini", "[fonts]"),
        ("....//....//....//windows/win.ini", "[fonts]"),
        ("..%5c..%5c..%5c..%5cwindows/win.ini", "[fonts]"),
        ("C:/windows/win.ini", "[fonts]"),
        ("C:\\windows\\win.ini", "[fonts]"),

        # Application files
        ("../../../../../../../var/www/html/index.php", "<?php"),
        ("....//....//....//var/www/html/index.php", "<?php"),
    ]

    # SSRF Payloads for internal access
    SSRF_PAYLOADS = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:6379/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://2130706433/",  # 127.0.0.1 decimal
    ]

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 20, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout

        parsed = urlparse(self.target)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.host = parsed.netloc

        self.vulnerabilities: List[VulnerabilityResult] = []
        self.technologies: Dict[str, str] = {}
        self.headers_info: Dict = {}

        self.stats = {
            "total_checks": 0,
            "vulnerabilities_found": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def scan(self) -> List[VulnerabilityResult]:
        """Main scanning method"""
        await self.emit("status", {
            "message": f"Starting vulnerability scan on {self.target}"
        })

        # Run all scan modules
        await asyncio.gather(
            self._scan_sensitive_files(),
            self._scan_directory_traversal(),
            self._scan_information_disclosure(),
            self._scan_misconfigurations(),
            self._detect_technologies(),
            return_exceptions=True
        )

        # Calculate stats
        for vuln in self.vulnerabilities:
            self.stats["vulnerabilities_found"] += 1
            self.stats[vuln.severity] = self.stats.get(vuln.severity, 0) + 1

        await self.emit("scan_complete", {
            "vulnerabilities": [v.__dict__ for v in self.vulnerabilities],
            "technologies": self.technologies,
            "stats": self.stats
        })

        return self.vulnerabilities

    def _add_vulnerability(self, vuln: VulnerabilityResult):
        """Add vulnerability and emit event"""
        self.vulnerabilities.append(vuln)
        asyncio.create_task(self.emit("vulnerability_found", vuln.__dict__))

    async def _scan_sensitive_files(self):
        """Scan for sensitive files"""
        await self.emit("status", {"message": "Scanning for sensitive files..."})

        semaphore = asyncio.Semaphore(self.threads)

        async def check_file(file_path: str):
            async with semaphore:
                self.stats["total_checks"] += 1
                url = f"{self.base_url}/{file_path}"

                async with AsyncHTTPClient(timeout=self.timeout) as client:
                    result = await client.get(url)

                    if result and result.status_code == 200:
                        # Verify it's not a generic 200 response
                        if result.response_length > 0:
                            severity = self._classify_file_severity(file_path)

                            vuln = VulnerabilityResult(
                                url=url,
                                vuln_type="sensitive_file_exposure",
                                severity=severity,
                                title=f"Sensitive File Exposed: {file_path}",
                                description=f"The file '{file_path}' is publicly accessible and may contain sensitive information.",
                                evidence=f"Status: {result.status_code}, Size: {result.response_length} bytes",
                                remediation="Remove or restrict access to sensitive files. Use .htaccess or web server configuration to deny access.",
                                cwe="CWE-538"
                            )
                            self._add_vulnerability(vuln)

        tasks = [check_file(f) for f in self.SENSITIVE_FILES]
        await asyncio.gather(*tasks, return_exceptions=True)

    def _classify_file_severity(self, file_path: str) -> str:
        """Classify severity based on file type"""
        critical_files = [".env", "credentials", "secrets", "id_rsa", ".htpasswd", "wp-config"]
        high_files = [".git", ".svn", "backup", "database", "config", "phpinfo"]
        medium_files = ["log", "swagger", "api-docs", "package.json"]

        file_lower = file_path.lower()

        for pattern in critical_files:
            if pattern in file_lower:
                return "critical"

        for pattern in high_files:
            if pattern in file_lower:
                return "high"

        for pattern in medium_files:
            if pattern in file_lower:
                return "medium"

        return "low"

    async def _scan_directory_traversal(self):
        """Scan for directory traversal / LFI"""
        await self.emit("status", {"message": "Testing for directory traversal..."})

        semaphore = asyncio.Semaphore(self.threads)

        # Find parameters in URL that might be vulnerable
        parsed = urlparse(self.target)
        params_to_test = []

        # Common vulnerable parameters
        vuln_params = ["file", "path", "page", "include", "doc", "document",
                       "folder", "root", "pg", "style", "pdf", "template",
                       "php_path", "action", "cat", "dir", "load", "read"]

        for param in vuln_params:
            params_to_test.append(f"{self.base_url}?{param}=")

        async def test_lfi(base_url: str, payload: str, signature: str):
            async with semaphore:
                self.stats["total_checks"] += 1
                url = f"{base_url}{payload}"

                async with AsyncHTTPClient(timeout=self.timeout) as client:
                    result = await client.get(url)

                    if result and result.status_code == 200:
                        # Check response for LFI signature
                        async with aiohttp.ClientSession() as session:
                            try:
                                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                                    content = await resp.text()

                                    if signature.lower() in content.lower():
                                        vuln = VulnerabilityResult(
                                            url=url,
                                            vuln_type="directory_traversal",
                                            severity="critical",
                                            title="Directory Traversal / LFI Vulnerability",
                                            description="The application is vulnerable to directory traversal attacks, allowing access to sensitive system files.",
                                            evidence=f"Payload: {payload}, Signature found: {signature}",
                                            payload=payload,
                                            remediation="Validate and sanitize all user input. Use whitelisting for allowed file paths. Implement proper access controls.",
                                            cwe="CWE-22",
                                            cvss=9.8,
                                            verified=True
                                        )
                                        self._add_vulnerability(vuln)
                            except:
                                pass

        tasks = []
        for base_url in params_to_test:
            for payload, signature in self.LFI_PAYLOADS:
                tasks.append(test_lfi(base_url, payload, signature))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _scan_information_disclosure(self):
        """Scan for information disclosure"""
        await self.emit("status", {"message": "Checking for information disclosure..."})

        async with AsyncHTTPClient(timeout=self.timeout) as client:
            result = await client.get(self.target)

            if result:
                headers = result.headers

                # Check for sensitive headers
                sensitive_headers = {
                    "X-Powered-By": "Technology disclosure",
                    "Server": "Server version disclosure",
                    "X-AspNet-Version": "ASP.NET version disclosure",
                    "X-AspNetMvc-Version": "ASP.NET MVC version disclosure",
                    "X-Debug-Token": "Debug token exposed",
                    "X-Debug-Token-Link": "Debug link exposed",
                }

                for header, description in sensitive_headers.items():
                    if header in headers:
                        value = headers[header]
                        self.headers_info[header] = value

                        vuln = VulnerabilityResult(
                            url=self.target,
                            vuln_type="information_disclosure",
                            severity="info",
                            title=f"Header Information Disclosure: {header}",
                            description=f"{description}. Value: {value}",
                            evidence=f"{header}: {value}",
                            remediation=f"Remove or suppress the {header} header in production.",
                            cwe="CWE-200"
                        )
                        self._add_vulnerability(vuln)

                # Check for missing security headers
                security_headers = {
                    "X-Frame-Options": "Missing clickjacking protection",
                    "X-Content-Type-Options": "Missing MIME sniffing protection",
                    "X-XSS-Protection": "Missing XSS filter",
                    "Content-Security-Policy": "Missing CSP",
                    "Strict-Transport-Security": "Missing HSTS"
                }

                for header, description in security_headers.items():
                    if header not in headers:
                        vuln = VulnerabilityResult(
                            url=self.target,
                            vuln_type="missing_security_header",
                            severity="low",
                            title=f"Missing Security Header: {header}",
                            description=description,
                            evidence=f"Header '{header}' not present in response",
                            remediation=f"Add the {header} security header to all responses.",
                            cwe="CWE-693"
                        )
                        self._add_vulnerability(vuln)

    async def _scan_misconfigurations(self):
        """Scan for common misconfigurations"""
        await self.emit("status", {"message": "Checking for misconfigurations..."})

        # Check for directory listing
        test_dirs = ["/", "/images/", "/uploads/", "/files/", "/assets/", "/static/"]

        async with AsyncHTTPClient(timeout=self.timeout) as client:
            for dir_path in test_dirs:
                url = f"{self.base_url}{dir_path}"
                result = await client.get(url)

                if result and result.status_code == 200:
                    # Check for directory listing signatures
                    async with aiohttp.ClientSession() as session:
                        try:
                            async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                                content = await resp.text()

                                dir_listing_signatures = [
                                    "Index of /",
                                    "Directory listing for",
                                    "<title>Index of",
                                    "Parent Directory",
                                    "[To Parent Directory]"
                                ]

                                for sig in dir_listing_signatures:
                                    if sig in content:
                                        vuln = VulnerabilityResult(
                                            url=url,
                                            vuln_type="directory_listing",
                                            severity="medium",
                                            title=f"Directory Listing Enabled: {dir_path}",
                                            description="Directory listing is enabled, allowing attackers to enumerate files and directories.",
                                            evidence=f"Found signature: {sig}",
                                            remediation="Disable directory listing in web server configuration.",
                                            cwe="CWE-548"
                                        )
                                        self._add_vulnerability(vuln)
                                        break
                        except:
                            pass

    async def _detect_technologies(self):
        """Detect technologies used"""
        await self.emit("status", {"message": "Detecting technologies..."})

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.target, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    content = await resp.text()
                    headers = dict(resp.headers)

                    # Header-based detection
                    if "X-Powered-By" in headers:
                        self.technologies["server_tech"] = headers["X-Powered-By"]

                    if "Server" in headers:
                        self.technologies["server"] = headers["Server"]

                    # Content-based detection
                    tech_signatures = {
                        "WordPress": ["wp-content", "wp-includes", "wordpress"],
                        "Drupal": ["drupal", "sites/default"],
                        "Joomla": ["joomla", "/components/com_"],
                        "Laravel": ["laravel", "csrf-token"],
                        "Django": ["csrfmiddlewaretoken", "django"],
                        "React": ["react", "_react"],
                        "Vue.js": ["vue", "__vue__"],
                        "Angular": ["ng-", "angular"],
                        "jQuery": ["jquery"],
                        "Bootstrap": ["bootstrap"],
                    }

                    content_lower = content.lower()
                    for tech, signatures in tech_signatures.items():
                        for sig in signatures:
                            if sig.lower() in content_lower:
                                self.technologies[tech] = "detected"
                                break

            except Exception as e:
                pass

        await self.emit("technologies", {"detected": self.technologies})

    def get_critical_vulnerabilities(self) -> List[VulnerabilityResult]:
        """Get critical and high severity vulnerabilities"""
        return [v for v in self.vulnerabilities if v.severity in ["critical", "high"]]

    def get_vulnerabilities_by_type(self) -> Dict[str, List[VulnerabilityResult]]:
        """Group vulnerabilities by type"""
        by_type = {}
        for vuln in self.vulnerabilities:
            if vuln.vuln_type not in by_type:
                by_type[vuln.vuln_type] = []
            by_type[vuln.vuln_type].append(vuln)
        return by_type
