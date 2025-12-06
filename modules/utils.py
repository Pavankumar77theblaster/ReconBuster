"""
ReconBuster Utilities
Common functions and helpers
"""

import asyncio
import aiohttp
import dns.resolver
import random
import re
import hashlib
import socket
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse, urljoin
from datetime import datetime
from dataclasses import dataclass, field
from .config import USER_AGENTS, COLORS

@dataclass
class ScanResult:
    """Represents a single scan result"""
    url: str
    status_code: int
    method: str = "GET"
    response_length: int = 0
    response_time: float = 0.0
    headers: Dict = field(default_factory=dict)
    content_hash: str = ""
    redirect_url: str = ""
    bypass_method: str = ""
    vulnerability: str = ""
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    is_success: bool = False
    is_bypass: bool = False

@dataclass
class SubdomainResult:
    """Represents a subdomain discovery result"""
    subdomain: str
    source: str
    ip_address: str = ""
    is_alive: bool = False
    http_status: int = 0
    https_status: int = 0
    title: str = ""
    server: str = ""
    technologies: List[str] = field(default_factory=list)
    cname: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

class AsyncHTTPClient:
    """Async HTTP client with retry and rate limiting"""

    def __init__(self, timeout: int = 10, max_retries: int = 3,
                 delay: float = 0.0, verify_ssl: bool = False,
                 proxy: str = None):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.session = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            ssl=self.verify_ssl,
            limit=100,
            limit_per_host=10
        )
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def get_random_user_agent(self) -> str:
        return random.choice(USER_AGENTS)

    async def request(self, url: str, method: str = "GET",
                      headers: Dict = None, data: Any = None,
                      allow_redirects: bool = True,
                      custom_ua: bool = True) -> Optional[ScanResult]:
        """Make HTTP request with retry logic"""

        if headers is None:
            headers = {}

        if custom_ua and "User-Agent" not in headers:
            headers["User-Agent"] = self.get_random_user_agent()

        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    await asyncio.sleep(self.delay)

                start_time = asyncio.get_event_loop().time()

                async with self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=data,
                    allow_redirects=allow_redirects,
                    proxy=self.proxy
                ) as response:
                    end_time = asyncio.get_event_loop().time()
                    response_time = end_time - start_time

                    content = await response.text()
                    content_hash = hashlib.md5(content.encode()).hexdigest()

                    redirect_url = ""
                    if response.history:
                        redirect_url = str(response.url)

                    result = ScanResult(
                        url=url,
                        status_code=response.status,
                        method=method,
                        response_length=len(content),
                        response_time=response_time,
                        headers=dict(response.headers),
                        content_hash=content_hash,
                        redirect_url=redirect_url,
                        is_success=response.status in [200, 201, 202, 204]
                    )

                    return result

            except asyncio.TimeoutError:
                if attempt == self.max_retries - 1:
                    return None
            except aiohttp.ClientError as e:
                if attempt == self.max_retries - 1:
                    return None
            except Exception as e:
                if attempt == self.max_retries - 1:
                    return None

        return None

    async def get(self, url: str, **kwargs) -> Optional[ScanResult]:
        return await self.request(url, method="GET", **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[ScanResult]:
        return await self.request(url, method="POST", **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[ScanResult]:
        return await self.request(url, method="HEAD", **kwargs)


class DNSResolver:
    """DNS resolution utilities"""

    def __init__(self, nameservers: List[str] = None):
        self.resolver = dns.resolver.Resolver()
        if nameservers:
            self.resolver.nameservers = nameservers
        else:
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def resolve(self, domain: str, record_type: str = 'A') -> List[str]:
        """Resolve DNS records"""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(domain, record_type)
            )
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    async def get_ip(self, domain: str) -> str:
        """Get IP address for domain"""
        ips = await self.resolve(domain, 'A')
        return ips[0] if ips else ""

    async def get_cname(self, domain: str) -> str:
        """Get CNAME record"""
        cnames = await self.resolve(domain, 'CNAME')
        return cnames[0] if cnames else ""

    async def is_alive(self, domain: str) -> bool:
        """Check if domain resolves"""
        ip = await self.get_ip(domain)
        return bool(ip)


def normalize_url(url: str) -> str:
    """Normalize URL format"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url.rstrip('/')


def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(normalize_url(url))
    return parsed.netloc


def is_valid_domain(domain: str) -> bool:
    """Validate domain format"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def colorize(text: str, color: str) -> str:
    """Add color to text"""
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def print_banner():
    """Print tool banner"""
    banner = """
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
    ║  Version 1.0.0                                                ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(colorize(banner, "cyan"))


def format_size(size_bytes: int) -> str:
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def format_time(seconds: float) -> str:
    """Format seconds to human readable"""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"


def deduplicate_results(results: List[ScanResult]) -> List[ScanResult]:
    """Remove duplicate results based on content hash"""
    seen_hashes = set()
    unique_results = []

    for result in results:
        if result.content_hash not in seen_hashes:
            seen_hashes.add(result.content_hash)
            unique_results.append(result)

    return unique_results


def filter_false_positives(results: List[ScanResult],
                           original_hash: str) -> List[ScanResult]:
    """Filter out false positives by comparing content hashes"""
    return [r for r in results if r.content_hash != original_hash and r.is_success]


async def check_port(host: str, port: int, timeout: float = 3) -> bool:
    """Check if port is open"""
    try:
        future = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(future, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False


def generate_path_variations(path: str) -> List[str]:
    """Generate path variations for bypass attempts"""
    from .config import PATH_BYPASSES

    path = path.strip('/')
    variations = []

    for template in PATH_BYPASSES:
        if "{path}" in template:
            variation = template.replace("{path}", path)
        elif "{PATH}" in template:
            variation = template.replace("{PATH}", path.upper())
        else:
            variation = template

        variations.append(variation)

    # Add original path
    variations.append(f"/{path}")

    return list(set(variations))


def extract_title(html: str) -> str:
    """Extract title from HTML"""
    match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def extract_server(headers: Dict) -> str:
    """Extract server from headers"""
    return headers.get('Server', headers.get('server', ''))


def is_wildcard_response(results: List[ScanResult]) -> bool:
    """Detect wildcard DNS/HTTP responses"""
    if len(results) < 3:
        return False

    hashes = [r.content_hash for r in results]
    # If all hashes are the same, likely wildcard
    return len(set(hashes)) == 1


class RateLimiter:
    """Async rate limiter"""

    def __init__(self, rate: int = 10, per: float = 1.0):
        self.rate = rate
        self.per = per
        self.tokens = rate
        self.last_update = asyncio.get_event_loop().time()
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = asyncio.get_event_loop().time()
            time_passed = now - self.last_update
            self.tokens += time_passed * (self.rate / self.per)
            self.tokens = min(self.tokens, self.rate)
            self.last_update = now

            if self.tokens < 1:
                sleep_time = (1 - self.tokens) * (self.per / self.rate)
                await asyncio.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1
