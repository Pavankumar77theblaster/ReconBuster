"""
ReconBuster Directory Enumeration Module
Combines techniques from: dirsearch, dirstalk, zenbuster, omnisci3nt
"""

import asyncio
import aiohttp
from typing import List, Dict, Set, Callable, Optional
from dataclasses import dataclass, field
from pathlib import Path
from .utils import (
    AsyncHTTPClient, ScanResult, normalize_url,
    colorize, format_size, format_time, deduplicate_results
)
from .config import (
    DEFAULT_DIRECTORIES, USER_AGENTS, STATUS_SUCCESS,
    STATUS_REDIRECT, STATUS_FORBIDDEN, STATUS_NOT_FOUND
)

@dataclass
class DirectoryResult:
    """Result of directory scan"""
    url: str
    status_code: int
    content_length: int
    response_time: float
    redirect_url: str = ""
    content_type: str = ""
    server: str = ""
    title: str = ""
    is_directory: bool = False
    is_file: bool = False
    is_forbidden: bool = False
    methods_allowed: List[str] = field(default_factory=list)


class DirectoryFuzzer:
    """
    Advanced directory and file fuzzer
    Features:
    - Multi-threaded async scanning
    - Extension fuzzing
    - Recursive scanning
    - Smart filtering (content length, wildcards)
    - Status code filtering
    - Response time analysis
    """

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 50, timeout: int = 10,
                 extensions: List[str] = None,
                 wordlist: List[str] = None,
                 recursive: bool = False,
                 recursive_depth: int = 2,
                 follow_redirects: bool = False,
                 exclude_status: List[int] = None,
                 include_status: List[int] = None,
                 exclude_length: List[int] = None):

        self.target = normalize_url(target)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.extensions = extensions or [""]
        self.wordlist = wordlist or DEFAULT_DIRECTORIES
        self.recursive = recursive
        self.recursive_depth = recursive_depth
        self.follow_redirects = follow_redirects
        self.exclude_status = exclude_status or [404]
        self.include_status = include_status
        self.exclude_length = exclude_length or []

        self.results: List[DirectoryResult] = []
        self.forbidden_paths: List[str] = []  # 403 paths for bypass attempts
        self.scanned_paths: Set[str] = set()
        self.wildcard_response: Optional[str] = None

        # Statistics
        self.stats = {
            "total_requests": 0,
            "found": 0,
            "forbidden": 0,
            "errors": 0,
            "directories": 0,
            "files": 0
        }

    async def emit(self, event: str, data: dict):
        """Emit event to callback"""
        if self.callback:
            await self.callback(event, data)

    async def scan(self) -> List[DirectoryResult]:
        """Main scanning method"""
        await self.emit("status", {
            "message": f"Starting directory scan on {self.target}",
            "total_paths": len(self.wordlist) * len(self.extensions)
        })

        # Detect wildcard responses
        await self._detect_wildcard()

        # Generate all paths to scan
        paths = self._generate_paths()

        await self.emit("status", {
            "message": f"Scanning {len(paths)} paths with {self.threads} threads"
        })

        # Scan with semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.threads)

        async def scan_with_semaphore(path: str):
            async with semaphore:
                return await self._scan_path(path)

        tasks = [scan_with_semaphore(path) for path in paths]

        # Process results as they complete
        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
                if result:
                    self._process_result(result)
            except Exception as e:
                self.stats["errors"] += 1

        # Recursive scanning
        if self.recursive and self.recursive_depth > 0:
            await self._recursive_scan()

        await self.emit("complete", {
            "results": [r.__dict__ for r in self.results],
            "forbidden_paths": self.forbidden_paths,
            "stats": self.stats
        })

        return self.results

    def _generate_paths(self) -> List[str]:
        """Generate all paths to scan"""
        paths = []

        for word in self.wordlist:
            word = word.strip()
            if not word or word.startswith('#'):
                continue

            # Without extension
            paths.append(f"/{word}")
            paths.append(f"/{word}/")

            # With extensions
            for ext in self.extensions:
                if ext and not ext.startswith('.'):
                    ext = f".{ext}"
                if ext:
                    paths.append(f"/{word}{ext}")

        return list(set(paths))

    async def _detect_wildcard(self):
        """Detect wildcard responses"""
        random_paths = [
            "/asdfjkl234randompath",
            "/xyznonexistent123456",
            "/qwerty98765notreal"
        ]

        responses = []
        async with AsyncHTTPClient(timeout=self.timeout) as client:
            for path in random_paths:
                url = f"{self.target}{path}"
                result = await client.get(url)
                if result:
                    responses.append(result)

        # Check if all responses are the same
        if len(responses) >= 2:
            hashes = [r.content_hash for r in responses]
            lengths = [r.response_length for r in responses]

            if len(set(hashes)) == 1 or len(set(lengths)) == 1:
                self.wildcard_response = hashes[0]
                await self.emit("warning", {
                    "message": "Wildcard response detected - filtering enabled"
                })

    async def _scan_path(self, path: str) -> Optional[DirectoryResult]:
        """Scan a single path"""
        if path in self.scanned_paths:
            return None

        self.scanned_paths.add(path)
        url = f"{self.target}{path}"
        self.stats["total_requests"] += 1

        async with AsyncHTTPClient(timeout=self.timeout) as client:
            result = await client.get(
                url,
                allow_redirects=self.follow_redirects
            )

            if not result:
                return None

            # Filter by status code
            if self.include_status and result.status_code not in self.include_status:
                return None

            if result.status_code in self.exclude_status:
                return None

            # Filter wildcard responses
            if self.wildcard_response and result.content_hash == self.wildcard_response:
                return None

            # Filter by content length
            if result.response_length in self.exclude_length:
                return None

            # Create directory result
            dir_result = DirectoryResult(
                url=url,
                status_code=result.status_code,
                content_length=result.response_length,
                response_time=result.response_time,
                redirect_url=result.redirect_url,
                content_type=result.headers.get('Content-Type', ''),
                server=result.headers.get('Server', ''),
                is_directory=path.endswith('/'),
                is_file=not path.endswith('/') and '.' in path.split('/')[-1],
                is_forbidden=result.status_code in [401, 403]
            )

            return dir_result

    def _process_result(self, result: DirectoryResult):
        """Process and categorize a result"""
        self.results.append(result)
        self.stats["found"] += 1

        if result.is_forbidden:
            self.stats["forbidden"] += 1
            self.forbidden_paths.append(result.url)

            asyncio.create_task(self.emit("forbidden", {
                "url": result.url,
                "status": result.status_code
            }))
        else:
            if result.is_directory:
                self.stats["directories"] += 1
            elif result.is_file:
                self.stats["files"] += 1

            asyncio.create_task(self.emit("found", {
                "url": result.url,
                "status": result.status_code,
                "length": result.content_length,
                "type": "directory" if result.is_directory else "file"
            }))

    async def _recursive_scan(self, depth: int = 0):
        """Recursively scan discovered directories"""
        if depth >= self.recursive_depth:
            return

        directories = [r for r in self.results if r.is_directory and r.status_code == 200]

        for dir_result in directories:
            base_path = dir_result.url.replace(self.target, "")

            paths = []
            for word in self.wordlist[:100]:  # Limit for recursive
                word = word.strip()
                if not word:
                    continue
                paths.append(f"{base_path}{word}")
                paths.append(f"{base_path}{word}/")

            semaphore = asyncio.Semaphore(self.threads)

            async def scan_with_semaphore(path: str):
                async with semaphore:
                    return await self._scan_path(path)

            tasks = [scan_with_semaphore(path) for path in paths]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, DirectoryResult):
                    self._process_result(result)

        # Continue recursion
        if depth + 1 < self.recursive_depth:
            await self._recursive_scan(depth + 1)

    async def check_methods(self, url: str) -> List[str]:
        """Check allowed HTTP methods for a URL"""
        allowed_methods = []
        methods_to_check = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]

        async with AsyncHTTPClient(timeout=self.timeout) as client:
            # Try OPTIONS first
            result = await client.request(url, method="OPTIONS")
            if result and result.status_code == 200:
                allow_header = result.headers.get('Allow', '')
                if allow_header:
                    allowed_methods = [m.strip() for m in allow_header.split(',')]
                    return allowed_methods

            # Check each method manually
            for method in methods_to_check:
                result = await client.request(url, method=method)
                if result and result.status_code not in [405, 501]:
                    allowed_methods.append(method)

        return allowed_methods

    def get_forbidden_paths(self) -> List[str]:
        """Get all paths returning 403"""
        return self.forbidden_paths

    def get_successful_paths(self) -> List[str]:
        """Get all successful paths (200)"""
        return [r.url for r in self.results if r.status_code == 200]


class AdminFinder:
    """
    Specialized admin panel finder
    Checks common admin paths and login pages
    """

    ADMIN_PATHS = [
        "admin", "administrator", "admin.php", "admin.html",
        "admin/login", "admin/index", "adminpanel", "admincp",
        "wp-admin", "wp-login.php", "wp-admin/login.php",
        "administrator/index.php", "admin/admin.php",
        "panel", "controlpanel", "cpanel", "webadmin",
        "siteadmin", "admin1", "admin2", "admin_area",
        "admin_login", "manager", "manage", "management",
        "user/login", "login", "signin", "login.php",
        "auth/login", "account/login", "dashboard",
        "portal", "backend", "cms", "cms/admin",
        "phpmyadmin", "myadmin", "mysql", "mysqladmin",
        "pma", "dbadmin", "db", "database",
        "modelsearch/index.php", "moderator", "webmaster",
        "adminarea", "bb-admin", "admin/home",
        "admin/controlpanel", "admin/cp", "admin_cp",
        "administrator/account", "admin/account",
        "admin/login.php", "admin/adminLogin",
        "home.php", "adminLogin.php", "admin-login.php",
        "adminpanel/login", "moderator/admin",
        "user_area/admin", "fileadmin", "siteadmin/login",
        "memberadmin", "member/admin", "admin/member",
    ]

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 30, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.found_panels: List[Dict] = []

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def find(self) -> List[Dict]:
        """Find admin panels"""
        await self.emit("status", {"message": "Searching for admin panels..."})

        semaphore = asyncio.Semaphore(self.threads)

        async def check_path(path: str):
            async with semaphore:
                url = f"{self.target}/{path}"
                async with AsyncHTTPClient(timeout=self.timeout) as client:
                    result = await client.get(url)

                    if result and result.status_code in [200, 302, 301, 401, 403]:
                        panel_info = {
                            "url": url,
                            "path": path,
                            "status": result.status_code,
                            "length": result.response_length,
                            "type": "potential" if result.status_code in [401, 403] else "found"
                        }
                        self.found_panels.append(panel_info)
                        await self.emit("admin_found", panel_info)
                        return panel_info
                return None

        tasks = [check_path(path) for path in self.ADMIN_PATHS]
        await asyncio.gather(*tasks, return_exceptions=True)

        await self.emit("complete", {"panels": self.found_panels})
        return self.found_panels
