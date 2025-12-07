"""
ReconBuster Robots.txt Analyzer
Extracts valuable reconnaissance information from robots.txt
"""

import asyncio
import aiohttp
import re
from typing import List, Dict, Set, Optional, Callable
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field


@dataclass
class RobotsResult:
    """Result from robots.txt analysis"""
    url: str
    exists: bool = False
    content: str = ""
    disallowed_paths: List[str] = field(default_factory=list)
    allowed_paths: List[str] = field(default_factory=list)
    sitemaps: List[str] = field(default_factory=list)
    interesting_paths: List[Dict] = field(default_factory=list)
    crawl_delay: Optional[int] = None
    user_agents: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    hidden_gems: List[Dict] = field(default_factory=list)


class RobotsAnalyzer:
    """
    Analyzes robots.txt for reconnaissance information

    Extracts:
    - Disallowed paths (potential sensitive areas)
    - Sitemaps (additional URL discovery)
    - Admin panels, API endpoints, backup files
    - Comments that might reveal info
    - Crawl delays (rate limiting hints)
    """

    # Interesting path patterns that indicate sensitive areas
    INTERESTING_PATTERNS = {
        "admin": [
            r"/admin", r"/administrator", r"/admin-panel", r"/admincp",
            r"/wp-admin", r"/backend", r"/manager", r"/control",
            r"/cpanel", r"/dashboard", r"/portal", r"/cms"
        ],
        "api": [
            r"/api", r"/api/v\d", r"/rest", r"/graphql", r"/swagger",
            r"/openapi", r"/v1", r"/v2", r"/v3", r"/endpoints"
        ],
        "backup": [
            r"/backup", r"/bak", r"/old", r"/copy", r"/archive",
            r"\.bak$", r"\.backup$", r"\.old$", r"\.orig$", r"\.save$"
        ],
        "config": [
            r"/config", r"/conf", r"/settings", r"/setup", r"\.config",
            r"/env", r"\.env", r"/properties", r"/secrets"
        ],
        "database": [
            r"/db", r"/database", r"/sql", r"/mysql", r"/phpmyadmin",
            r"/adminer", r"/pgadmin", r"/mongodb"
        ],
        "upload": [
            r"/upload", r"/uploads", r"/files", r"/media", r"/attachments",
            r"/documents", r"/assets", r"/static"
        ],
        "user": [
            r"/user", r"/users", r"/account", r"/profile", r"/member",
            r"/login", r"/register", r"/auth", r"/oauth"
        ],
        "internal": [
            r"/internal", r"/private", r"/restricted", r"/secure",
            r"/hidden", r"/secret", r"/dev", r"/test", r"/staging"
        ],
        "logs": [
            r"/log", r"/logs", r"/debug", r"/trace", r"/error",
            r"\.log$", r"/monitoring", r"/metrics"
        ],
        "source": [
            r"/src", r"/source", r"\.git", r"/svn", r"\.svn",
            r"/repository", r"/repo", r"\.hg"
        ],
        "temp": [
            r"/tmp", r"/temp", r"/cache", r"/swap", r"\.tmp$",
            r"\.temp$", r"\.swp$"
        ],
        "cgi": [
            r"/cgi", r"/cgi-bin", r"/scripts", r"/bin", r"/exec"
        ],
    }

    def __init__(self, target_url: str, callback: Callable = None, timeout: int = 10):
        self.target_url = target_url
        self.callback = callback
        self.timeout = timeout

        parsed = urlparse(target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.robots_url = f"{self.base_url}/robots.txt"

        self.result = RobotsResult(url=self.robots_url)

    async def emit(self, event: str, data: dict):
        """Emit event to callback"""
        if self.callback:
            await self.callback(event, data)

    async def analyze(self) -> RobotsResult:
        """Fetch and analyze robots.txt"""
        await self.emit("status", {"message": f"Analyzing robots.txt at {self.robots_url}"})

        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self.robots_url, ssl=False) as response:
                    if response.status == 200:
                        self.result.exists = True
                        self.result.content = await response.text()
                        await self._parse_robots()
                        await self._find_interesting_paths()
                        await self._extract_hidden_gems()
                    else:
                        self.result.exists = False
                        await self.emit("info", {"message": f"robots.txt not found (HTTP {response.status})"})
        except Exception as e:
            self.result.exists = False
            await self.emit("error", {"message": f"Error fetching robots.txt: {str(e)}"})

        await self.emit("complete", {
            "exists": self.result.exists,
            "disallowed_count": len(self.result.disallowed_paths),
            "interesting_count": len(self.result.interesting_paths),
            "sitemaps_count": len(self.result.sitemaps)
        })

        return self.result

    async def _parse_robots(self):
        """Parse robots.txt content"""
        lines = self.result.content.split('\n')
        current_ua = "*"

        for line in lines:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Extract comments
            if line.startswith('#'):
                comment = line[1:].strip()
                if comment:
                    self.result.comments.append(comment)
                continue

            # Handle inline comments
            if '#' in line:
                line = line.split('#')[0].strip()

            # Parse directives
            if ':' in line:
                directive, value = line.split(':', 1)
                directive = directive.strip().lower()
                value = value.strip()

                if directive == 'user-agent':
                    current_ua = value
                    if value not in self.result.user_agents:
                        self.result.user_agents.append(value)

                elif directive == 'disallow':
                    if value and value not in self.result.disallowed_paths:
                        self.result.disallowed_paths.append(value)

                elif directive == 'allow':
                    if value and value not in self.result.allowed_paths:
                        self.result.allowed_paths.append(value)

                elif directive == 'sitemap':
                    if value and value not in self.result.sitemaps:
                        self.result.sitemaps.append(value)

                elif directive == 'crawl-delay':
                    try:
                        self.result.crawl_delay = int(value)
                    except:
                        pass

    async def _find_interesting_paths(self):
        """Find interesting paths from disallowed entries"""
        all_paths = self.result.disallowed_paths + self.result.allowed_paths

        for path in all_paths:
            for category, patterns in self.INTERESTING_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        full_url = urljoin(self.base_url, path)

                        # Determine priority
                        priority = "medium"
                        if category in ["admin", "config", "database", "backup", "source"]:
                            priority = "high"
                        elif category in ["logs", "internal", "api"]:
                            priority = "high"

                        self.result.interesting_paths.append({
                            "path": path,
                            "url": full_url,
                            "category": category,
                            "priority": priority,
                            "reason": f"Matches {category} pattern: {pattern}"
                        })
                        break

    async def _extract_hidden_gems(self):
        """Extract hidden information from robots.txt"""
        # Look for version numbers in comments
        version_pattern = r'v?\d+\.\d+(\.\d+)?'
        for comment in self.result.comments:
            versions = re.findall(version_pattern, comment)
            if versions:
                self.result.hidden_gems.append({
                    "type": "version",
                    "value": comment,
                    "info": "Possible version disclosure in comment"
                })

        # Look for email addresses
        email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        for comment in self.result.comments:
            emails = re.findall(email_pattern, comment)
            for email in emails:
                self.result.hidden_gems.append({
                    "type": "email",
                    "value": email,
                    "info": "Email address found in robots.txt comment"
                })

        # Look for internal paths that might reveal structure
        internal_patterns = [
            r'/[a-z]+[-_]?v\d+/',  # Versioned APIs
            r'/[a-z]+[-_]?\d{4}/',  # Year-based paths
            r'/[a-z]+[-_]?(dev|test|staging|prod)/',  # Environment paths
        ]

        for path in self.result.disallowed_paths:
            for pattern in internal_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    self.result.hidden_gems.append({
                        "type": "internal_structure",
                        "value": path,
                        "info": "Path reveals internal structure/versioning"
                    })
                    break

        # Look for backup file patterns
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.save', '.swp', '.tmp', '~']
        for path in self.result.disallowed_paths:
            for ext in backup_extensions:
                if path.endswith(ext):
                    self.result.hidden_gems.append({
                        "type": "backup_file",
                        "value": path,
                        "info": f"Potential backup file ({ext})"
                    })
                    break

        # Check for interesting user agents mentioned
        interesting_uas = ['googlebot', 'bingbot', 'yandex', 'baidu', 'gptbot', 'chatgpt', 'anthropic']
        for ua in self.result.user_agents:
            ua_lower = ua.lower()
            for iua in interesting_uas:
                if iua in ua_lower:
                    self.result.hidden_gems.append({
                        "type": "user_agent",
                        "value": ua,
                        "info": f"Specific rules for {iua}"
                    })
                    break

    def get_paths_for_bypass_testing(self) -> List[str]:
        """Get list of paths that should be tested for 403 bypass"""
        priority_paths = []

        # High priority: admin, config, database paths
        high_priority_categories = ["admin", "config", "database", "backup", "source", "internal", "api"]

        for interesting in self.result.interesting_paths:
            if interesting["category"] in high_priority_categories:
                priority_paths.append(interesting["url"])

        # Add all disallowed paths
        for path in self.result.disallowed_paths:
            full_url = urljoin(self.base_url, path)
            if full_url not in priority_paths:
                priority_paths.append(full_url)

        return priority_paths

    def get_report_data(self) -> Dict:
        """Get data formatted for report"""
        return {
            "url": self.result.url,
            "exists": self.result.exists,
            "disallowed_paths": self.result.disallowed_paths,
            "allowed_paths": self.result.allowed_paths,
            "sitemaps": self.result.sitemaps,
            "interesting_paths": self.result.interesting_paths,
            "hidden_gems": self.result.hidden_gems,
            "crawl_delay": self.result.crawl_delay,
            "user_agents": self.result.user_agents,
            "comments": self.result.comments,
            "total_entries": len(self.result.disallowed_paths) + len(self.result.allowed_paths)
        }
