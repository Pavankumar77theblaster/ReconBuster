"""
ReconBuster CMS Detection and Vulnerability Module
Detects CMS platforms and checks for known vulnerabilities
"""

import asyncio
import aiohttp
import re
import random
from typing import List, Dict, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from .utils import normalize_url, USER_AGENTS


@dataclass
class CMSResult:
    """CMS Detection Result"""
    detected: bool = False
    cms_name: str = ""
    version: str = ""
    confidence: str = ""  # high, medium, low
    evidence: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    plugins: List[str] = field(default_factory=list)
    themes: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class CMSDetector:
    """
    CMS (Content Management System) Detector
    Detects: WordPress, Joomla, Drupal, Magento, Shopify, etc.
    """

    # CMS Signatures
    CMS_SIGNATURES = {
        "WordPress": {
            "paths": [
                "/wp-login.php",
                "/wp-admin/",
                "/wp-content/",
                "/wp-includes/",
                "/xmlrpc.php",
            ],
            "meta": [
                'name="generator" content="WordPress',
                "wp-content/themes/",
                "wp-content/plugins/",
            ],
            "headers": [],
            "cookies": ["wordpress_logged_in", "wp-settings"],
            "version_paths": [
                "/readme.html",
                "/wp-includes/version.php",
                "/feed/",
            ],
        },
        "Joomla": {
            "paths": [
                "/administrator/",
                "/components/",
                "/modules/",
                "/plugins/",
                "/templates/",
            ],
            "meta": [
                'name="generator" content="Joomla',
                "/media/system/js/",
                "joomla",
            ],
            "headers": [],
            "cookies": ["joomla_user_state"],
            "version_paths": [
                "/administrator/manifests/files/joomla.xml",
                "/language/en-GB/en-GB.xml",
            ],
        },
        "Drupal": {
            "paths": [
                "/core/",
                "/modules/",
                "/profiles/",
                "/sites/default/",
                "/themes/",
                "/user/login",
            ],
            "meta": [
                'name="generator" content="Drupal',
                "drupal.js",
                "Drupal.settings",
            ],
            "headers": ["X-Drupal-Cache", "X-Generator: Drupal"],
            "cookies": ["Drupal.visitor", "SESS"],
            "version_paths": [
                "/CHANGELOG.txt",
                "/core/CHANGELOG.txt",
            ],
        },
        "Magento": {
            "paths": [
                "/admin/",
                "/downloader/",
                "/skin/frontend/",
                "/js/mage/",
                "/app/etc/local.xml",
            ],
            "meta": [
                "Magento",
                "Mage.Cookies",
                "skin/frontend/",
            ],
            "headers": [],
            "cookies": ["frontend", "adminhtml"],
            "version_paths": [
                "/magento_version",
                "/RELEASE_NOTES.txt",
            ],
        },
        "Shopify": {
            "paths": [
                "/collections/",
                "/products/",
            ],
            "meta": [
                "Shopify",
                "cdn.shopify.com",
            ],
            "headers": ["X-Shopify-Stage"],
            "cookies": ["_shopify_s", "_shopify_y"],
            "version_paths": [],
        },
        "PrestaShop": {
            "paths": [
                "/classes/",
                "/controllers/",
                "/modules/",
                "/themes/",
                "/tools/",
            ],
            "meta": [
                "PrestaShop",
                "prestashop",
            ],
            "headers": [],
            "cookies": ["PrestaShop"],
            "version_paths": [
                "/config/settings.inc.php",
            ],
        },
        "OpenCart": {
            "paths": [
                "/catalog/",
                "/admin/",
                "/image/",
            ],
            "meta": [
                "OpenCart",
                "catalog/view/theme/",
            ],
            "headers": [],
            "cookies": ["OCSESSID"],
            "version_paths": [],
        },
        "TYPO3": {
            "paths": [
                "/typo3/",
                "/typo3conf/",
                "/typo3temp/",
            ],
            "meta": [
                "TYPO3",
                'name="generator" content="TYPO3',
            ],
            "headers": [],
            "cookies": ["fe_typo_user"],
            "version_paths": [
                "/typo3/sysext/core/Documentation/Changelog/",
            ],
        },
        "Ghost": {
            "paths": [
                "/ghost/",
                "/content/themes/",
            ],
            "meta": [
                "Ghost",
                'name="generator" content="Ghost',
            ],
            "headers": ["X-Ghost-Cache-Status"],
            "cookies": ["ghost-admin-api-session"],
            "version_paths": [],
        },
        "Wix": {
            "paths": [],
            "meta": [
                "wix.com",
                "X-Wix-",
            ],
            "headers": ["X-Wix-Request-Id"],
            "cookies": [],
            "version_paths": [],
        },
        "Squarespace": {
            "paths": [],
            "meta": [
                "squarespace",
                "static.squarespace.com",
            ],
            "headers": [],
            "cookies": ["SS_ANALYTICS"],
            "version_paths": [],
        },
    }

    # Known CMS vulnerabilities
    CMS_VULNERABILITIES = {
        "WordPress": {
            "paths": [
                ("/wp-config.php.bak", "WordPress config backup exposed"),
                ("/wp-config.php~", "WordPress config backup exposed"),
                ("/.wp-config.php.swp", "WordPress config swap file exposed"),
                ("/wp-content/debug.log", "WordPress debug log exposed"),
                ("/wp-content/uploads/", "Directory listing in uploads"),
                ("/wp-json/wp/v2/users", "User enumeration via REST API"),
                ("/wp-admin/install.php", "WordPress installation exposed"),
            ],
            "xmlrpc_attacks": True,
            "user_enumeration": [
                "/?author=1",
                "/wp-json/wp/v2/users",
            ],
        },
        "Joomla": {
            "paths": [
                ("/configuration.php.bak", "Joomla config backup exposed"),
                ("/configuration.php~", "Joomla config backup exposed"),
                ("/administrator/components/", "Directory listing"),
            ],
            "user_enumeration": [],
        },
        "Drupal": {
            "paths": [
                ("/CHANGELOG.txt", "Drupal version disclosure"),
                ("/core/CHANGELOG.txt", "Drupal version disclosure"),
                ("/user/register", "User registration enabled"),
            ],
            "user_enumeration": [],
        },
    }

    def __init__(self, target: str, callback: Callable = None, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.timeout = timeout
        self.result = CMSResult()

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def detect(self) -> CMSResult:
        """Main CMS detection method"""
        await self.emit("status", {"message": "Starting CMS detection..."})

        # Method 1: Check meta tags and page content
        content_cms = await self._check_page_content()

        # Method 2: Check paths
        if not self.result.detected:
            await self._check_cms_paths()

        # Method 3: Check headers and cookies
        if not self.result.detected:
            await self._check_headers_cookies()

        # If CMS detected, get version and check vulnerabilities
        if self.result.detected:
            await self._get_version()
            await self._check_cms_vulnerabilities()

            if self.result.cms_name == "WordPress":
                await self._enumerate_wordpress()

        await self.emit("cms_detection_complete", self.result.__dict__)
        return self.result

    async def _check_page_content(self) -> Optional[str]:
        """Check page content for CMS signatures"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                    headers={"User-Agent": random.choice(USER_AGENTS)}
                ) as resp:
                    content = await resp.text()
                    content_lower = content.lower()

                    for cms_name, signatures in self.CMS_SIGNATURES.items():
                        evidence = []

                        for meta in signatures["meta"]:
                            if meta.lower() in content_lower:
                                evidence.append(f"Content match: {meta}")

                        if evidence:
                            self.result.detected = True
                            self.result.cms_name = cms_name
                            self.result.evidence = evidence
                            self.result.confidence = "high" if len(evidence) >= 2 else "medium"
                            return cms_name

        except Exception:
            pass

        return None

    async def _check_cms_paths(self):
        """Check for CMS-specific paths"""
        for cms_name, signatures in self.CMS_SIGNATURES.items():
            for path in signatures["paths"][:3]:  # Check first 3 paths
                try:
                    url = f"{self.target}{path}"
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False,
                            allow_redirects=False
                        ) as resp:
                            if resp.status in [200, 301, 302, 403]:
                                self.result.detected = True
                                self.result.cms_name = cms_name
                                self.result.evidence.append(f"Path found: {path}")
                                self.result.confidence = "medium"
                                return

                except Exception:
                    pass

    async def _check_headers_cookies(self):
        """Check headers and cookies for CMS signatures"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    cookies = {k.lower(): v.value for k, v in resp.cookies.items()}

                    for cms_name, signatures in self.CMS_SIGNATURES.items():
                        evidence = []

                        # Check headers
                        for header in signatures["headers"]:
                            for h_name, h_value in headers.items():
                                if header.lower() in h_name or header.lower() in h_value.lower():
                                    evidence.append(f"Header found: {header}")

                        # Check cookies
                        for cookie in signatures["cookies"]:
                            for c_name in cookies.keys():
                                if cookie.lower() in c_name:
                                    evidence.append(f"Cookie found: {c_name}")

                        if evidence:
                            self.result.detected = True
                            self.result.cms_name = cms_name
                            self.result.evidence.extend(evidence)
                            self.result.confidence = "low"
                            return

        except Exception:
            pass

    async def _get_version(self):
        """Try to get CMS version"""
        if not self.result.cms_name:
            return

        signatures = self.CMS_SIGNATURES.get(self.result.cms_name, {})
        version_paths = signatures.get("version_paths", [])

        for path in version_paths:
            try:
                url = f"{self.target}{path}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            version = self._extract_version(content)
                            if version:
                                self.result.version = version
                                self.result.evidence.append(f"Version: {version}")
                                return

            except Exception:
                pass

    def _extract_version(self, content: str) -> Optional[str]:
        """Extract version from content"""
        patterns = [
            r'version["\s:]+([0-9]+\.[0-9]+\.?[0-9]*)',
            r'v([0-9]+\.[0-9]+\.?[0-9]*)',
            r'([0-9]+\.[0-9]+\.?[0-9]*)',
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    async def _check_cms_vulnerabilities(self):
        """Check for CMS-specific vulnerabilities"""
        if not self.result.cms_name:
            return

        vuln_info = self.CMS_VULNERABILITIES.get(self.result.cms_name, {})
        vuln_paths = vuln_info.get("paths", [])

        for path, description in vuln_paths:
            try:
                url = f"{self.target}{path}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            content_length = len(await resp.text())
                            if content_length > 0:
                                self.result.vulnerabilities.append({
                                    "path": path,
                                    "description": description,
                                    "severity": "high" if "config" in path.lower() else "medium"
                                })

            except Exception:
                pass

    async def _enumerate_wordpress(self):
        """WordPress-specific enumeration"""
        # Enumerate users
        await self._wp_enumerate_users()

        # Enumerate plugins
        await self._wp_enumerate_plugins()

        # Enumerate themes
        await self._wp_enumerate_themes()

        # Check XMLRPC
        await self._wp_check_xmlrpc()

    async def _wp_enumerate_users(self):
        """Enumerate WordPress users"""
        users = []

        # Method 1: Author parameter
        for i in range(1, 11):
            try:
                url = f"{self.target}/?author={i}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False,
                        allow_redirects=True
                    ) as resp:
                        if resp.status == 200:
                            final_url = str(resp.url)
                            match = re.search(r'/author/([^/]+)', final_url)
                            if match:
                                users.append(match.group(1))

            except Exception:
                pass

        # Method 2: REST API
        try:
            url = f"{self.target}/wp-json/wp/v2/users"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for user in data:
                            if 'slug' in user:
                                users.append(user['slug'])

                        self.result.vulnerabilities.append({
                            "path": "/wp-json/wp/v2/users",
                            "description": "User enumeration via REST API",
                            "severity": "medium"
                        })

        except Exception:
            pass

        if users:
            self.result.evidence.append(f"Users found: {', '.join(set(users))}")

    async def _wp_enumerate_plugins(self):
        """Enumerate WordPress plugins"""
        common_plugins = [
            "akismet", "contact-form-7", "yoast-seo", "wordfence",
            "woocommerce", "jetpack", "elementor", "wpforms-lite",
            "classic-editor", "really-simple-ssl", "updraftplus",
            "duplicate-post", "all-in-one-seo-pack", "wp-super-cache"
        ]

        for plugin in common_plugins:
            try:
                url = f"{self.target}/wp-content/plugins/{plugin}/"
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as resp:
                        if resp.status in [200, 403]:
                            self.result.plugins.append(plugin)

            except Exception:
                pass

    async def _wp_enumerate_themes(self):
        """Enumerate WordPress themes"""
        common_themes = [
            "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
            "astra", "oceanwp", "generatepress", "neve", "flavor",
            "flavflavor", "flavor flavor flavor flavor flavor flavor flavor"
        ]

        for theme in common_themes:
            try:
                url = f"{self.target}/wp-content/themes/{theme}/"
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as resp:
                        if resp.status in [200, 403]:
                            self.result.themes.append(theme)

            except Exception:
                pass

    async def _wp_check_xmlrpc(self):
        """Check WordPress XMLRPC"""
        try:
            url = f"{self.target}/xmlrpc.php"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        if "XML-RPC server accepts POST requests only" in content:
                            self.result.vulnerabilities.append({
                                "path": "/xmlrpc.php",
                                "description": "XMLRPC enabled - vulnerable to brute force and DDoS amplification",
                                "severity": "medium"
                            })

        except Exception:
            pass


class TechStackDetector:
    """
    Technology Stack Detector
    Detects frameworks, libraries, and technologies
    """

    TECH_SIGNATURES = {
        # Frontend Frameworks
        "React": ["react", "_react", "__REACT_DEVTOOLS_GLOBAL_HOOK__"],
        "Vue.js": ["vue", "__VUE__", "vue-router"],
        "Angular": ["ng-", "angular", "ng-version"],
        "jQuery": ["jquery", "jQuery"],
        "Bootstrap": ["bootstrap", "btn-primary"],
        "Tailwind CSS": ["tailwind", "tw-"],

        # Backend Frameworks
        "Laravel": ["laravel", "csrf_token", "laravel_session"],
        "Django": ["csrfmiddlewaretoken", "django"],
        "Rails": ["rails", "_rails", "csrf-token"],
        "Express.js": ["express", "x-powered-by: express"],
        "ASP.NET": ["asp.net", "__viewstate", "__eventvalidation"],
        "Spring": ["spring", "jsessionid"],

        # Servers
        "Nginx": ["nginx"],
        "Apache": ["apache", "mod_"],
        "IIS": ["iis", "microsoft-iis"],
        "LiteSpeed": ["litespeed"],

        # CDNs
        "Cloudflare": ["cloudflare", "cf-ray"],
        "Akamai": ["akamai"],
        "Fastly": ["fastly"],
        "AWS CloudFront": ["cloudfront"],

        # Analytics
        "Google Analytics": ["google-analytics", "ga(", "gtag"],
        "Google Tag Manager": ["googletagmanager"],
        "Facebook Pixel": ["facebook.com/tr", "fbq("],
        "Hotjar": ["hotjar"],

        # Other
        "PHP": ["php", ".php", "x-powered-by: php"],
        "Node.js": ["node", "x-powered-by: express"],
        "Python": ["python", "wsgi"],
        "Java": ["java", "jsessionid"],
    }

    def __init__(self, target: str, callback: Callable = None, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.timeout = timeout
        self.technologies: Dict[str, List[str]] = {}

    async def detect(self) -> Dict[str, List[str]]:
        """Detect technology stack"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                    headers={"User-Agent": random.choice(USER_AGENTS)}
                ) as resp:
                    content = await resp.text()
                    headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                    content_lower = content.lower()

                    for tech, signatures in self.TECH_SIGNATURES.items():
                        for sig in signatures:
                            sig_lower = sig.lower()

                            # Check in content
                            if sig_lower in content_lower:
                                if tech not in self.technologies:
                                    self.technologies[tech] = []
                                self.technologies[tech].append(f"Content: {sig}")
                                break

                            # Check in headers
                            for header_name, header_value in headers.items():
                                if sig_lower in header_name or sig_lower in header_value:
                                    if tech not in self.technologies:
                                        self.technologies[tech] = []
                                    self.technologies[tech].append(f"Header: {sig}")
                                    break

        except Exception:
            pass

        return self.technologies
