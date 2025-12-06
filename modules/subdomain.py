"""
ReconBuster Subdomain Enumeration Module
Properly integrated from: Sublist3r, subfinder, theHarvester
Sources: 15+ active sources for maximum subdomain discovery
"""

import asyncio
import aiohttp
import re
import json
import random
from typing import List, Dict, Set, Callable, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, quote
from bs4 import BeautifulSoup
from .utils import (
    AsyncHTTPClient, DNSResolver, SubdomainResult,
    normalize_url, is_valid_domain, colorize, extract_title, extract_server
)

# User agents for search engine scraping
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]


class SubdomainEnumerator:
    """
    Advanced subdomain enumeration combining 15+ sources
    Based on Sublist3r and subfinder techniques

    Sources:
    - Certificate Transparency: crt.sh, CertSpotter
    - DNS Databases: HackerTarget, AlienVault OTX, BufferOver, RapidDNS
    - Web Archives: Wayback Machine
    - Threat Intel: ThreatCrowd, VirusTotal
    - Search Engines: Google (via scraping patterns)
    - Passive DNS: PassiveDNS API, DNSDumpster
    - Other: Anubis, URLScan
    """

    def __init__(self, domain: str, callback: Callable = None,
                 threads: int = 50, timeout: int = 15,
                 verify_ssl: bool = False):
        self.domain = domain.lower().strip().replace('http://', '').replace('https://', '').split('/')[0]
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self.subdomains: Set[str] = set()
        self.results: List[SubdomainResult] = []
        self.dns_resolver = DNSResolver()

        # Statistics
        self.stats = {
            "total_found": 0,
            "alive": 0,
            "sources_checked": 0,
            "sources_success": 0,
            "errors": 0
        }

        # Session headers
        self.headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }

    async def emit(self, event: str, data: dict):
        """Emit event to callback"""
        if self.callback:
            try:
                if asyncio.iscoroutinefunction(self.callback):
                    await self.callback(event, data)
                else:
                    self.callback(event, data)
            except:
                pass

    async def enumerate(self) -> List[SubdomainResult]:
        """Main enumeration method - runs all sources"""
        await self.emit("status", {"message": f"Starting subdomain enumeration for {self.domain}"})

        # Run all passive sources concurrently
        sources = [
            ("crt.sh", self._crtsh),
            ("CertSpotter", self._certspotter),
            ("HackerTarget", self._hackertarget),
            ("AlienVault", self._alienvault),
            ("URLScan", self._urlscan),
            ("RapidDNS", self._rapiddns),
            ("BufferOver", self._bufferover),
            ("Wayback", self._webarchive),
            ("ThreatCrowd", self._threatcrowd),
            ("VirusTotal", self._virustotal),
            ("Anubis", self._anubis),
            ("DNSDumpster", self._dnsdumpster),
            ("Omnisint", self._omnisint),
            ("Synapsint", self._synapsint),
        ]

        # Create tasks for all sources
        tasks = []
        for source_name, source_func in sources:
            tasks.append(self._run_source(source_name, source_func))

        # Run all sources concurrently
        await asyncio.gather(*tasks, return_exceptions=True)

        await self.emit("status", {
            "message": f"Found {len(self.subdomains)} unique subdomains from {self.stats['sources_success']}/{self.stats['sources_checked']} sources"
        })

        # Verify and probe discovered subdomains
        if self.subdomains:
            await self._verify_subdomains()

        self.stats["total_found"] = len(self.results)
        self.stats["alive"] = len([r for r in self.results if r.is_alive])

        await self.emit("complete", {
            "subdomains": [r.__dict__ for r in self.results],
            "stats": self.stats
        })

        return self.results

    async def _run_source(self, source_name: str, source_func):
        """Run a single source with error handling"""
        self.stats["sources_checked"] += 1
        try:
            await self.emit("source_start", {"source": source_name})
            count_before = len(self.subdomains)
            await source_func()
            count_after = len(self.subdomains)
            found = count_after - count_before

            if found > 0:
                self.stats["sources_success"] += 1
                await self.emit("source_complete", {
                    "source": source_name,
                    "found": found,
                    "total": len(self.subdomains)
                })
            else:
                await self.emit("source_complete", {
                    "source": source_name,
                    "found": 0,
                    "total": len(self.subdomains)
                })
        except Exception as e:
            self.stats["errors"] += 1
            await self.emit("source_error", {"source": source_name, "error": str(e)})

    def _add_subdomain(self, subdomain: str, source: str):
        """Add subdomain to set if valid"""
        if not subdomain:
            return

        subdomain = subdomain.lower().strip()

        # Remove wildcards
        subdomain = subdomain.replace('*.', '')

        # Validate subdomain belongs to target domain
        if not subdomain.endswith(f".{self.domain}") and subdomain != self.domain:
            return

        # Basic validation - must be valid hostname
        if not re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$', subdomain):
            return

        if subdomain not in self.subdomains:
            self.subdomains.add(subdomain)
            # Emit found event
            asyncio.create_task(self.emit("found", {
                "subdomain": subdomain,
                "source": source
            }))

    async def _fetch_url(self, url: str, timeout: int = None) -> Optional[str]:
        """Fetch URL with timeout and error handling"""
        timeout = timeout or self.timeout
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    url,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True
                ) as resp:
                    if resp.status == 200:
                        return await resp.text()
        except Exception:
            pass
        return None

    async def _fetch_json(self, url: str, timeout: int = None) -> Optional[dict]:
        """Fetch JSON with timeout and error handling"""
        timeout = timeout or self.timeout
        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=10)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    url,
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception:
            pass
        return None

    # ==================== SOURCE IMPLEMENTATIONS ====================

    async def _crtsh(self):
        """Certificate Transparency via crt.sh - Usually returns MANY results"""
        source = "crt.sh"
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"

        data = await self._fetch_json(url, timeout=30)
        if data:
            for entry in data:
                name_value = entry.get("name_value", "")
                # Split by newlines (crt.sh returns multiple names per cert)
                for name in name_value.split("\n"):
                    name = name.strip().replace("*.", "")
                    if name:
                        self._add_subdomain(name, source)

    async def _certspotter(self):
        """CertSpotter API"""
        source = "CertSpotter"
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"

        data = await self._fetch_json(url, timeout=20)
        if data and isinstance(data, list):
            for cert in data:
                for name in cert.get("dns_names", []):
                    name = name.replace("*.", "")
                    self._add_subdomain(name, source)

    async def _hackertarget(self):
        """HackerTarget API - Free and reliable"""
        source = "HackerTarget"
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"

        text = await self._fetch_url(url, timeout=20)
        if text and "error" not in text.lower() and "API count exceeded" not in text:
            for line in text.split("\n"):
                if "," in line:
                    subdomain = line.split(",")[0].strip()
                    self._add_subdomain(subdomain, source)

    async def _alienvault(self):
        """AlienVault OTX Passive DNS"""
        source = "AlienVault"
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"

        data = await self._fetch_json(url, timeout=20)
        if data:
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                self._add_subdomain(hostname, source)

    async def _urlscan(self):
        """URLScan.io"""
        source = "URLScan"
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000"

        data = await self._fetch_json(url, timeout=20)
        if data:
            for result in data.get("results", []):
                page = result.get("page", {})
                domain = page.get("domain", "")
                self._add_subdomain(domain, source)

    async def _rapiddns(self):
        """RapidDNS - Web scraping"""
        source = "RapidDNS"
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"

        html = await self._fetch_url(url, timeout=20)
        if html:
            # Parse with regex for speed
            pattern = r'<td>([a-zA-Z0-9\.\-]+\.' + re.escape(self.domain) + r')</td>'
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                self._add_subdomain(match, source)

    async def _bufferover(self):
        """BufferOver Run DNS"""
        source = "BufferOver"
        url = f"https://dns.bufferover.run/dns?q=.{self.domain}"

        data = await self._fetch_json(url, timeout=20)
        if data:
            # FDNS_A records
            for entry in data.get("FDNS_A", []) or []:
                if "," in str(entry):
                    subdomain = entry.split(",")[1]
                    self._add_subdomain(subdomain, source)
            # RDNS records
            for entry in data.get("RDNS", []) or []:
                if "," in str(entry):
                    subdomain = entry.split(",")[1]
                    self._add_subdomain(subdomain, source)

    async def _webarchive(self):
        """Wayback Machine / Web Archive"""
        source = "Wayback"
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"

        data = await self._fetch_json(url, timeout=30)
        if data and len(data) > 1:
            for entry in data[1:]:  # Skip header row
                if entry:
                    original_url = entry[0] if isinstance(entry, list) else entry
                    # Extract domain from URL
                    match = re.search(r'https?://([^/]+)', str(original_url))
                    if match:
                        subdomain = match.group(1).split(':')[0]
                        self._add_subdomain(subdomain, source)

    async def _threatcrowd(self):
        """ThreatCrowd API"""
        source = "ThreatCrowd"
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"

        data = await self._fetch_json(url, timeout=20)
        if data:
            for subdomain in data.get("subdomains", []) or []:
                self._add_subdomain(subdomain, source)

    async def _virustotal(self):
        """VirusTotal (public endpoint)"""
        source = "VirusTotal"
        url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40"

        data = await self._fetch_json(url, timeout=20)
        if data:
            for item in data.get("data", []):
                subdomain = item.get("id", "")
                self._add_subdomain(subdomain, source)

    async def _anubis(self):
        """Anubis DB"""
        source = "Anubis"
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"

        data = await self._fetch_json(url, timeout=20)
        if data and isinstance(data, list):
            for subdomain in data:
                self._add_subdomain(subdomain, source)

    async def _dnsdumpster(self):
        """DNSDumpster - requires CSRF token"""
        source = "DNSDumpster"
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                # Get CSRF token
                async with session.get(
                    "https://dnsdumpster.com/",
                    headers=self.headers,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    html = await resp.text()
                    cookies = resp.cookies

                    # Extract CSRF token
                    csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
                    if not csrf_match:
                        return

                    csrf_token = csrf_match.group(1)

                    # Make POST request
                    post_headers = dict(self.headers)
                    post_headers['Referer'] = 'https://dnsdumpster.com/'
                    post_headers['Content-Type'] = 'application/x-www-form-urlencoded'

                    async with session.post(
                        "https://dnsdumpster.com/",
                        data={'csrfmiddlewaretoken': csrf_token, 'targetip': self.domain},
                        headers=post_headers,
                        cookies=cookies,
                        timeout=aiohttp.ClientTimeout(total=20)
                    ) as post_resp:
                        html = await post_resp.text()

                        # Extract subdomains from table
                        pattern = r'<td class="col-md-4">([a-zA-Z0-9\.\-]+\.' + re.escape(self.domain) + r')<br>'
                        matches = re.findall(pattern, html, re.IGNORECASE)
                        for match in matches:
                            self._add_subdomain(match, source)
        except Exception:
            pass

    async def _omnisint(self):
        """Omnisint/Sonar - Project Sonar data"""
        source = "Omnisint"
        url = f"https://sonar.omnisint.io/subdomains/{self.domain}"

        data = await self._fetch_json(url, timeout=20)
        if data and isinstance(data, list):
            for subdomain in data:
                self._add_subdomain(subdomain, source)

    async def _synapsint(self):
        """Synapsint API"""
        source = "Synapsint"
        url = f"https://synapsint.com/report.php?name={self.domain}"

        html = await self._fetch_url(url, timeout=20)
        if html:
            # Extract subdomains from response
            pattern = r'([a-zA-Z0-9\.\-]+\.' + re.escape(self.domain) + r')'
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in set(matches):
                self._add_subdomain(match, source)

    # ==================== VERIFICATION ====================

    async def _verify_subdomain(self, subdomain: str) -> SubdomainResult:
        """Verify and probe a single subdomain"""
        result = SubdomainResult(
            subdomain=subdomain,
            source="passive"
        )

        # DNS Resolution
        ip = await self.dns_resolver.get_ip(subdomain)
        if ip:
            result.ip_address = ip
            result.is_alive = True

            # CNAME check for takeover detection
            cname = await self.dns_resolver.get_cname(subdomain)
            if cname:
                result.cname = cname

        # HTTP Probing
        if result.is_alive:
            await self._probe_http(result)

        return result

    async def _probe_http(self, result: SubdomainResult):
        """Probe HTTP/HTTPS services"""
        subdomain = result.subdomain

        try:
            connector = aiohttp.TCPConnector(ssl=False, limit=5)
            async with aiohttp.ClientSession(connector=connector) as session:
                # Try HTTPS first
                try:
                    async with session.get(
                        f"https://{subdomain}",
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=True,
                        headers={"User-Agent": random.choice(USER_AGENTS)}
                    ) as resp:
                        result.https_status = resp.status
                        if resp.status in [200, 301, 302, 403, 401]:
                            html = await resp.text()
                            result.title = extract_title(html[:5000])
                            result.server = resp.headers.get('Server', '')
                except:
                    pass

                # Try HTTP
                try:
                    async with session.get(
                        f"http://{subdomain}",
                        timeout=aiohttp.ClientTimeout(total=8),
                        allow_redirects=True,
                        headers={"User-Agent": random.choice(USER_AGENTS)}
                    ) as resp:
                        result.http_status = resp.status
                        if not result.title and resp.status in [200, 301, 302, 403, 401]:
                            html = await resp.text()
                            result.title = extract_title(html[:5000])
                            if not result.server:
                                result.server = resp.headers.get('Server', '')
                except:
                    pass
        except:
            pass

    async def _verify_subdomains(self):
        """Verify all discovered subdomains"""
        await self.emit("status", {"message": f"Verifying {len(self.subdomains)} subdomains..."})

        semaphore = asyncio.Semaphore(self.threads)

        async def verify_with_semaphore(subdomain):
            async with semaphore:
                return await self._verify_subdomain(subdomain)

        tasks = [verify_with_semaphore(sub) for sub in self.subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, SubdomainResult):
                self.results.append(result)
                await self.emit("verified", {"subdomain": result.__dict__})

    def get_alive_subdomains(self) -> List[str]:
        """Get list of alive subdomain hostnames"""
        return [r.subdomain for r in self.results if r.is_alive]

    def get_403_targets(self) -> List[str]:
        """Get subdomains returning 403 - targets for bypass"""
        targets = []
        for r in self.results:
            if r.http_status == 403:
                targets.append(f"http://{r.subdomain}")
            if r.https_status == 403:
                targets.append(f"https://{r.subdomain}")
        return targets

    def get_all_urls(self) -> List[str]:
        """Get all live URLs"""
        urls = []
        for r in self.results:
            if r.https_status in [200, 301, 302, 403, 401]:
                urls.append(f"https://{r.subdomain}")
            elif r.http_status in [200, 301, 302, 403, 401]:
                urls.append(f"http://{r.subdomain}")
        return urls
