"""
ReconBuster API Security Scanner
Tests REST/GraphQL APIs for security vulnerabilities
"""

import asyncio
import aiohttp
import json
import random
import re
from typing import List, Dict, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urljoin
from .utils import normalize_url, USER_AGENTS


@dataclass
class APIEndpoint:
    """API Endpoint information"""
    url: str
    method: str = "GET"
    parameters: Dict = field(default_factory=dict)
    auth_required: bool = False
    response_code: int = 0
    content_type: str = ""


@dataclass
class APIVulnerability:
    """API Security Vulnerability"""
    endpoint: str
    vuln_type: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    owasp_api: str = ""  # OWASP API Security Top 10


@dataclass
class APISecurityResult:
    """API Security Scan Result"""
    target: str
    api_type: str = ""  # REST, GraphQL, SOAP
    endpoints_found: List[APIEndpoint] = field(default_factory=list)
    vulnerabilities: List[APIVulnerability] = field(default_factory=list)
    documentation: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class APIScanner:
    """
    API Security Scanner
    Checks for OWASP API Security Top 10 vulnerabilities
    """

    # Common API paths
    API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/v1", "/v2", "/v3",
        "/graphql", "/graphiql", "/playground",
        "/swagger", "/swagger.json", "/swagger.yaml",
        "/openapi", "/openapi.json", "/openapi.yaml",
        "/api-docs", "/docs", "/api/docs",
        "/redoc", "/rapidoc",
        "/.well-known/openapi.json",
        "/actuator", "/actuator/health", "/actuator/info",
        "/health", "/healthz", "/ready",
        "/metrics", "/prometheus",
    ]

    # Common API endpoints to test
    COMMON_ENDPOINTS = [
        "/users", "/user", "/account", "/accounts",
        "/auth", "/login", "/register", "/logout",
        "/admin", "/admin/users", "/admin/config",
        "/config", "/settings", "/configuration",
        "/debug", "/debug/vars", "/debug/pprof",
        "/internal", "/private", "/secret",
        "/backup", "/dump", "/export",
        "/upload", "/download", "/files",
        "/search", "/query",
        "/items", "/products", "/orders",
    ]

    # GraphQL introspection query
    GRAPHQL_INTROSPECTION = '''
    {
        __schema {
            types {
                name
                fields {
                    name
                }
            }
        }
    }
    '''

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 20, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.result = APISecurityResult(target=self.target)

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def scan(self) -> APISecurityResult:
        """Main API scanning method"""
        await self.emit("status", {"message": "Starting API security scan..."})

        # Discover API endpoints
        await self._discover_api_endpoints()

        # Check for documentation exposure
        await self._check_api_documentation()

        # Check for GraphQL
        await self._check_graphql()

        # Test OWASP API Top 10
        await self._check_broken_auth()
        await self._check_excessive_data()
        await self._check_rate_limiting()
        await self._check_bola()
        await self._check_security_misconfig()
        await self._check_injection()
        await self._check_mass_assignment()

        await self.emit("api_scan_complete", {
            "endpoints": len(self.result.endpoints_found),
            "vulnerabilities": len(self.result.vulnerabilities),
            "results": [v.__dict__ for v in self.result.vulnerabilities]
        })

        return self.result

    async def _discover_api_endpoints(self):
        """Discover API endpoints"""
        await self.emit("status", {"message": "Discovering API endpoints..."})

        semaphore = asyncio.Semaphore(self.threads)

        async def check_path(path: str):
            async with semaphore:
                url = f"{self.target}{path}"
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False,
                            headers={"User-Agent": random.choice(USER_AGENTS)}
                        ) as resp:
                            if resp.status in [200, 201, 401, 403, 405]:
                                content_type = resp.headers.get("Content-Type", "")
                                endpoint = APIEndpoint(
                                    url=url,
                                    method="GET",
                                    auth_required=resp.status in [401, 403],
                                    response_code=resp.status,
                                    content_type=content_type
                                )
                                self.result.endpoints_found.append(endpoint)
                                await self.emit("endpoint_found", endpoint.__dict__)

                except Exception:
                    pass

        all_paths = self.API_PATHS + self.COMMON_ENDPOINTS
        tasks = [check_path(path) for path in all_paths]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _check_api_documentation(self):
        """Check for exposed API documentation"""
        doc_paths = [
            ("/swagger.json", "Swagger JSON"),
            ("/swagger.yaml", "Swagger YAML"),
            ("/openapi.json", "OpenAPI JSON"),
            ("/openapi.yaml", "OpenAPI YAML"),
            ("/api-docs", "API Documentation"),
            ("/swagger-ui.html", "Swagger UI"),
            ("/redoc", "ReDoc"),
            ("/graphiql", "GraphiQL"),
            ("/playground", "GraphQL Playground"),
        ]

        for path, doc_type in doc_paths:
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
                            if len(content) > 100:
                                self.result.documentation[doc_type] = url

                                self.result.vulnerabilities.append(APIVulnerability(
                                    endpoint=url,
                                    vuln_type="api_documentation_exposed",
                                    severity="medium",
                                    title=f"API Documentation Exposed: {doc_type}",
                                    description=f"API documentation is publicly accessible at {path}",
                                    evidence=f"Status: 200, Size: {len(content)} bytes",
                                    remediation="Restrict access to API documentation in production",
                                    owasp_api="API9:2023 - Improper Inventory Management"
                                ))

            except Exception:
                pass

    async def _check_graphql(self):
        """Check for GraphQL endpoints and vulnerabilities"""
        graphql_paths = ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql"]

        for path in graphql_paths:
            try:
                url = f"{self.target}{path}"

                # Check introspection
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json={"query": self.GRAPHQL_INTROSPECTION},
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False,
                        headers={"Content-Type": "application/json"}
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.json()
                            if "__schema" in str(content):
                                self.result.api_type = "GraphQL"
                                self.result.vulnerabilities.append(APIVulnerability(
                                    endpoint=url,
                                    vuln_type="graphql_introspection",
                                    severity="medium",
                                    title="GraphQL Introspection Enabled",
                                    description="GraphQL introspection is enabled, exposing the entire API schema",
                                    evidence="Introspection query returned schema",
                                    remediation="Disable introspection in production",
                                    owasp_api="API9:2023 - Improper Inventory Management"
                                ))

            except Exception:
                pass

    async def _check_broken_auth(self):
        """Check for broken authentication (OWASP API2)"""
        auth_endpoints = ["/login", "/auth", "/authenticate", "/api/login", "/api/auth"]

        for path in auth_endpoints:
            try:
                url = f"{self.target}{path}"
                async with aiohttp.ClientSession() as session:
                    # Test with empty credentials
                    async with session.post(
                        url,
                        json={"username": "", "password": ""},
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False,
                        headers={"Content-Type": "application/json"}
                    ) as resp:
                        if resp.status == 200:
                            self.result.vulnerabilities.append(APIVulnerability(
                                endpoint=url,
                                vuln_type="broken_authentication",
                                severity="critical",
                                title="Broken Authentication - Empty Credentials Accepted",
                                description="API accepts empty credentials for authentication",
                                evidence=f"Empty credentials returned status {resp.status}",
                                remediation="Implement proper authentication validation",
                                owasp_api="API2:2023 - Broken Authentication"
                            ))

            except Exception:
                pass

    async def _check_excessive_data(self):
        """Check for excessive data exposure (OWASP API3)"""
        for endpoint in self.result.endpoints_found[:10]:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        endpoint.url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            content = await resp.text()

                            # Check for sensitive data patterns
                            sensitive_patterns = [
                                (r'"password"\s*:', "Password field in response"),
                                (r'"secret"\s*:', "Secret field in response"),
                                (r'"token"\s*:\s*"[^"]{20,}"', "Token in response"),
                                (r'"api_key"\s*:', "API key in response"),
                                (r'"private_key"\s*:', "Private key in response"),
                                (r'"ssn"\s*:', "SSN in response"),
                                (r'"credit_card"\s*:', "Credit card in response"),
                            ]

                            for pattern, desc in sensitive_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    self.result.vulnerabilities.append(APIVulnerability(
                                        endpoint=endpoint.url,
                                        vuln_type="excessive_data_exposure",
                                        severity="high",
                                        title=f"Excessive Data Exposure: {desc}",
                                        description=f"API response contains sensitive data: {desc}",
                                        evidence=f"Pattern matched: {pattern}",
                                        remediation="Filter sensitive data from API responses",
                                        owasp_api="API3:2023 - Broken Object Property Level Authorization"
                                    ))
                                    break

            except Exception:
                pass

    async def _check_rate_limiting(self):
        """Check for lack of rate limiting (OWASP API4)"""
        test_endpoints = ["/login", "/api", "/search", "/users"]

        for path in test_endpoints:
            url = f"{self.target}{path}"
            success_count = 0

            try:
                async with aiohttp.ClientSession() as session:
                    # Make rapid requests
                    for _ in range(20):
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=2),
                            ssl=False
                        ) as resp:
                            if resp.status not in [429, 503]:
                                success_count += 1

                    if success_count >= 18:  # 90% success rate
                        self.result.vulnerabilities.append(APIVulnerability(
                            endpoint=url,
                            vuln_type="no_rate_limiting",
                            severity="medium",
                            title="Missing Rate Limiting",
                            description="API endpoint does not implement rate limiting",
                            evidence=f"{success_count}/20 rapid requests succeeded",
                            remediation="Implement rate limiting on all API endpoints",
                            owasp_api="API4:2023 - Unrestricted Resource Consumption"
                        ))
                        break

            except Exception:
                pass

    async def _check_bola(self):
        """Check for Broken Object Level Authorization (OWASP API1)"""
        # Test for IDOR vulnerabilities
        idor_patterns = [
            "/users/1", "/users/2", "/users/100",
            "/account/1", "/account/2",
            "/order/1", "/order/2",
            "/api/users/1", "/api/users/2",
        ]

        for path in idor_patterns:
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
                            if len(content) > 50:
                                self.result.vulnerabilities.append(APIVulnerability(
                                    endpoint=url,
                                    vuln_type="bola_potential",
                                    severity="high",
                                    title="Potential BOLA/IDOR Vulnerability",
                                    description=f"Object accessible via predictable ID: {path}",
                                    evidence=f"Status 200 with data returned",
                                    remediation="Implement proper authorization checks for object access",
                                    owasp_api="API1:2023 - Broken Object Level Authorization"
                                ))
                                break

            except Exception:
                pass

    async def _check_security_misconfig(self):
        """Check for security misconfiguration (OWASP API8)"""
        # Check for debug endpoints
        debug_paths = [
            "/debug", "/debug/vars", "/debug/pprof",
            "/actuator", "/actuator/env", "/actuator/heapdump",
            "/.env", "/config", "/phpinfo.php",
            "/server-status", "/server-info",
            "/trace", "/dump", "/metrics",
        ]

        for path in debug_paths:
            try:
                url = f"{self.target}{path}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            self.result.vulnerabilities.append(APIVulnerability(
                                endpoint=url,
                                vuln_type="security_misconfiguration",
                                severity="high",
                                title=f"Debug/Admin Endpoint Exposed: {path}",
                                description=f"Sensitive endpoint is publicly accessible",
                                evidence=f"Status: {resp.status}",
                                remediation="Disable debug endpoints in production",
                                owasp_api="API8:2023 - Security Misconfiguration"
                            ))

            except Exception:
                pass

    async def _check_injection(self):
        """Check for injection vulnerabilities (OWASP API10)"""
        # Basic injection tests
        injection_payloads = [
            ("'", "SQL Injection"),
            ("{{7*7}}", "Template Injection"),
            ("${7*7}", "Expression Language Injection"),
            ("<script>", "XSS"),
        ]

        for endpoint in self.result.endpoints_found[:5]:
            for payload, injection_type in injection_payloads:
                try:
                    url = f"{endpoint.url}?test={payload}"
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            content = await resp.text()

                            # Check for error-based detection
                            error_patterns = [
                                "sql syntax", "mysql", "postgresql",
                                "sqlite", "oracle", "49", "syntax error"
                            ]

                            for error in error_patterns:
                                if error.lower() in content.lower():
                                    self.result.vulnerabilities.append(APIVulnerability(
                                        endpoint=endpoint.url,
                                        vuln_type="injection",
                                        severity="critical",
                                        title=f"{injection_type} Detected",
                                        description=f"API endpoint vulnerable to {injection_type}",
                                        evidence=f"Error pattern found: {error}",
                                        remediation="Use parameterized queries and input validation",
                                        owasp_api="API10:2023 - Unsafe Consumption of APIs"
                                    ))
                                    break

                except Exception:
                    pass

    async def _check_mass_assignment(self):
        """Check for mass assignment vulnerabilities"""
        # Try to add extra fields in requests
        test_endpoints = ["/users", "/api/users", "/account", "/profile"]

        malicious_fields = {
            "role": "admin",
            "is_admin": True,
            "admin": True,
            "verified": True,
            "balance": 999999,
        }

        for path in test_endpoints:
            try:
                url = f"{self.target}{path}"
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json=malicious_fields,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False,
                        headers={"Content-Type": "application/json"}
                    ) as resp:
                        if resp.status in [200, 201]:
                            content = await resp.text()
                            if any(field in content for field in ["admin", "role", "verified"]):
                                self.result.vulnerabilities.append(APIVulnerability(
                                    endpoint=url,
                                    vuln_type="mass_assignment",
                                    severity="high",
                                    title="Potential Mass Assignment Vulnerability",
                                    description="API may accept unexpected fields in request",
                                    evidence="Admin/privileged fields accepted",
                                    remediation="Whitelist allowed fields in API requests",
                                    owasp_api="API6:2023 - Unrestricted Access to Sensitive Business Flows"
                                ))
                                break

            except Exception:
                pass


class CORSChecker:
    """
    CORS Misconfiguration Checker
    """

    def __init__(self, target: str, callback: Callable = None, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.timeout = timeout
        self.vulnerabilities: List[Dict] = []

    async def check(self) -> List[Dict]:
        """Check for CORS misconfigurations"""
        # Test origins
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            self.target.replace("https://", "https://evil."),
            f"https://{urlparse(self.target).netloc}.evil.com",
        ]

        for origin in test_origins:
            try:
                async with aiohttp.ClientSession() as session:
                    headers = {
                        "Origin": origin,
                        "User-Agent": random.choice(USER_AGENTS)
                    }

                    async with session.get(
                        self.target,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False,
                        headers=headers
                    ) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                        if acao == "*":
                            self.vulnerabilities.append({
                                "type": "cors_wildcard",
                                "severity": "high",
                                "description": "CORS allows all origins (*)",
                                "evidence": f"ACAO: {acao}",
                                "remediation": "Restrict allowed origins to trusted domains"
                            })

                        elif acao == origin and origin != self.target:
                            self.vulnerabilities.append({
                                "type": "cors_reflection",
                                "severity": "critical" if acac.lower() == "true" else "high",
                                "description": f"CORS reflects arbitrary origin: {origin}",
                                "evidence": f"ACAO: {acao}, ACAC: {acac}",
                                "remediation": "Validate allowed origins against a whitelist"
                            })

                        elif acao == "null":
                            self.vulnerabilities.append({
                                "type": "cors_null",
                                "severity": "medium",
                                "description": "CORS allows null origin",
                                "evidence": f"ACAO: {acao}",
                                "remediation": "Do not allow null origin"
                            })

            except Exception:
                pass

        return self.vulnerabilities


class SecurityHeadersChecker:
    """
    HTTP Security Headers Checker
    """

    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "description": "HSTS - Forces HTTPS",
            "severity": "high",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME sniffing",
            "severity": "medium",
            "recommendation": "Add: X-Content-Type-Options: nosniff"
        },
        "X-Frame-Options": {
            "description": "Clickjacking protection",
            "severity": "medium",
            "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
        },
        "X-XSS-Protection": {
            "description": "XSS filter (deprecated but still useful)",
            "severity": "low",
            "recommendation": "Add: X-XSS-Protection: 1; mode=block"
        },
        "Content-Security-Policy": {
            "description": "CSP - Prevents XSS and injection attacks",
            "severity": "high",
            "recommendation": "Add appropriate Content-Security-Policy header"
        },
        "Referrer-Policy": {
            "description": "Controls referrer information",
            "severity": "low",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
        },
        "Permissions-Policy": {
            "description": "Controls browser features",
            "severity": "low",
            "recommendation": "Add appropriate Permissions-Policy header"
        },
    }

    def __init__(self, target: str, callback: Callable = None, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.timeout = timeout

    async def check(self) -> Dict:
        """Check security headers"""
        result = {
            "present": [],
            "missing": [],
            "issues": [],
            "score": 0
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}

                    total = len(self.SECURITY_HEADERS)
                    present = 0

                    for header, info in self.SECURITY_HEADERS.items():
                        header_lower = header.lower()
                        if header_lower in headers:
                            present += 1
                            result["present"].append({
                                "header": header,
                                "value": headers[header_lower]
                            })

                            # Check for weak configurations
                            if header_lower == "strict-transport-security":
                                if "max-age=0" in headers[header_lower]:
                                    result["issues"].append({
                                        "header": header,
                                        "issue": "HSTS max-age is 0",
                                        "severity": "high"
                                    })
                        else:
                            result["missing"].append({
                                "header": header,
                                "severity": info["severity"],
                                "recommendation": info["recommendation"]
                            })

                    # Calculate score
                    result["score"] = int((present / total) * 100)

        except Exception as e:
            result["error"] = str(e)

        return result
