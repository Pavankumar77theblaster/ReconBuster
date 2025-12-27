"""
ReconBuster SSL/TLS Security Analyzer
Analyzes SSL/TLS configuration and identifies vulnerabilities
"""

import asyncio
import ssl
import socket
import re
from typing import List, Dict, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from .utils import normalize_url, extract_domain


@dataclass
class SSLCertInfo:
    """SSL Certificate Information"""
    subject: Dict = field(default_factory=dict)
    issuer: Dict = field(default_factory=dict)
    version: int = 0
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int = 0
    is_expired: bool = False
    is_self_signed: bool = False
    signature_algorithm: str = ""
    san: List[str] = field(default_factory=list)
    key_size: int = 0
    key_type: str = ""


@dataclass
class SSLVulnerability:
    """SSL/TLS Vulnerability"""
    name: str
    severity: str  # critical, high, medium, low, info
    description: str
    remediation: str
    cve: str = ""
    evidence: str = ""


@dataclass
class SSLResult:
    """Complete SSL Analysis Result"""
    target: str
    certificate: SSLCertInfo = None
    supported_protocols: List[str] = field(default_factory=list)
    supported_ciphers: List[str] = field(default_factory=list)
    vulnerabilities: List[SSLVulnerability] = field(default_factory=list)
    score: str = ""  # A+, A, B, C, D, F
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class SSLAnalyzer:
    """
    SSL/TLS Security Analyzer
    Checks for:
    - Certificate validity and expiration
    - Weak protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    - Weak ciphers
    - Known vulnerabilities (Heartbleed, POODLE, BEAST, etc.)
    - Security headers (HSTS)
    """

    # TLS Protocol versions
    TLS_VERSIONS = {
        "SSLv2": ssl.PROTOCOL_SSLv23,  # Will test specifically
        "SSLv3": ssl.PROTOCOL_SSLv23,
        "TLSv1.0": ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None,
        "TLSv1.1": ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None,
        "TLSv1.2": ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
        "TLSv1.3": None,  # Handled separately
    }

    # Weak cipher suites
    WEAK_CIPHERS = [
        "NULL", "EXPORT", "DES", "RC4", "RC2", "MD5",
        "ANON", "ADH", "AECDH", "3DES", "IDEA", "SEED"
    ]

    # Known SSL vulnerabilities
    SSL_VULNERABILITIES = {
        "heartbleed": {
            "name": "Heartbleed (CVE-2014-0160)",
            "severity": "critical",
            "description": "OpenSSL Heartbleed vulnerability allows attackers to read server memory.",
            "remediation": "Upgrade OpenSSL to 1.0.1g or later.",
            "cve": "CVE-2014-0160"
        },
        "poodle": {
            "name": "POODLE (CVE-2014-3566)",
            "severity": "high",
            "description": "SSLv3 POODLE vulnerability allows attackers to decrypt secure connections.",
            "remediation": "Disable SSLv3 on the server.",
            "cve": "CVE-2014-3566"
        },
        "beast": {
            "name": "BEAST (CVE-2011-3389)",
            "severity": "medium",
            "description": "TLS 1.0 vulnerability in CBC cipher mode.",
            "remediation": "Disable TLS 1.0 or use RC4 as workaround (not recommended).",
            "cve": "CVE-2011-3389"
        },
        "freak": {
            "name": "FREAK (CVE-2015-0204)",
            "severity": "high",
            "description": "Export-grade cipher downgrade attack.",
            "remediation": "Disable EXPORT cipher suites.",
            "cve": "CVE-2015-0204"
        },
        "logjam": {
            "name": "Logjam (CVE-2015-4000)",
            "severity": "high",
            "description": "Weak Diffie-Hellman key exchange vulnerability.",
            "remediation": "Use 2048-bit or larger DH groups.",
            "cve": "CVE-2015-4000"
        },
        "drown": {
            "name": "DROWN (CVE-2016-0800)",
            "severity": "critical",
            "description": "Cross-protocol attack using SSLv2.",
            "remediation": "Disable SSLv2 completely.",
            "cve": "CVE-2016-0800"
        },
        "sweet32": {
            "name": "Sweet32 (CVE-2016-2183)",
            "severity": "medium",
            "description": "Birthday attack on 64-bit block ciphers (3DES, Blowfish).",
            "remediation": "Disable 64-bit block ciphers like 3DES.",
            "cve": "CVE-2016-2183"
        },
        "robot": {
            "name": "ROBOT (CVE-2017-13099)",
            "severity": "high",
            "description": "Return Of Bleichenbacher's Oracle Threat in TLS.",
            "remediation": "Update TLS implementation and disable RSA encryption.",
            "cve": "CVE-2017-13099"
        },
    }

    def __init__(self, target: str, callback: Callable = None,
                 port: int = 443, timeout: int = 10):
        self.target = extract_domain(normalize_url(target))
        self.callback = callback
        self.port = port
        self.timeout = timeout
        self.result = SSLResult(target=self.target)

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def analyze(self) -> SSLResult:
        """Main SSL analysis method"""
        await self.emit("status", {"message": f"Analyzing SSL/TLS on {self.target}:{self.port}"})

        # Get certificate info
        await self._get_certificate_info()

        # Check supported protocols
        await self._check_protocols()

        # Check cipher suites
        await self._check_ciphers()

        # Check for vulnerabilities
        await self._check_vulnerabilities()

        # Calculate score
        self._calculate_score()

        await self.emit("ssl_analysis_complete", {
            "certificate": self.result.certificate.__dict__ if self.result.certificate else None,
            "protocols": self.result.supported_protocols,
            "vulnerabilities": [v.__dict__ for v in self.result.vulnerabilities],
            "score": self.result.score
        })

        return self.result

    async def _get_certificate_info(self):
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()

            def get_cert():
                with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        cert_bin = ssock.getpeercert(binary_form=True)
                        cipher = ssock.cipher()
                        return cert, cert_bin, cipher

            cert, cert_bin, cipher = await loop.run_in_executor(None, get_cert)

            if cert:
                cert_info = SSLCertInfo()

                # Parse subject
                if 'subject' in cert:
                    for item in cert['subject']:
                        for key, value in item:
                            cert_info.subject[key] = value

                # Parse issuer
                if 'issuer' in cert:
                    for item in cert['issuer']:
                        for key, value in item:
                            cert_info.issuer[key] = value

                # Dates
                if 'notBefore' in cert:
                    cert_info.not_before = cert['notBefore']

                if 'notAfter' in cert:
                    cert_info.not_after = cert['notAfter']
                    # Calculate days until expiry
                    try:
                        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        cert_info.days_until_expiry = (expiry - datetime.now()).days
                        cert_info.is_expired = cert_info.days_until_expiry < 0
                    except:
                        pass

                # Serial number
                if 'serialNumber' in cert:
                    cert_info.serial_number = cert['serialNumber']

                # Subject Alternative Names
                if 'subjectAltName' in cert:
                    cert_info.san = [name for _, name in cert['subjectAltName']]

                # Check if self-signed
                cert_info.is_self_signed = cert_info.subject == cert_info.issuer

                self.result.certificate = cert_info

                # Add vulnerabilities for certificate issues
                if cert_info.is_expired:
                    self.result.vulnerabilities.append(SSLVulnerability(
                        name="Expired Certificate",
                        severity="critical",
                        description=f"The SSL certificate expired {abs(cert_info.days_until_expiry)} days ago.",
                        remediation="Renew the SSL certificate immediately."
                    ))
                elif cert_info.days_until_expiry < 30:
                    self.result.vulnerabilities.append(SSLVulnerability(
                        name="Certificate Expiring Soon",
                        severity="medium",
                        description=f"The SSL certificate expires in {cert_info.days_until_expiry} days.",
                        remediation="Renew the SSL certificate before expiration."
                    ))

                if cert_info.is_self_signed:
                    self.result.vulnerabilities.append(SSLVulnerability(
                        name="Self-Signed Certificate",
                        severity="medium",
                        description="The SSL certificate is self-signed and not trusted by browsers.",
                        remediation="Use a certificate from a trusted Certificate Authority."
                    ))

        except Exception as e:
            await self.emit("error", {"message": f"Failed to get certificate: {str(e)}"})

    async def _check_protocols(self):
        """Check supported SSL/TLS protocols"""
        await self.emit("status", {"message": "Checking supported protocols..."})

        protocols_to_test = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl, 'TLSVersion') else None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl, 'TLSVersion') else None),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2 if hasattr(ssl, 'TLSVersion') else None),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl, 'TLSVersion') else None),
        ]

        for proto_name, proto_version in protocols_to_test:
            if await self._test_protocol(proto_name, proto_version):
                self.result.supported_protocols.append(proto_name)

        # Check for weak protocols
        weak_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
        for weak in weak_protocols:
            if weak in self.result.supported_protocols:
                self.result.vulnerabilities.append(SSLVulnerability(
                    name=f"Weak Protocol: {weak}",
                    severity="high" if weak in ["SSLv2", "SSLv3"] else "medium",
                    description=f"The server supports the deprecated {weak} protocol.",
                    remediation=f"Disable {weak} on the server."
                ))

    async def _test_protocol(self, proto_name: str, proto_version) -> bool:
        """Test if a protocol is supported"""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            if proto_version and hasattr(context, 'minimum_version'):
                context.minimum_version = proto_version
                context.maximum_version = proto_version

            loop = asyncio.get_event_loop()

            def test():
                with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        return True

            return await loop.run_in_executor(None, test)

        except:
            return False

    async def _check_ciphers(self):
        """Check supported cipher suites"""
        await self.emit("status", {"message": "Checking cipher suites..."})

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()

            def get_ciphers():
                with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        return ssock.cipher()

            cipher = await loop.run_in_executor(None, get_ciphers)

            if cipher:
                cipher_name = cipher[0]
                self.result.supported_ciphers.append(cipher_name)

                # Check for weak ciphers
                for weak in self.WEAK_CIPHERS:
                    if weak.upper() in cipher_name.upper():
                        self.result.vulnerabilities.append(SSLVulnerability(
                            name=f"Weak Cipher: {cipher_name}",
                            severity="high" if weak in ["NULL", "EXPORT", "DES"] else "medium",
                            description=f"The server supports the weak cipher suite {cipher_name}.",
                            remediation="Disable weak cipher suites and use strong ciphers."
                        ))
                        break

        except Exception as e:
            pass

    async def _check_vulnerabilities(self):
        """Check for known SSL vulnerabilities"""
        await self.emit("status", {"message": "Checking for known vulnerabilities..."})

        # POODLE - SSLv3 support
        if "SSLv3" in self.result.supported_protocols:
            vuln = self.SSL_VULNERABILITIES["poodle"]
            self.result.vulnerabilities.append(SSLVulnerability(**vuln))

        # BEAST - TLS 1.0 with CBC
        if "TLSv1.0" in self.result.supported_protocols:
            vuln = self.SSL_VULNERABILITIES["beast"]
            self.result.vulnerabilities.append(SSLVulnerability(**vuln))

        # DROWN - SSLv2 support
        if "SSLv2" in self.result.supported_protocols:
            vuln = self.SSL_VULNERABILITIES["drown"]
            self.result.vulnerabilities.append(SSLVulnerability(**vuln))

        # Sweet32 - 3DES
        for cipher in self.result.supported_ciphers:
            if "3DES" in cipher or "DES-CBC3" in cipher:
                vuln = self.SSL_VULNERABILITIES["sweet32"]
                self.result.vulnerabilities.append(SSLVulnerability(**vuln))
                break

        # FREAK - EXPORT ciphers
        for cipher in self.result.supported_ciphers:
            if "EXPORT" in cipher:
                vuln = self.SSL_VULNERABILITIES["freak"]
                self.result.vulnerabilities.append(SSLVulnerability(**vuln))
                break

    def _calculate_score(self):
        """Calculate SSL security score"""
        # Start with perfect score
        score = 100

        # Deduct for vulnerabilities
        for vuln in self.result.vulnerabilities:
            if vuln.severity == "critical":
                score -= 30
            elif vuln.severity == "high":
                score -= 20
            elif vuln.severity == "medium":
                score -= 10
            elif vuln.severity == "low":
                score -= 5

        # Deduct for missing TLS 1.3
        if "TLSv1.3" not in self.result.supported_protocols:
            score -= 5

        # Bonus for only TLS 1.2/1.3
        if self.result.supported_protocols == ["TLSv1.2", "TLSv1.3"]:
            score += 5
        elif self.result.supported_protocols == ["TLSv1.3"]:
            score += 10

        # Cap score
        score = max(0, min(100, score))

        # Convert to grade
        if score >= 95:
            self.result.score = "A+"
        elif score >= 85:
            self.result.score = "A"
        elif score >= 75:
            self.result.score = "B"
        elif score >= 65:
            self.result.score = "C"
        elif score >= 50:
            self.result.score = "D"
        else:
            self.result.score = "F"


class HSTSChecker:
    """
    HTTP Strict Transport Security (HSTS) Checker
    """

    def __init__(self, target: str, callback: Callable = None, timeout: int = 10):
        self.target = normalize_url(target)
        self.callback = callback
        self.timeout = timeout

    async def check(self) -> Dict:
        """Check HSTS configuration"""
        import aiohttp

        result = {
            "hsts_enabled": False,
            "max_age": 0,
            "include_subdomains": False,
            "preload": False,
            "issues": []
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}

                    if "strict-transport-security" in headers:
                        result["hsts_enabled"] = True
                        hsts = headers["strict-transport-security"]

                        # Parse max-age
                        match = re.search(r'max-age=(\d+)', hsts)
                        if match:
                            result["max_age"] = int(match.group(1))

                            # Check if max-age is sufficient
                            if result["max_age"] < 31536000:  # 1 year
                                result["issues"].append(
                                    "HSTS max-age is less than 1 year (recommended minimum)"
                                )

                        # Check includeSubDomains
                        if "includesubdomains" in hsts.lower():
                            result["include_subdomains"] = True

                        # Check preload
                        if "preload" in hsts.lower():
                            result["preload"] = True

                    else:
                        result["issues"].append("HSTS header is not present")

        except Exception as e:
            result["issues"].append(f"Error checking HSTS: {str(e)}")

        return result
