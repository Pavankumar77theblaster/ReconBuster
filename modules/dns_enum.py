"""
ReconBuster DNS Enumeration Module
Advanced DNS reconnaissance and zone transfer testing
"""

import asyncio
import socket
import random
from typing import List, Dict, Optional, Callable, Set
from dataclasses import dataclass, field
from datetime import datetime

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


@dataclass
class DNSRecord:
    """DNS Record information"""
    name: str
    record_type: str
    value: str
    ttl: int = 0


@dataclass
class DNSResult:
    """DNS Enumeration Result"""
    domain: str
    nameservers: List[str] = field(default_factory=list)
    mx_records: List[DNSRecord] = field(default_factory=list)
    a_records: List[DNSRecord] = field(default_factory=list)
    aaaa_records: List[DNSRecord] = field(default_factory=list)
    cname_records: List[DNSRecord] = field(default_factory=list)
    txt_records: List[DNSRecord] = field(default_factory=list)
    soa_record: Optional[DNSRecord] = None
    zone_transfer_possible: bool = False
    zone_data: List[str] = field(default_factory=list)
    subdomains: Set[str] = field(default_factory=set)
    vulnerabilities: List[Dict] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class DNSEnumerator:
    """
    Advanced DNS Enumeration
    Features:
    - DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME)
    - Zone transfer attempts
    - Subdomain brute-forcing
    - DNS security analysis
    - Reverse DNS lookups
    """

    # Common subdomain wordlist
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
        "admin", "administrator", "cpanel", "whm", "panel",
        "api", "dev", "development", "staging", "stage", "test", "testing",
        "beta", "alpha", "demo", "preview", "sandbox",
        "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
        "mx", "mx1", "mx2", "mail1", "mail2",
        "vpn", "remote", "secure", "gateway", "proxy",
        "cdn", "static", "assets", "media", "images", "img",
        "app", "apps", "mobile", "m", "wap",
        "blog", "news", "forum", "community", "support",
        "shop", "store", "cart", "checkout", "payment",
        "portal", "intranet", "extranet", "internal",
        "backup", "bak", "old", "new", "v2", "v3",
        "db", "database", "sql", "mysql", "mongo", "redis",
        "git", "svn", "jenkins", "ci", "build",
        "grafana", "kibana", "elastic", "prometheus",
        "autodiscover", "autoconfig", "exchange",
        "cloud", "aws", "azure", "gcp",
        "sso", "auth", "oauth", "login", "signin",
        "cms", "wp", "wordpress", "joomla", "drupal",
    ]

    def __init__(self, domain: str, callback: Callable = None,
                 nameservers: List[str] = None, timeout: int = 5):
        self.domain = domain.lower().strip()
        self.callback = callback
        self.timeout = timeout
        self.result = DNSResult(domain=self.domain)

        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            if nameservers:
                self.resolver.nameservers = nameservers
            else:
                self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout
        else:
            self.resolver = None

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def enumerate(self) -> DNSResult:
        """Main DNS enumeration method"""
        if not DNS_AVAILABLE:
            await self.emit("error", {"message": "dnspython not installed. Install with: pip install dnspython"})
            return self.result

        await self.emit("status", {"message": f"Starting DNS enumeration for {self.domain}"})

        # Get all DNS records
        await self._get_nameservers()
        await self._get_mx_records()
        await self._get_a_records()
        await self._get_aaaa_records()
        await self._get_txt_records()
        await self._get_soa_record()
        await self._get_cname_records()

        # Attempt zone transfer
        await self._attempt_zone_transfer()

        # Subdomain enumeration
        await self._enumerate_subdomains()

        # Security analysis
        await self._analyze_security()

        await self.emit("dns_enumeration_complete", {
            "domain": self.domain,
            "nameservers": self.result.nameservers,
            "subdomains": list(self.result.subdomains),
            "zone_transfer": self.result.zone_transfer_possible,
            "vulnerabilities": self.result.vulnerabilities
        })

        return self.result

    async def _get_nameservers(self):
        """Get NS records"""
        await self.emit("status", {"message": "Getting nameservers..."})
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(self.domain, 'NS')
            )
            for rdata in answers:
                ns = str(rdata).rstrip('.')
                self.result.nameservers.append(ns)

        except Exception as e:
            pass

    async def _get_mx_records(self):
        """Get MX records"""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(self.domain, 'MX')
            )
            for rdata in answers:
                record = DNSRecord(
                    name=self.domain,
                    record_type="MX",
                    value=f"{rdata.preference} {str(rdata.exchange).rstrip('.')}",
                    ttl=answers.rrset.ttl
                )
                self.result.mx_records.append(record)

        except Exception:
            pass

    async def _get_a_records(self):
        """Get A records"""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(self.domain, 'A')
            )
            for rdata in answers:
                record = DNSRecord(
                    name=self.domain,
                    record_type="A",
                    value=str(rdata),
                    ttl=answers.rrset.ttl
                )
                self.result.a_records.append(record)

        except Exception:
            pass

    async def _get_aaaa_records(self):
        """Get AAAA (IPv6) records"""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(self.domain, 'AAAA')
            )
            for rdata in answers:
                record = DNSRecord(
                    name=self.domain,
                    record_type="AAAA",
                    value=str(rdata),
                    ttl=answers.rrset.ttl
                )
                self.result.aaaa_records.append(record)

        except Exception:
            pass

    async def _get_txt_records(self):
        """Get TXT records"""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(self.domain, 'TXT')
            )
            for rdata in answers:
                record = DNSRecord(
                    name=self.domain,
                    record_type="TXT",
                    value=str(rdata),
                    ttl=answers.rrset.ttl
                )
                self.result.txt_records.append(record)

        except Exception:
            pass

    async def _get_soa_record(self):
        """Get SOA record"""
        try:
            loop = asyncio.get_event_loop()
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(self.domain, 'SOA')
            )
            for rdata in answers:
                self.result.soa_record = DNSRecord(
                    name=self.domain,
                    record_type="SOA",
                    value=str(rdata),
                    ttl=answers.rrset.ttl
                )

        except Exception:
            pass

    async def _get_cname_records(self):
        """Get CNAME records for common subdomains"""
        common_cname_hosts = ["www", "mail", "ftp", "cdn"]

        for host in common_cname_hosts:
            try:
                subdomain = f"{host}.{self.domain}"
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None,
                    lambda: self.resolver.resolve(subdomain, 'CNAME')
                )
                for rdata in answers:
                    record = DNSRecord(
                        name=subdomain,
                        record_type="CNAME",
                        value=str(rdata).rstrip('.'),
                        ttl=answers.rrset.ttl
                    )
                    self.result.cname_records.append(record)

            except Exception:
                pass

    async def _attempt_zone_transfer(self):
        """Attempt DNS zone transfer (AXFR)"""
        await self.emit("status", {"message": "Attempting zone transfer..."})

        for ns in self.result.nameservers:
            try:
                # Resolve NS to IP
                loop = asyncio.get_event_loop()
                ns_ip = await loop.run_in_executor(
                    None,
                    lambda: socket.gethostbyname(ns)
                )

                # Attempt zone transfer
                zone = await loop.run_in_executor(
                    None,
                    lambda: dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=self.timeout))
                )

                if zone:
                    self.result.zone_transfer_possible = True

                    for name, node in zone.nodes.items():
                        subdomain = str(name)
                        if subdomain != '@':
                            self.result.zone_data.append(subdomain)
                            self.result.subdomains.add(f"{subdomain}.{self.domain}")

                    self.result.vulnerabilities.append({
                        "type": "zone_transfer",
                        "severity": "critical",
                        "nameserver": ns,
                        "description": f"DNS Zone Transfer (AXFR) is possible from {ns}",
                        "remediation": "Restrict zone transfers to authorized secondary nameservers only"
                    })

                    await self.emit("zone_transfer_success", {
                        "nameserver": ns,
                        "records": len(self.result.zone_data)
                    })

                    break  # One successful is enough

            except Exception:
                pass

    async def _enumerate_subdomains(self):
        """Brute-force subdomain enumeration"""
        await self.emit("status", {"message": "Enumerating subdomains..."})

        semaphore = asyncio.Semaphore(50)

        async def check_subdomain(subdomain: str):
            async with semaphore:
                fqdn = f"{subdomain}.{self.domain}"
                try:
                    loop = asyncio.get_event_loop()
                    answers = await loop.run_in_executor(
                        None,
                        lambda: self.resolver.resolve(fqdn, 'A')
                    )
                    if answers:
                        self.result.subdomains.add(fqdn)
                        ip = str(answers[0])
                        await self.emit("subdomain_found", {"subdomain": fqdn, "ip": ip})
                        return fqdn, ip

                except Exception:
                    pass

                return None

        tasks = [check_subdomain(sub) for sub in self.COMMON_SUBDOMAINS]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _analyze_security(self):
        """Analyze DNS security"""
        # Check SPF record
        spf_found = False
        for txt in self.result.txt_records:
            if 'v=spf1' in txt.value.lower():
                spf_found = True
                if '+all' in txt.value.lower():
                    self.result.vulnerabilities.append({
                        "type": "weak_spf",
                        "severity": "high",
                        "description": "SPF record uses permissive '+all' mechanism",
                        "evidence": txt.value,
                        "remediation": "Use '-all' or '~all' instead of '+all'"
                    })

        if not spf_found:
            self.result.vulnerabilities.append({
                "type": "missing_spf",
                "severity": "medium",
                "description": "No SPF record found",
                "remediation": "Add an SPF record to prevent email spoofing"
            })

        # Check DMARC record
        try:
            loop = asyncio.get_event_loop()
            dmarc_answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
            )
            dmarc_found = False
            for rdata in dmarc_answers:
                if 'v=DMARC1' in str(rdata).upper():
                    dmarc_found = True
                    if 'p=none' in str(rdata).lower():
                        self.result.vulnerabilities.append({
                            "type": "weak_dmarc",
                            "severity": "medium",
                            "description": "DMARC policy is set to 'none' (monitoring only)",
                            "remediation": "Consider using 'quarantine' or 'reject' policy"
                        })
        except Exception:
            self.result.vulnerabilities.append({
                "type": "missing_dmarc",
                "severity": "medium",
                "description": "No DMARC record found",
                "remediation": "Add a DMARC record to improve email security"
            })

        # Check DKIM (common selectors)
        dkim_selectors = ["default", "google", "mail", "selector1", "selector2", "k1", "k2"]
        dkim_found = False

        for selector in dkim_selectors:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    lambda: self.resolver.resolve(f"{selector}._domainkey.{self.domain}", 'TXT')
                )
                dkim_found = True
                break
            except Exception:
                pass

        if not dkim_found:
            self.result.vulnerabilities.append({
                "type": "dkim_not_found",
                "severity": "low",
                "description": "DKIM record not found with common selectors",
                "remediation": "Ensure DKIM is configured for email authentication"
            })

        # Check DNSSEC
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(self.domain, 'DNSKEY')
            )
        except Exception:
            self.result.vulnerabilities.append({
                "type": "no_dnssec",
                "severity": "low",
                "description": "DNSSEC is not enabled for this domain",
                "remediation": "Consider enabling DNSSEC for additional DNS security"
            })

    async def reverse_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            loop = asyncio.get_event_loop()
            rev_name = dns.reversename.from_address(ip)
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(rev_name, 'PTR')
            )
            return str(answers[0]).rstrip('.')
        except Exception:
            return None


class DNSSecurityChecker:
    """
    DNS Security Analysis
    """

    def __init__(self, domain: str, callback: Callable = None):
        self.domain = domain
        self.callback = callback

    async def check_all(self) -> Dict:
        """Run all DNS security checks"""
        enumerator = DNSEnumerator(self.domain, self.callback)
        result = await enumerator.enumerate()

        return {
            "domain": self.domain,
            "nameservers": result.nameservers,
            "zone_transfer_vulnerable": result.zone_transfer_possible,
            "subdomains_found": len(result.subdomains),
            "vulnerabilities": result.vulnerabilities,
            "records": {
                "a": len(result.a_records),
                "aaaa": len(result.aaaa_records),
                "mx": len(result.mx_records),
                "txt": len(result.txt_records),
            }
        }
