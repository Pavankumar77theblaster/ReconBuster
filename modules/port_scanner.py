"""
ReconBuster Port Scanner and Service Enumeration Module
Fast async port scanning with service detection
"""

import asyncio
import socket
import struct
import re
from typing import List, Dict, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from .utils import normalize_url, extract_domain


@dataclass
class PortResult:
    """Port scan result"""
    port: int
    state: str  # open, closed, filtered
    service: str = ""
    version: str = ""
    banner: str = ""
    protocol: str = "tcp"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ServiceInfo:
    """Service detection info"""
    name: str
    version: str = ""
    product: str = ""
    extra_info: str = ""
    cpe: str = ""


class PortScanner:
    """
    Async TCP Port Scanner with Service Detection
    """

    # Common ports with service names
    COMMON_PORTS = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        443: "https",
        445: "microsoft-ds",
        465: "smtps",
        587: "submission",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        2049: "nfs",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http-proxy",
        8443: "https-alt",
        27017: "mongodb",
    }

    # Web ports for additional scanning
    WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 3000, 4443, 8081, 8082]

    # Top 100 ports
    TOP_PORTS = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
        119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
        515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
        1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717,
        3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357,
        5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080,
        8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156
    ]

    # Service banners/probes
    SERVICE_PROBES = {
        "http": b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        "https": b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        "ssh": b"SSH-2.0-OpenSSH_Test\r\n",
        "ftp": b"USER anonymous\r\n",
        "smtp": b"EHLO test\r\n",
        "mysql": b"\x00\x00\x00\x00",
        "redis": b"PING\r\n",
    }

    # Service signatures
    SERVICE_SIGNATURES = {
        "SSH": [b"SSH-", b"OpenSSH", b"dropbear"],
        "HTTP": [b"HTTP/", b"html", b"<html", b"<!DOCTYPE"],
        "FTP": [b"220 ", b"FTP", b"vsFTPd", b"ProFTPD"],
        "SMTP": [b"220 ", b"SMTP", b"ESMTP", b"Postfix"],
        "MySQL": [b"mysql", b"5.5.", b"5.6.", b"5.7.", b"8.0."],
        "PostgreSQL": [b"PostgreSQL", b"PGSQL"],
        "Redis": [b"+PONG", b"redis_version", b"-ERR"],
        "MongoDB": [b"mongodb", b"MongoDB"],
        "Telnet": [b"\xff\xfb", b"\xff\xfd", b"login:"],
        "RDP": [b"\x03\x00\x00"],
        "VNC": [b"RFB "],
        "DNS": [b"\x00\x00\x81"],
        "IMAP": [b"* OK", b"IMAP"],
        "POP3": [b"+OK", b"POP3"],
    }

    def __init__(self, target: str, callback: Callable = None,
                 threads: int = 100, timeout: float = 2.0):
        self.target = extract_domain(normalize_url(target))
        self.callback = callback
        self.threads = threads
        self.timeout = timeout
        self.results: List[PortResult] = []
        self.open_ports: List[int] = []

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def scan_port(self, port: int) -> Optional[PortResult]:
        """Scan a single port"""
        try:
            future = asyncio.open_connection(self.target, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)

            # Port is open
            service = self.COMMON_PORTS.get(port, "unknown")
            banner = ""

            # Try to grab banner
            try:
                # Send probe if available
                if service in self.SERVICE_PROBES:
                    writer.write(self.SERVICE_PROBES[service])
                    await writer.drain()

                # Read banner
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                banner = banner_data.decode('utf-8', errors='ignore').strip()

                # Detect service from banner
                detected_service = self._detect_service(banner_data)
                if detected_service:
                    service = detected_service

            except:
                pass

            writer.close()
            await writer.wait_closed()

            result = PortResult(
                port=port,
                state="open",
                service=service,
                banner=banner[:200] if banner else ""
            )

            self.open_ports.append(port)
            await self.emit("port_found", result.__dict__)
            return result

        except asyncio.TimeoutError:
            return PortResult(port=port, state="filtered")
        except ConnectionRefusedError:
            return PortResult(port=port, state="closed")
        except Exception:
            return PortResult(port=port, state="error")

    def _detect_service(self, banner: bytes) -> Optional[str]:
        """Detect service from banner"""
        for service, signatures in self.SERVICE_SIGNATURES.items():
            for sig in signatures:
                if sig in banner:
                    return service.lower()
        return None

    async def scan_common_ports(self) -> List[PortResult]:
        """Scan common ports only"""
        await self.emit("status", {"message": f"Scanning common ports on {self.target}"})

        ports = list(self.COMMON_PORTS.keys())
        return await self._scan_ports(ports)

    async def scan_top_ports(self) -> List[PortResult]:
        """Scan top 100 ports"""
        await self.emit("status", {"message": f"Scanning top 100 ports on {self.target}"})

        return await self._scan_ports(self.TOP_PORTS)

    async def scan_web_ports(self) -> List[PortResult]:
        """Scan web-related ports"""
        await self.emit("status", {"message": f"Scanning web ports on {self.target}"})

        return await self._scan_ports(self.WEB_PORTS)

    async def scan_range(self, start: int = 1, end: int = 1024) -> List[PortResult]:
        """Scan a port range"""
        await self.emit("status", {"message": f"Scanning ports {start}-{end} on {self.target}"})

        ports = list(range(start, end + 1))
        return await self._scan_ports(ports)

    async def scan_full(self) -> List[PortResult]:
        """Full port scan (1-65535) - Use with caution"""
        await self.emit("status", {"message": f"Full port scan on {self.target} (this may take a while)"})

        ports = list(range(1, 65536))
        return await self._scan_ports(ports)

    async def _scan_ports(self, ports: List[int]) -> List[PortResult]:
        """Internal method to scan a list of ports"""
        semaphore = asyncio.Semaphore(self.threads)

        async def bounded_scan(port: int):
            async with semaphore:
                return await self.scan_port(port)

        tasks = [bounded_scan(port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter results
        self.results = [r for r in results if isinstance(r, PortResult) and r.state == "open"]

        await self.emit("scan_complete", {
            "total_scanned": len(ports),
            "open_ports": len(self.results),
            "results": [r.__dict__ for r in self.results]
        })

        return self.results

    async def service_scan(self, ports: List[int] = None) -> List[PortResult]:
        """Detailed service detection on open ports"""
        if ports is None:
            ports = self.open_ports

        if not ports:
            return []

        await self.emit("status", {"message": "Performing service detection..."})

        detailed_results = []

        for port in ports:
            result = await self._probe_service(port)
            if result:
                detailed_results.append(result)

        return detailed_results

    async def _probe_service(self, port: int) -> Optional[PortResult]:
        """Probe a port for service details"""
        try:
            future = asyncio.open_connection(self.target, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)

            banner = ""
            service = self.COMMON_PORTS.get(port, "unknown")
            version = ""

            # Try multiple probes
            probes = [
                b"",  # Empty probe
                b"\r\n",
                b"HEAD / HTTP/1.0\r\n\r\n",
                b"HELP\r\n",
            ]

            for probe in probes:
                try:
                    if probe:
                        writer.write(probe)
                        await writer.drain()

                    data = await asyncio.wait_for(reader.read(2048), timeout=3.0)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()

                        # Extract version info
                        version = self._extract_version(banner)

                        # Detect service
                        detected = self._detect_service(data)
                        if detected:
                            service = detected
                        break

                except:
                    continue

            writer.close()
            await writer.wait_closed()

            return PortResult(
                port=port,
                state="open",
                service=service,
                version=version,
                banner=banner[:500]
            )

        except:
            return None

    def _extract_version(self, banner: str) -> str:
        """Extract version from banner"""
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.?\d*)',
            r'v(\d+\.\d+)',
            r'version\s+(\d+\.\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)

        return ""

    def get_open_ports(self) -> List[int]:
        """Get list of open ports"""
        return self.open_ports

    def get_web_servers(self) -> List[PortResult]:
        """Get ports running web servers"""
        web_services = ["http", "https", "http-proxy", "https-alt"]
        return [r for r in self.results if r.service in web_services]


class UDPScanner:
    """
    UDP Port Scanner
    """

    UDP_PORTS = {
        53: "dns",
        67: "dhcp",
        68: "dhcp",
        69: "tftp",
        123: "ntp",
        137: "netbios-ns",
        138: "netbios-dgm",
        161: "snmp",
        162: "snmptrap",
        500: "isakmp",
        514: "syslog",
        520: "rip",
        1900: "upnp",
        4500: "ipsec-nat-t",
        5353: "mdns",
    }

    def __init__(self, target: str, callback: Callable = None, timeout: float = 3.0):
        self.target = extract_domain(normalize_url(target))
        self.callback = callback
        self.timeout = timeout
        self.results: List[PortResult] = []

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    async def scan_port(self, port: int) -> PortResult:
        """Scan a UDP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.settimeout(self.timeout)

            # Send probe
            probe = self._get_udp_probe(port)
            sock.sendto(probe, (self.target, port))

            # Try to receive response
            try:
                data, addr = sock.recvfrom(1024)
                service = self.UDP_PORTS.get(port, "unknown")

                return PortResult(
                    port=port,
                    state="open",
                    service=service,
                    banner=data.decode('utf-8', errors='ignore')[:100],
                    protocol="udp"
                )
            except socket.timeout:
                return PortResult(port=port, state="open|filtered", protocol="udp")

        except Exception:
            return PortResult(port=port, state="error", protocol="udp")
        finally:
            sock.close()

    def _get_udp_probe(self, port: int) -> bytes:
        """Get UDP probe for specific port"""
        probes = {
            53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS
            161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04",  # SNMP
            123: b"\x1b" + b"\x00" * 47,  # NTP
        }
        return probes.get(port, b"\x00")

    async def scan_common_udp(self) -> List[PortResult]:
        """Scan common UDP ports"""
        await self.emit("status", {"message": f"Scanning UDP ports on {self.target}"})

        tasks = [self.scan_port(port) for port in self.UDP_PORTS.keys()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        self.results = [r for r in results if isinstance(r, PortResult)]
        return self.results
