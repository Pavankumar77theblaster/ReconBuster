"""
ReconBuster External Tools Integration
Integrates with popular security tools: Nmap, Nuclei, FFuf, etc.
"""

import asyncio
import subprocess
import shutil
import json
import os
import tempfile
from typing import List, Dict, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class ToolResult:
    """External tool execution result"""
    tool: str
    success: bool
    output: str = ""
    parsed_results: List[Dict] = field(default_factory=list)
    error: str = ""
    execution_time: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ExternalToolsIntegration:
    """
    Integration with external security tools
    Supported tools:
    - Nmap: Port scanning and service detection
    - Nuclei: Vulnerability scanning with templates
    - FFuf: Web fuzzing
    - Gobuster: Directory/DNS brute-forcing
    - Subfinder: Subdomain discovery
    - Httpx: HTTP probing
    - Amass: Subdomain enumeration
    """

    TOOL_CHECKS = {
        "nmap": ["nmap", "--version"],
        "nuclei": ["nuclei", "-version"],
        "ffuf": ["ffuf", "-V"],
        "gobuster": ["gobuster", "version"],
        "subfinder": ["subfinder", "-version"],
        "httpx": ["httpx", "-version"],
        "amass": ["amass", "version"],
        "masscan": ["masscan", "--version"],
        "nikto": ["nikto", "-Version"],
        "sqlmap": ["sqlmap", "--version"],
        "wpscan": ["wpscan", "--version"],
        "dirsearch": ["dirsearch", "--version"],
    }

    def __init__(self, callback: Callable = None, timeout: int = 300):
        self.callback = callback
        self.timeout = timeout
        self.available_tools: Dict[str, bool] = {}
        self._check_tools()

    async def emit(self, event: str, data: dict):
        if self.callback:
            await self.callback(event, data)

    def _check_tools(self):
        """Check which tools are available"""
        for tool, cmd in self.TOOL_CHECKS.items():
            self.available_tools[tool] = shutil.which(cmd[0]) is not None

    def get_available_tools(self) -> Dict[str, bool]:
        """Get list of available tools"""
        return self.available_tools

    async def _run_command(self, cmd: List[str], timeout: int = None) -> ToolResult:
        """Run external command"""
        if timeout is None:
            timeout = self.timeout

        tool_name = cmd[0]
        start_time = asyncio.get_event_loop().time()

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            execution_time = asyncio.get_event_loop().time() - start_time

            return ToolResult(
                tool=tool_name,
                success=process.returncode == 0,
                output=stdout.decode('utf-8', errors='ignore'),
                error=stderr.decode('utf-8', errors='ignore'),
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool=tool_name,
                success=False,
                error=f"Command timed out after {timeout}s"
            )
        except Exception as e:
            return ToolResult(
                tool=tool_name,
                success=False,
                error=str(e)
            )


class NmapIntegration(ExternalToolsIntegration):
    """Nmap Integration"""

    async def quick_scan(self, target: str) -> ToolResult:
        """Quick scan - top 100 ports"""
        if not self.available_tools.get("nmap"):
            return ToolResult(tool="nmap", success=False, error="Nmap not installed")

        await self.emit("status", {"message": f"Running Nmap quick scan on {target}"})

        cmd = ["nmap", "-F", "-T4", "-oG", "-", target]
        result = await self._run_command(cmd)

        if result.success:
            result.parsed_results = self._parse_nmap_grepable(result.output)

        return result

    async def full_scan(self, target: str) -> ToolResult:
        """Full port scan with service detection"""
        if not self.available_tools.get("nmap"):
            return ToolResult(tool="nmap", success=False, error="Nmap not installed")

        await self.emit("status", {"message": f"Running Nmap full scan on {target}"})

        cmd = ["nmap", "-sV", "-sC", "-p-", "-T4", "-oG", "-", target]
        result = await self._run_command(cmd, timeout=600)

        if result.success:
            result.parsed_results = self._parse_nmap_grepable(result.output)

        return result

    async def vuln_scan(self, target: str) -> ToolResult:
        """Vulnerability scan using Nmap scripts"""
        if not self.available_tools.get("nmap"):
            return ToolResult(tool="nmap", success=False, error="Nmap not installed")

        await self.emit("status", {"message": f"Running Nmap vuln scan on {target}"})

        cmd = ["nmap", "-sV", "--script=vuln", "-T4", target]
        result = await self._run_command(cmd, timeout=600)

        return result

    async def service_scan(self, target: str, ports: str = "80,443,8080") -> ToolResult:
        """Service version detection on specific ports"""
        if not self.available_tools.get("nmap"):
            return ToolResult(tool="nmap", success=False, error="Nmap not installed")

        cmd = ["nmap", "-sV", "-p", ports, "-T4", "-oG", "-", target]
        result = await self._run_command(cmd)

        if result.success:
            result.parsed_results = self._parse_nmap_grepable(result.output)

        return result

    def _parse_nmap_grepable(self, output: str) -> List[Dict]:
        """Parse Nmap grepable output"""
        results = []
        for line in output.split('\n'):
            if 'Ports:' in line:
                # Extract host
                host_part = line.split('\t')[0]
                host = host_part.split()[1] if 'Host:' in host_part else ""

                # Extract ports
                ports_part = line.split('Ports:')[1] if 'Ports:' in line else ""
                for port_info in ports_part.split(','):
                    port_info = port_info.strip()
                    if '/' in port_info:
                        parts = port_info.split('/')
                        if len(parts) >= 5:
                            results.append({
                                "host": host,
                                "port": parts[0],
                                "state": parts[1],
                                "protocol": parts[2],
                                "service": parts[4] if len(parts) > 4 else "",
                                "version": parts[6] if len(parts) > 6 else ""
                            })
        return results


class NucleiIntegration(ExternalToolsIntegration):
    """Nuclei Integration"""

    async def scan(self, target: str, templates: str = None,
                   severity: str = None) -> ToolResult:
        """Run Nuclei scan"""
        if not self.available_tools.get("nuclei"):
            return ToolResult(tool="nuclei", success=False, error="Nuclei not installed")

        await self.emit("status", {"message": f"Running Nuclei scan on {target}"})

        cmd = ["nuclei", "-u", target, "-json", "-silent"]

        if templates:
            cmd.extend(["-t", templates])

        if severity:
            cmd.extend(["-severity", severity])

        result = await self._run_command(cmd, timeout=600)

        if result.success:
            result.parsed_results = self._parse_nuclei_json(result.output)

        return result

    async def scan_cves(self, target: str) -> ToolResult:
        """Scan for CVEs only"""
        return await self.scan(target, templates="cves/", severity="critical,high")

    async def scan_exposures(self, target: str) -> ToolResult:
        """Scan for exposures and misconfigurations"""
        return await self.scan(target, templates="exposures/")

    async def scan_technologies(self, target: str) -> ToolResult:
        """Detect technologies"""
        return await self.scan(target, templates="technologies/")

    def _parse_nuclei_json(self, output: str) -> List[Dict]:
        """Parse Nuclei JSON output"""
        results = []
        for line in output.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    results.append({
                        "template": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", ""),
                        "matched_at": data.get("matched-at", ""),
                        "type": data.get("type", ""),
                        "description": data.get("info", {}).get("description", ""),
                    })
                except json.JSONDecodeError:
                    pass
        return results


class FFufIntegration(ExternalToolsIntegration):
    """FFuf Integration"""

    async def directory_fuzz(self, target: str, wordlist: str = None) -> ToolResult:
        """Directory fuzzing"""
        if not self.available_tools.get("ffuf"):
            return ToolResult(tool="ffuf", success=False, error="FFuf not installed")

        await self.emit("status", {"message": f"Running FFuf directory fuzz on {target}"})

        # Use default wordlist if not provided
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
            if not os.path.exists(wordlist):
                wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"

        if not os.path.exists(wordlist):
            return ToolResult(tool="ffuf", success=False, error="Wordlist not found")

        url = f"{target}/FUZZ"
        cmd = ["ffuf", "-u", url, "-w", wordlist, "-mc", "200,204,301,302,307,401,403",
               "-o", "-", "-of", "json", "-s"]

        result = await self._run_command(cmd)

        if result.success:
            result.parsed_results = self._parse_ffuf_json(result.output)

        return result

    async def vhost_fuzz(self, target: str, wordlist: str) -> ToolResult:
        """Virtual host fuzzing"""
        if not self.available_tools.get("ffuf"):
            return ToolResult(tool="ffuf", success=False, error="FFuf not installed")

        cmd = ["ffuf", "-u", target, "-H", "Host: FUZZ.target.com",
               "-w", wordlist, "-o", "-", "-of", "json", "-s"]

        result = await self._run_command(cmd)

        if result.success:
            result.parsed_results = self._parse_ffuf_json(result.output)

        return result

    def _parse_ffuf_json(self, output: str) -> List[Dict]:
        """Parse FFuf JSON output"""
        try:
            data = json.loads(output)
            results = []
            for item in data.get("results", []):
                results.append({
                    "url": item.get("url", ""),
                    "status": item.get("status", 0),
                    "length": item.get("length", 0),
                    "words": item.get("words", 0),
                    "lines": item.get("lines", 0),
                })
            return results
        except:
            return []


class SubfinderIntegration(ExternalToolsIntegration):
    """Subfinder Integration"""

    async def enumerate(self, domain: str) -> ToolResult:
        """Enumerate subdomains"""
        if not self.available_tools.get("subfinder"):
            return ToolResult(tool="subfinder", success=False, error="Subfinder not installed")

        await self.emit("status", {"message": f"Running Subfinder on {domain}"})

        cmd = ["subfinder", "-d", domain, "-silent"]
        result = await self._run_command(cmd)

        if result.success:
            subdomains = [s.strip() for s in result.output.split('\n') if s.strip()]
            result.parsed_results = [{"subdomain": s} for s in subdomains]

        return result


class HttpxIntegration(ExternalToolsIntegration):
    """Httpx Integration"""

    async def probe(self, targets: List[str]) -> ToolResult:
        """Probe HTTP services"""
        if not self.available_tools.get("httpx"):
            return ToolResult(tool="httpx", success=False, error="Httpx not installed")

        await self.emit("status", {"message": "Running Httpx probe"})

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(targets))
            targets_file = f.name

        try:
            cmd = ["httpx", "-l", targets_file, "-json", "-silent",
                   "-status-code", "-title", "-tech-detect"]

            result = await self._run_command(cmd)

            if result.success:
                result.parsed_results = self._parse_httpx_json(result.output)

        finally:
            os.unlink(targets_file)

        return result

    def _parse_httpx_json(self, output: str) -> List[Dict]:
        """Parse Httpx JSON output"""
        results = []
        for line in output.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    results.append({
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "technologies": data.get("tech", []),
                        "content_length": data.get("content_length", 0),
                    })
                except json.JSONDecodeError:
                    pass
        return results


class SQLMapIntegration(ExternalToolsIntegration):
    """SQLMap Integration"""

    async def scan(self, target: str, level: int = 1, risk: int = 1) -> ToolResult:
        """Run SQLMap scan"""
        if not self.available_tools.get("sqlmap"):
            return ToolResult(tool="sqlmap", success=False, error="SQLMap not installed")

        await self.emit("status", {"message": f"Running SQLMap on {target}"})

        cmd = ["sqlmap", "-u", target, "--batch", "--level", str(level),
               "--risk", str(risk), "--output-dir=/tmp/sqlmap"]

        result = await self._run_command(cmd, timeout=600)

        return result


class WPScanIntegration(ExternalToolsIntegration):
    """WPScan Integration"""

    async def scan(self, target: str, enumerate: str = "vp,vt,u") -> ToolResult:
        """Run WPScan"""
        if not self.available_tools.get("wpscan"):
            return ToolResult(tool="wpscan", success=False, error="WPScan not installed")

        await self.emit("status", {"message": f"Running WPScan on {target}"})

        cmd = ["wpscan", "--url", target, "-e", enumerate, "--format", "json", "--no-banner"]

        result = await self._run_command(cmd, timeout=600)

        if result.success:
            try:
                result.parsed_results = [json.loads(result.output)]
            except:
                pass

        return result


class ToolOrchestrator:
    """
    Orchestrates multiple external tools for comprehensive scanning
    """

    def __init__(self, callback: Callable = None):
        self.callback = callback
        self.nmap = NmapIntegration(callback)
        self.nuclei = NucleiIntegration(callback)
        self.ffuf = FFufIntegration(callback)
        self.subfinder = SubfinderIntegration(callback)
        self.httpx = HttpxIntegration(callback)
        self.sqlmap = SQLMapIntegration(callback)
        self.wpscan = WPScanIntegration(callback)

    def get_available_tools(self) -> Dict[str, bool]:
        """Get all available tools"""
        return self.nmap.get_available_tools()

    async def full_recon(self, target: str) -> Dict[str, ToolResult]:
        """Run full reconnaissance using available tools"""
        results = {}

        tasks = []

        # Subdomain enumeration
        if self.subfinder.available_tools.get("subfinder"):
            tasks.append(("subfinder", self.subfinder.enumerate(target)))

        # Port scan
        if self.nmap.available_tools.get("nmap"):
            tasks.append(("nmap", self.nmap.quick_scan(target)))

        # Vulnerability scan
        if self.nuclei.available_tools.get("nuclei"):
            tasks.append(("nuclei", self.nuclei.scan(f"https://{target}")))

        # Run all tasks
        for name, task in tasks:
            try:
                results[name] = await task
            except Exception as e:
                results[name] = ToolResult(tool=name, success=False, error=str(e))

        return results

    async def web_scan(self, target: str) -> Dict[str, ToolResult]:
        """Run web-focused scanning"""
        results = {}

        # Directory fuzzing
        if self.ffuf.available_tools.get("ffuf"):
            results["ffuf"] = await self.ffuf.directory_fuzz(target)

        # Nuclei web scan
        if self.nuclei.available_tools.get("nuclei"):
            results["nuclei"] = await self.nuclei.scan(target)

        return results
