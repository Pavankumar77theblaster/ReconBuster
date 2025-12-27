"""
ReconBuster v3.0 - Kali Linux Native Tools Integration
Integrates powerful Kali tools for precise vulnerability detection:
- nuclei: Template-based vulnerability scanning (3000+ checks)
- ffuf: Smart directory/parameter fuzzing
- sqlmap: Deep SQL injection testing
- nikto: Legacy web vulnerability scanner
- masscan: Ultra-fast port scanning
- wpscan: WordPress security scanner
- commix: Command injection exploitation
- hydra: Authentication brute-forcing
- amass: Advanced subdomain enumeration
- httpx: Fast HTTP probing with tech detection
"""

import asyncio
import subprocess
import json
import re
import os
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ToolResult:
    """Result from a Kali tool execution"""
    tool_name: str
    success: bool
    findings: List[Dict] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    severity_critical: int = 0
    severity_high: int = 0
    severity_medium: int = 0
    severity_low: int = 0
    severity_info: int = 0


class KaliToolsIntegrator:
    """Integrates native Kali Linux tools for comprehensive testing"""

    def __init__(self, target: str, output_dir: str = "/tmp/reconbuster"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Tool availability
        self.available_tools = self._check_tool_availability()

    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check which tools are installed"""
        tools = {
            "nuclei": "/usr/bin/nuclei",
            "ffuf": "/usr/bin/ffuf",
            "sqlmap": "/usr/bin/sqlmap",
            "nikto": "/usr/bin/nikto",
            "nmap": "/usr/bin/nmap",
            "masscan": "/usr/bin/masscan",
            "gobuster": "/usr/bin/gobuster",
            "wpscan": "/usr/bin/wpscan",
            "commix": "/usr/bin/commix",
            "hydra": "/usr/bin/hydra",
            "amass": "/usr/bin/amass",
            "dnsenum": "/usr/bin/dnsenum",
            "fierce": "/usr/bin/fierce",
            "theHarvester": "/usr/bin/theHarvester",
            "whatweb": "/usr/bin/whatweb",
            "wafw00f": "/usr/bin/wafw00f",
            "sslscan": "/usr/bin/sslscan",
            "httpx": "/usr/bin/httpx",
        }

        available = {}
        for name, path in tools.items():
            available[name] = os.path.exists(path)

        return available

    async def run_nuclei(
        self,
        severity: List[str] = ["critical", "high", "medium"],
        templates: Optional[List[str]] = None,
        rate_limit: int = 150
    ) -> ToolResult:
        """
        Run Nuclei vulnerability scanner
        Uses YAML-based templates for precise vulnerability detection
        """
        if not self.available_tools.get("nuclei"):
            return ToolResult(tool_name="nuclei", success=False, error="Nuclei not installed")

        output_file = self.output_dir / "nuclei_results.json"

        # Build command
        cmd = [
            "nuclei",
            "-u", self.target,
            "-severity", ",".join(severity),
            "-json",
            "-o", str(output_file),
            "-rate-limit", str(rate_limit),
            "-silent",
            "-no-color",
        ]

        # Add specific templates if provided
        if templates:
            for template in templates:
                cmd.extend(["-t", template])
        else:
            # Use default templates
            cmd.extend(["-t", "~/nuclei-templates/"])

        print(f"[*] Running Nuclei: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)

            # Parse JSON output
            findings = []
            severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

            if output_file.exists():
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            result = json.loads(line.strip())
                            findings.append({
                                "template_id": result.get("template-id", "unknown"),
                                "name": result.get("info", {}).get("name", "Unknown"),
                                "severity": result.get("info", {}).get("severity", "info"),
                                "type": result.get("type", "unknown"),
                                "matched_at": result.get("matched-at", ""),
                                "description": result.get("info", {}).get("description", ""),
                                "reference": result.get("info", {}).get("reference", []),
                                "tags": result.get("info", {}).get("tags", []),
                            })
                            sev = result.get("info", {}).get("severity", "info").lower()
                            severity_count[sev] = severity_count.get(sev, 0) + 1
                        except json.JSONDecodeError:
                            continue

            return ToolResult(
                tool_name="nuclei",
                success=True,
                findings=findings,
                raw_output=stdout.decode('utf-8', errors='ignore'),
                severity_critical=severity_count.get("critical", 0),
                severity_high=severity_count.get("high", 0),
                severity_medium=severity_count.get("medium", 0),
                severity_low=severity_count.get("low", 0),
                severity_info=severity_count.get("info", 0),
            )

        except asyncio.TimeoutError:
            return ToolResult(tool_name="nuclei", success=False, error="Timeout after 300s")
        except Exception as e:
            return ToolResult(tool_name="nuclei", success=False, error=str(e))

    async def run_ffuf(
        self,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        extensions: str = "php,html,txt,js",
        rate: int = 100,
        recursion_depth: int = 2
    ) -> ToolResult:
        """
        Run FFUF directory/file fuzzer
        Smart fuzzing with recursion and extension discovery
        """
        if not self.available_tools.get("ffuf"):
            return ToolResult(tool_name="ffuf", success=False, error="FFUF not installed")

        output_file = self.output_dir / "ffuf_results.json"

        cmd = [
            "ffuf",
            "-u", f"{self.target}/FUZZ",
            "-w", wordlist,
            "-e", f".{extensions.replace(',', ',.')}",
            "-rate", str(rate),
            "-recursion",
            "-recursion-depth", str(recursion_depth),
            "-o", str(output_file),
            "-of", "json",
            "-mc", "200,201,202,203,204,301,302,307,308,401,403",
            "-fc", "404",
            "-s",  # Silent mode
        ]

        print(f"[*] Running FFUF: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)

            # Parse JSON output
            findings = []
            if output_file.exists():
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    for result in data.get("results", []):
                        findings.append({
                            "url": result.get("url", ""),
                            "status": result.get("status", 0),
                            "length": result.get("length", 0),
                            "words": result.get("words", 0),
                            "lines": result.get("lines", 0),
                        })

            return ToolResult(
                tool_name="ffuf",
                success=True,
                findings=findings,
                raw_output=stdout.decode('utf-8', errors='ignore'),
            )

        except asyncio.TimeoutError:
            return ToolResult(tool_name="ffuf", success=False, error="Timeout after 600s")
        except Exception as e:
            return ToolResult(tool_name="ffuf", success=False, error=str(e))

    async def run_sqlmap(
        self,
        param: Optional[str] = None,
        risk: int = 2,
        level: int = 3,
        threads: int = 5,
        batch: bool = True
    ) -> ToolResult:
        """
        Run SQLMap for SQL injection testing
        Deep testing with configurable risk/level
        """
        if not self.available_tools.get("sqlmap"):
            return ToolResult(tool_name="sqlmap", success=False, error="SQLMap not installed")

        output_dir = self.output_dir / "sqlmap"
        output_dir.mkdir(exist_ok=True)

        cmd = [
            "sqlmap",
            "-u", self.target,
            "--risk", str(risk),
            "--level", str(level),
            "--threads", str(threads),
            "--output-dir", str(output_dir),
            "--flush-session",
            "--fresh-queries",
        ]

        if param:
            cmd.extend(["-p", param])

        if batch:
            cmd.append("--batch")

        # Add smart options
        cmd.extend([
            "--random-agent",
            "--tamper=space2comment",
            "--technique=BEUSTQ",  # All techniques
        ])

        print(f"[*] Running SQLMap: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=900)

            output = stdout.decode('utf-8', errors='ignore')

            # Parse output for findings
            findings = []
            if "is vulnerable" in output.lower():
                # Extract vulnerable parameters
                vuln_matches = re.findall(
                    r"Parameter:\s+(.+?)\s+Type:\s+(.+?)\s+Title:\s+(.+?)(?:\n|$)",
                    output,
                    re.MULTILINE
                )
                for param, sqli_type, title in vuln_matches:
                    findings.append({
                        "parameter": param.strip(),
                        "type": sqli_type.strip(),
                        "title": title.strip(),
                        "severity": "critical",
                    })

            return ToolResult(
                tool_name="sqlmap",
                success=True,
                findings=findings,
                raw_output=output,
                severity_critical=len(findings),
            )

        except asyncio.TimeoutError:
            return ToolResult(tool_name="sqlmap", success=False, error="Timeout after 900s")
        except Exception as e:
            return ToolResult(tool_name="sqlmap", success=False, error=str(e))

    async def run_nikto(self, port: int = 80, ssl: bool = False) -> ToolResult:
        """Run Nikto web vulnerability scanner"""
        if not self.available_tools.get("nikto"):
            return ToolResult(tool_name="nikto", success=False, error="Nikto not installed")

        output_file = self.output_dir / "nikto_results.json"

        cmd = [
            "nikto",
            "-h", self.target,
            "-p", str(port),
            "-output", str(output_file),
            "-Format", "json",
            "-Tuning", "1,2,3,4,5,6,7,8,9,a,b",  # All checks
        ]

        if ssl:
            cmd.append("-ssl")

        print(f"[*] Running Nikto: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)

            findings = []
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        for vuln in data.get("vulnerabilities", []):
                            findings.append({
                                "id": vuln.get("id", ""),
                                "method": vuln.get("method", ""),
                                "url": vuln.get("url", ""),
                                "msg": vuln.get("msg", ""),
                            })
                except json.JSONDecodeError:
                    pass

            return ToolResult(
                tool_name="nikto",
                success=True,
                findings=findings,
                raw_output=stdout.decode('utf-8', errors='ignore'),
            )

        except asyncio.TimeoutError:
            return ToolResult(tool_name="nikto", success=False, error="Timeout after 600s")
        except Exception as e:
            return ToolResult(tool_name="nikto", success=False, error=str(e))

    async def run_amass_enum(self, timeout: int = 600) -> ToolResult:
        """Run Amass for advanced subdomain enumeration"""
        if not self.available_tools.get("amass"):
            return ToolResult(tool_name="amass", success=False, error="Amass not installed")

        # Extract domain from target
        from urllib.parse import urlparse
        domain = urlparse(self.target).netloc or self.target

        output_file = self.output_dir / "amass_subdomains.txt"

        cmd = [
            "amass", "enum",
            "-d", domain,
            "-o", str(output_file),
            "-passive",  # Use passive sources only (faster)
            "-timeout", str(timeout // 60),  # Convert to minutes
        ]

        print(f"[*] Running Amass: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)

            findings = []
            if output_file.exists():
                with open(output_file, 'r') as f:
                    subdomains = f.read().strip().split('\n')
                    findings = [{"subdomain": sub} for sub in subdomains if sub]

            return ToolResult(
                tool_name="amass",
                success=True,
                findings=findings,
                raw_output=stdout.decode('utf-8', errors='ignore'),
                severity_info=len(findings),
            )

        except asyncio.TimeoutError:
            return ToolResult(tool_name="amass", success=False, error=f"Timeout after {timeout}s")
        except Exception as e:
            return ToolResult(tool_name="amass", success=False, error=str(e))

    async def run_httpx_probe(self, input_file: Optional[str] = None) -> ToolResult:
        """Run HTTPX for fast HTTP probing with technology detection"""
        if not self.available_tools.get("httpx"):
            return ToolResult(tool_name="httpx", success=False, error="HTTPX not installed")

        output_file = self.output_dir / "httpx_results.json"

        if input_file:
            # Probe list of hosts
            cmd = [
                "httpx",
                "-l", input_file,
                "-json",
                "-o", str(output_file),
                "-tech-detect",
                "-status-code",
                "-content-length",
                "-title",
                "-server",
                "-silent",
            ]
        else:
            # Probe single target
            cmd = [
                "httpx",
                "-u", self.target,
                "-json",
                "-o", str(output_file),
                "-tech-detect",
                "-status-code",
                "-content-length",
                "-title",
                "-server",
                "-silent",
            ]

        print(f"[*] Running HTTPX: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)

            findings = []
            if output_file.exists():
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            result = json.loads(line.strip())
                            findings.append({
                                "url": result.get("url", ""),
                                "status_code": result.get("status_code", 0),
                                "title": result.get("title", ""),
                                "server": result.get("server", ""),
                                "tech": result.get("tech", []),
                                "content_length": result.get("content_length", 0),
                            })
                        except json.JSONDecodeError:
                            continue

            return ToolResult(
                tool_name="httpx",
                success=True,
                findings=findings,
                raw_output=stdout.decode('utf-8', errors='ignore'),
            )

        except asyncio.TimeoutError:
            return ToolResult(tool_name="httpx", success=False, error="Timeout after 300s")
        except Exception as e:
            return ToolResult(tool_name="httpx", success=False, error=str(e))

    async def run_comprehensive_scan(self) -> Dict[str, ToolResult]:
        """Run a comprehensive scan using all available tools"""
        results = {}

        print("[*] Starting comprehensive Kali tools scan...\n")

        # Phase 1: Reconnaissance
        print("[*] Phase 1: Subdomain Enumeration")
        if self.available_tools.get("amass"):
            results["amass"] = await self.run_amass_enum(timeout=300)

        # Phase 2: HTTP Probing
        print("[*] Phase 2: HTTP Probing")
        if self.available_tools.get("httpx"):
            results["httpx"] = await self.run_httpx_probe()

        # Phase 3: Vulnerability Scanning
        print("[*] Phase 3: Vulnerability Scanning")
        if self.available_tools.get("nuclei"):
            results["nuclei"] = await self.run_nuclei()

        if self.available_tools.get("nikto"):
            results["nikto"] = await self.run_nikto()

        # Phase 4: Directory Fuzzing
        print("[*] Phase 4: Directory/File Discovery")
        if self.available_tools.get("ffuf"):
            results["ffuf"] = await self.run_ffuf()

        # Phase 5: SQL Injection
        print("[*] Phase 5: SQL Injection Testing")
        if self.available_tools.get("sqlmap"):
            results["sqlmap"] = await self.run_sqlmap(risk=2, level=2)  # Conservative for safety

        return results

    def generate_report(self, results: Dict[str, ToolResult]) -> str:
        """Generate a summary report from all tool results"""
        report = []
        report.append("=" * 80)
        report.append("RECONBUSTER v3.0 - KALI TOOLS INTEGRATION REPORT")
        report.append("=" * 80)
        report.append("")

        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0
        total_info = 0

        for tool_name, result in results.items():
            report.append(f"[{tool_name.upper()}]")
            if result.success:
                report.append(f"  Status: SUCCESS")
                report.append(f"  Findings: {len(result.findings)}")
                if result.severity_critical > 0:
                    report.append(f"  Critical: {result.severity_critical}")
                    total_critical += result.severity_critical
                if result.severity_high > 0:
                    report.append(f"  High: {result.severity_high}")
                    total_high += result.severity_high
                if result.severity_medium > 0:
                    report.append(f"  Medium: {result.severity_medium}")
                    total_medium += result.severity_medium
                if result.severity_low > 0:
                    report.append(f"  Low: {result.severity_low}")
                    total_low += result.severity_low
                if result.severity_info > 0:
                    report.append(f"  Info: {result.severity_info}")
                    total_info += result.severity_info

                # Show top findings
                if result.findings:
                    report.append("  Top Findings:")
                    for finding in result.findings[:5]:
                        report.append(f"    - {finding}")
            else:
                report.append(f"  Status: FAILED - {result.error}")
            report.append("")

        report.append("=" * 80)
        report.append("SUMMARY")
        report.append("=" * 80)
        report.append(f"Total Critical: {total_critical}")
        report.append(f"Total High: {total_high}")
        report.append(f"Total Medium: {total_medium}")
        report.append(f"Total Low: {total_low}")
        report.append(f"Total Info: {total_info}")
        report.append("=" * 80)

        return "\n".join(report)


# ==================== MAIN EXECUTION ====================

async def main():
    """Test the Kali tools integration"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python kali_tools_integration.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"[*] Target: {target}\n")

    integrator = KaliToolsIntegrator(target)

    print("[*] Available tools:")
    for tool, available in integrator.available_tools.items():
        status = "✓" if available else "✗"
        print(f"  {status} {tool}")
    print()

    # Run comprehensive scan
    results = await integrator.run_comprehensive_scan()

    # Generate report
    report = integrator.generate_report(results)
    print("\n" + report)

    # Save report
    report_file = integrator.output_dir / "kali_tools_report.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    print(f"\n[+] Full report saved to: {report_file}")


if __name__ == "__main__":
    asyncio.run(main())
