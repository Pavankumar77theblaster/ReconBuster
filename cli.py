#!/usr/bin/env python3
"""
ReconBuster CLI - Command Line Interface
Advanced Security Reconnaissance & 403 Bypass Tool
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich import print as rprint

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.subdomain import SubdomainEnumerator
from modules.directory import DirectoryFuzzer, AdminFinder
from modules.bypass403 import Bypass403, Bypass403Bulk
from modules.scanner import VulnerabilityScanner
from modules.report import ReportGenerator
from modules.utils import normalize_url, extract_domain, print_banner

console = Console()


def print_banner_cli():
    """Print CLI banner"""
    banner = """
[cyan]╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ██╗   ██╗ ║
║  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██║   ██║ ║
║  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╔╝██║   ██║ ║
║  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██╗██║   ██║ ║
║  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝╚██████╔╝ ║
║  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝  ╚═════╝  ║
║                                                               ║
║  [white]Advanced Security Reconnaissance & 403 Bypass Tool[/white]           ║
║  [white]Version 1.0.0[/white]                                                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝[/cyan]
    """
    rprint(banner)


class CLIScan:
    """CLI Scan Manager"""

    def __init__(self, target: str, options: dict):
        self.target = normalize_url(target)
        self.domain = extract_domain(self.target)
        self.options = options

        self.subdomains = []
        self.directories = []
        self.forbidden_paths = []
        self.bypasses = []
        self.vulnerabilities = []
        self.technologies = {}

        self.report = ReportGenerator()
        self.report.set_target(self.target)

    async def run(self):
        """Run full scan"""
        start_time = datetime.now()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:

            # Phase 1: Subdomain Enumeration
            if self.options.get("subdomain"):
                task1 = progress.add_task("[cyan]Subdomain Enumeration...", total=100)
                await self._subdomain_enum(progress, task1)
                progress.update(task1, completed=100)

            # Phase 2: Directory Fuzzing
            if self.options.get("directory"):
                task2 = progress.add_task("[cyan]Directory Fuzzing...", total=100)
                await self._directory_enum(progress, task2)
                progress.update(task2, completed=100)

            # Phase 3: 403 Bypass
            if self.options.get("bypass"):
                task3 = progress.add_task("[cyan]403 Bypass Testing...", total=100)
                await self._bypass_403(progress, task3)
                progress.update(task3, completed=100)

            # Phase 4: Vulnerability Scan
            if self.options.get("vuln"):
                task4 = progress.add_task("[cyan]Vulnerability Scanning...", total=100)
                await self._vuln_scan(progress, task4)
                progress.update(task4, completed=100)

        # Calculate duration
        duration = datetime.now() - start_time
        self.report.set_duration(str(duration))

        # Print results
        self._print_results()

        # Generate report
        if self.options.get("report"):
            self._generate_report()

    async def _subdomain_enum(self, progress, task):
        """Subdomain enumeration phase"""
        async def callback(event, data):
            if event == "found":
                progress.console.print(f"  [green]+ {data.get('subdomain')}[/green]")

        enumerator = SubdomainEnumerator(
            self.domain,
            callback=callback,
            threads=self.options.get("threads", 50),
            timeout=self.options.get("timeout", 10)
        )
        results = await enumerator.enumerate()
        self.subdomains = [r.__dict__ for r in results]
        self.forbidden_paths.extend(enumerator.get_403_targets())

        progress.update(task, advance=50)

    async def _directory_enum(self, progress, task):
        """Directory enumeration phase"""
        async def callback(event, data):
            if event == "found":
                progress.console.print(f"  [green]+ {data.get('url')} [{data.get('status')}][/green]")
            elif event == "forbidden":
                progress.console.print(f"  [yellow]! {data.get('url')} [403 FORBIDDEN][/yellow]")

        fuzzer = DirectoryFuzzer(
            self.target,
            callback=callback,
            threads=self.options.get("threads", 50),
            timeout=self.options.get("timeout", 10)
        )
        results = await fuzzer.scan()
        self.directories = [r.__dict__ for r in results]
        self.forbidden_paths.extend(fuzzer.get_forbidden_paths())

        progress.update(task, advance=50)

    async def _bypass_403(self, progress, task):
        """403 bypass phase"""
        async def callback(event, data):
            if event == "bypass_found":
                progress.console.print(
                    f"  [bold green]✓ BYPASS FOUND: {data.get('technique')} "
                    f"[{data.get('confidence')} confidence][/bold green]"
                )

        if not self.forbidden_paths:
            self.forbidden_paths = [self.target]

        bulk_bypasser = Bypass403Bulk(
            self.forbidden_paths[:20],
            callback=callback,
            threads=self.options.get("threads", 30),
            timeout=self.options.get("timeout", 10)
        )

        all_bypasses = await bulk_bypasser.bypass_all()

        for url, bypasses in all_bypasses.items():
            for bypass in bypasses:
                self.bypasses.append(bypass.__dict__)

        progress.update(task, advance=50)

    async def _vuln_scan(self, progress, task):
        """Vulnerability scanning phase"""
        async def callback(event, data):
            if event == "vulnerability_found":
                severity = data.get('severity', 'info')
                color = {
                    'critical': 'bold red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'green',
                    'info': 'blue'
                }.get(severity, 'white')
                progress.console.print(f"  [{color}]! {data.get('title')} [{severity.upper()}][/{color}]")

        scanner = VulnerabilityScanner(
            self.target,
            callback=callback,
            threads=self.options.get("threads", 20),
            timeout=self.options.get("timeout", 10)
        )

        results = await scanner.scan()
        self.vulnerabilities = [v.__dict__ for v in results]
        self.technologies = scanner.technologies

        progress.update(task, advance=50)

    def _print_results(self):
        """Print results summary"""
        console.print("\n")

        # Stats table
        stats_table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Count", justify="right", style="green")

        stats_table.add_row("Subdomains Found", str(len(self.subdomains)))
        stats_table.add_row("  - Alive", str(len([s for s in self.subdomains if s.get('is_alive')])))
        stats_table.add_row("Directories Found", str(len(self.directories)))
        stats_table.add_row("403 Forbidden Paths", str(len(self.forbidden_paths)))
        stats_table.add_row("Successful Bypasses", str(len(self.bypasses)))
        stats_table.add_row("Vulnerabilities", str(len(self.vulnerabilities)))
        stats_table.add_row("  - Critical", str(len([v for v in self.vulnerabilities if v.get('severity') == 'critical'])))
        stats_table.add_row("  - High", str(len([v for v in self.vulnerabilities if v.get('severity') == 'high'])))

        console.print(stats_table)

        # Bypasses
        if self.bypasses:
            console.print("\n")
            bypass_table = Table(title="[bold green]Successful 403 Bypasses[/bold green]", show_header=True)
            bypass_table.add_column("Technique", style="green")
            bypass_table.add_column("Original URL")
            bypass_table.add_column("Bypass URL")
            bypass_table.add_column("Confidence")

            for bypass in self.bypasses[:10]:
                bypass_table.add_row(
                    bypass.get('technique', '')[:40],
                    bypass.get('original_url', '')[:30],
                    bypass.get('bypass_url', '')[:30],
                    bypass.get('confidence', '').upper()
                )

            console.print(bypass_table)

        # Critical vulnerabilities
        critical_vulns = [v for v in self.vulnerabilities if v.get('severity') in ['critical', 'high']]
        if critical_vulns:
            console.print("\n")
            vuln_table = Table(title="[bold red]Critical/High Vulnerabilities[/bold red]", show_header=True)
            vuln_table.add_column("Severity", style="red")
            vuln_table.add_column("Title")
            vuln_table.add_column("URL")

            for vuln in critical_vulns[:10]:
                vuln_table.add_row(
                    vuln.get('severity', '').upper(),
                    vuln.get('title', '')[:40],
                    vuln.get('url', '')[:40]
                )

            console.print(vuln_table)

    def _generate_report(self):
        """Generate report"""
        self.report.add_subdomains(self.subdomains)
        self.report.add_directories(self.directories)
        self.report.add_bypasses(self.bypasses)
        self.report.add_vulnerabilities(self.vulnerabilities)
        self.report.add_technologies(self.technologies)

        report_paths = self.report.generate_report()

        console.print(f"\n[bold green]Reports generated:[/bold green]")
        console.print(f"  HTML: {report_paths['html']}")
        console.print(f"  JSON: {report_paths['json']}")


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="ReconBuster - Advanced Security Reconnaissance & 403 Bypass Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py -t example.com                    # Full scan
  python cli.py -t example.com -b                 # Only 403 bypass
  python cli.py -t example.com -s -d              # Subdomain + Directory only
  python cli.py -t https://example.com/admin -b   # Bypass specific URL
        """
    )

    parser.add_argument("-t", "--target", required=True, help="Target domain or URL")
    parser.add_argument("-s", "--subdomain", action="store_true", default=True,
                        help="Enable subdomain enumeration (default: enabled)")
    parser.add_argument("-d", "--directory", action="store_true", default=True,
                        help="Enable directory fuzzing (default: enabled)")
    parser.add_argument("-b", "--bypass", action="store_true", default=True,
                        help="Enable 403 bypass testing (default: enabled)")
    parser.add_argument("-v", "--vuln", action="store_true", default=True,
                        help="Enable vulnerability scanning (default: enabled)")
    parser.add_argument("--threads", type=int, default=50,
                        help="Number of threads (default: 50)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-report", action="store_true",
                        help="Disable report generation")
    parser.add_argument("-o", "--output", help="Output directory for reports")

    args = parser.parse_args()

    # Print banner
    print_banner_cli()

    # Build options
    options = {
        "subdomain": args.subdomain,
        "directory": args.directory,
        "bypass": args.bypass,
        "vuln": args.vuln,
        "threads": args.threads,
        "timeout": args.timeout,
        "report": not args.no_report,
        "output": args.output
    }

    console.print(f"\n[bold cyan]Target:[/bold cyan] {args.target}")
    console.print(f"[bold cyan]Modules:[/bold cyan] ", end="")

    modules = []
    if options["subdomain"]: modules.append("Subdomain")
    if options["directory"]: modules.append("Directory")
    if options["bypass"]: modules.append("403 Bypass")
    if options["vuln"]: modules.append("Vulnerability")
    console.print(", ".join(modules))
    console.print("")

    # Run scan
    scan = CLIScan(args.target, options)
    asyncio.run(scan.run())

    console.print("\n[bold green]Scan complete![/bold green]\n")


if __name__ == "__main__":
    main()
