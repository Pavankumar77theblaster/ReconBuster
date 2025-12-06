"""
ReconBuster - Advanced Security Reconnaissance Tool
Main Flask Application with WebSocket support
"""

import os
import sys
import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from threading import Thread
from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.subdomain import SubdomainEnumerator
from modules.directory import DirectoryFuzzer, AdminFinder
from modules.bypass403 import Bypass403, Bypass403Bulk
from modules.scanner import VulnerabilityScanner
from modules.report import ReportGenerator
from modules.utils import normalize_url, is_valid_domain, extract_domain

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'reconbuster_secret_key_2024'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global state
active_scans = {}
scan_results = {}

def run_async(coro):
    """Run async coroutine in new event loop"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class ScanManager:
    """Manages scan execution and state"""

    def __init__(self, scan_id: str, target: str, options: dict):
        self.scan_id = scan_id
        self.target = normalize_url(target)
        self.domain = extract_domain(self.target)
        self.options = options
        self.start_time = time.time()
        self.status = "initializing"
        self.progress = 0
        self.current_phase = ""

        # Results storage
        self.subdomains = []
        self.directories = []
        self.forbidden_paths = []
        self.bypasses = []
        self.vulnerabilities = []
        self.technologies = {}
        self.stats = {}

        # Report generator
        self.report = ReportGenerator()
        self.report.set_target(self.target)

    def emit_update(self, event: str, data: dict):
        """Emit update via WebSocket"""
        socketio.emit(event, {
            "scan_id": self.scan_id,
            **data
        })

    async def callback(self, event: str, data: dict):
        """Callback for module events"""
        self.emit_update(event, data)

    def run(self):
        """Run the full scan pipeline"""
        try:
            self.status = "running"
            self.emit_update("scan_started", {
                "target": self.target,
                "options": self.options
            })

            # Phase 1: Subdomain Enumeration
            if self.options.get("subdomain_enum", True):
                self._run_subdomain_enum()

            # Phase 2: Directory Enumeration
            if self.options.get("directory_enum", True):
                self._run_directory_enum()

            # Phase 3: 403 Bypass
            if self.options.get("bypass_403", True):
                self._run_403_bypass()

            # Phase 4: Vulnerability Scanning
            if self.options.get("vuln_scan", True):
                self._run_vuln_scan()

            # Generate report
            self._generate_report()

            # Complete
            self.status = "completed"
            duration = time.time() - self.start_time
            self.emit_update("scan_complete", {
                "duration": f"{duration:.2f}s",
                "stats": self.stats
            })

        except Exception as e:
            self.status = "error"
            self.emit_update("scan_error", {"error": str(e)})

    def _run_subdomain_enum(self):
        """Run subdomain enumeration phase"""
        self.current_phase = "subdomain_enumeration"
        self.progress = 10
        self.emit_update("phase_started", {
            "phase": "subdomain_enumeration",
            "message": f"Enumerating subdomains for {self.domain}"
        })

        async def run():
            enumerator = SubdomainEnumerator(
                self.domain,
                callback=self.callback,
                threads=self.options.get("threads", 50),
                timeout=self.options.get("timeout", 10)
            )
            results = await enumerator.enumerate()
            return results, enumerator.get_403_targets()

        results, forbidden_targets = run_async(run())

        self.subdomains = [r.__dict__ for r in results]
        self.forbidden_paths.extend(forbidden_targets)
        self.stats["subdomains_found"] = len(self.subdomains)
        self.stats["subdomains_alive"] = len([s for s in self.subdomains if s.get("is_alive")])

        self.progress = 25
        self.emit_update("phase_complete", {
            "phase": "subdomain_enumeration",
            "count": len(self.subdomains)
        })

    def _run_directory_enum(self):
        """Run directory enumeration phase"""
        self.current_phase = "directory_enumeration"
        self.progress = 30
        self.emit_update("phase_started", {
            "phase": "directory_enumeration",
            "message": f"Fuzzing directories on {self.target}"
        })

        # Load custom wordlist if provided
        wordlist = self.options.get("wordlist", None)
        if wordlist and os.path.exists(wordlist):
            with open(wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]

        async def run():
            fuzzer = DirectoryFuzzer(
                self.target,
                callback=self.callback,
                threads=self.options.get("threads", 50),
                timeout=self.options.get("timeout", 10),
                extensions=self.options.get("extensions", ["php", "html", "js", "txt"]),
                wordlist=wordlist,
                recursive=self.options.get("recursive", False)
            )
            results = await fuzzer.scan()
            return results, fuzzer.get_forbidden_paths()

        results, forbidden = run_async(run())

        self.directories = [r.__dict__ for r in results]
        self.forbidden_paths.extend(forbidden)
        self.stats["directories_found"] = len(self.directories)
        self.stats["forbidden_paths"] = len(self.forbidden_paths)

        # Also run admin finder
        async def find_admin():
            finder = AdminFinder(self.target, callback=self.callback)
            return await finder.find()

        admin_panels = run_async(find_admin())
        self.stats["admin_panels"] = len(admin_panels)

        self.progress = 50
        self.emit_update("phase_complete", {
            "phase": "directory_enumeration",
            "count": len(self.directories),
            "forbidden": len(self.forbidden_paths)
        })

    def _run_403_bypass(self):
        """Run 403 bypass phase"""
        self.current_phase = "bypass_403"
        self.progress = 55
        self.emit_update("phase_started", {
            "phase": "bypass_403",
            "message": f"Testing {len(self.forbidden_paths)} forbidden paths"
        })

        if not self.forbidden_paths:
            # Test main target if it returns 403
            self.forbidden_paths = [self.target]

        async def run():
            bulk_bypasser = Bypass403Bulk(
                self.forbidden_paths[:20],  # Limit to 20 URLs
                callback=self.callback,
                threads=self.options.get("threads", 30),
                timeout=self.options.get("timeout", 10)
            )
            return await bulk_bypasser.bypass_all()

        all_bypasses = run_async(run())

        for url, bypasses in all_bypasses.items():
            for bypass in bypasses:
                self.bypasses.append(bypass.__dict__)

        self.stats["bypass_attempts"] = sum(len(b) for b in all_bypasses.values())
        self.stats["successful_bypasses"] = len(self.bypasses)

        self.progress = 75
        self.emit_update("phase_complete", {
            "phase": "bypass_403",
            "count": len(self.bypasses)
        })

    def _run_vuln_scan(self):
        """Run vulnerability scanning phase"""
        self.current_phase = "vulnerability_scan"
        self.progress = 80
        self.emit_update("phase_started", {
            "phase": "vulnerability_scan",
            "message": "Scanning for vulnerabilities"
        })

        async def run():
            scanner = VulnerabilityScanner(
                self.target,
                callback=self.callback,
                threads=self.options.get("threads", 20),
                timeout=self.options.get("timeout", 10)
            )
            results = await scanner.scan()
            return results, scanner.technologies

        results, technologies = run_async(run())

        self.vulnerabilities = [v.__dict__ for v in results]
        self.technologies = technologies
        self.stats["vulnerabilities_found"] = len(self.vulnerabilities)
        self.stats["critical"] = len([v for v in self.vulnerabilities if v.get("severity") == "critical"])
        self.stats["high"] = len([v for v in self.vulnerabilities if v.get("severity") == "high"])

        self.progress = 95
        self.emit_update("phase_complete", {
            "phase": "vulnerability_scan",
            "count": len(self.vulnerabilities)
        })

    def _generate_report(self):
        """Generate final report"""
        self.current_phase = "generating_report"
        self.emit_update("phase_started", {
            "phase": "generating_report",
            "message": "Generating report"
        })

        duration = f"{time.time() - self.start_time:.2f}s"
        self.report.set_duration(duration)
        self.report.add_subdomains(self.subdomains)
        self.report.add_directories(self.directories)
        self.report.add_bypasses(self.bypasses)
        self.report.add_vulnerabilities(self.vulnerabilities)
        self.report.add_technologies(self.technologies)
        self.report.add_stats(self.stats)

        report_paths = self.report.generate_report()

        self.progress = 100
        self.emit_update("report_generated", {
            "html_path": report_paths["html"],
            "json_path": report_paths["json"]
        })

        return report_paths


# Routes
@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    target = data.get('target', '')

    if not target:
        return jsonify({"error": "Target is required"}), 400

    # Generate scan ID
    scan_id = f"scan_{int(time.time())}_{hash(target) % 10000}"

    # Parse options
    options = {
        "subdomain_enum": data.get("subdomain_enum", True),
        "directory_enum": data.get("directory_enum", True),
        "bypass_403": data.get("bypass_403", True),
        "vuln_scan": data.get("vuln_scan", True),
        "threads": data.get("threads", 50),
        "timeout": data.get("timeout", 10),
        "extensions": data.get("extensions", ["php", "html", "js", "txt"]),
        "recursive": data.get("recursive", False),
        "wordlist": data.get("wordlist", None)
    }

    # Create scan manager
    manager = ScanManager(scan_id, target, options)
    active_scans[scan_id] = manager

    # Run scan in background thread
    thread = Thread(target=manager.run)
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "status": "started",
        "target": target
    })


@app.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    """Get scan status"""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    manager = active_scans[scan_id]
    return jsonify({
        "scan_id": scan_id,
        "status": manager.status,
        "progress": manager.progress,
        "current_phase": manager.current_phase,
        "stats": manager.stats
    })


@app.route('/api/scan/<scan_id>/results')
def get_scan_results(scan_id):
    """Get scan results"""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    manager = active_scans[scan_id]
    return jsonify({
        "scan_id": scan_id,
        "target": manager.target,
        "subdomains": manager.subdomains,
        "directories": manager.directories,
        "bypasses": manager.bypasses,
        "vulnerabilities": manager.vulnerabilities,
        "technologies": manager.technologies,
        "stats": manager.stats
    })


@app.route('/api/scan/<scan_id>/report')
def download_report(scan_id):
    """Download scan report"""
    if scan_id not in active_scans:
        return jsonify({"error": "Scan not found"}), 404

    manager = active_scans[scan_id]

    # Get report format
    format_type = request.args.get('format', 'html')

    if format_type == 'json':
        return jsonify(manager.report.scan_data)
    else:
        html_content = manager.report.generate_html()
        return Response(
            html_content,
            mimetype='text/html',
            headers={
                "Content-Disposition": f"attachment; filename=reconbuster_report_{scan_id}.html"
            }
        )


@app.route('/api/quick-bypass', methods=['POST'])
def quick_bypass():
    """Quick 403 bypass test for a single URL"""
    data = request.json
    url = data.get('url', '')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    async def run():
        bypasser = Bypass403(url, threads=30, timeout=10)
        return await bypasser.bypass()

    results = run_async(run())

    return jsonify({
        "url": url,
        "bypasses": [r.__dict__ for r in results],
        "count": len(results)
    })


# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'status': 'connected'})


@socketio.on('subscribe')
def handle_subscribe(data):
    """Subscribe to scan updates"""
    scan_id = data.get('scan_id')
    if scan_id:
        emit('subscribed', {'scan_id': scan_id})


if __name__ == '__main__':
    print("""
    ================================================================
    |                                                              |
    |  RECONBUSTER                                                 |
    |  Advanced Security Reconnaissance & 403 Bypass Tool          |
    |  Version 1.0.0                                               |
    |                                                              |
    |  Starting web interface on http://localhost:5000             |
    |                                                              |
    ================================================================
    """)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
