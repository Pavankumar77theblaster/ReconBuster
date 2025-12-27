"""
ReconBuster v3.0 - Enhanced Flask Application
Intelligent Workflow with Real-time Updates
"""

import os
import sys
import asyncio
import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from threading import Thread
from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

# Import v3.0 modules
from modules.intelligent_workflow import IntelligentWorkflow
from modules.bypass403_v3 import Bypass403Engine
from modules.kali_tools_integration import KaliToolsIntegrator
from modules.owasp_advanced_scanner import OWASPAdvancedScanner
from modules.port_scanner import PortScanner

# Import v2.0 modules
from modules.subdomain import SubdomainEnumerator
from modules.directory import DirectoryFuzzer
from modules.bypass403 import Bypass403
from modules.scanner import VulnerabilityScanner
from modules.report import ReportGenerator
from modules.utils import normalize_url, is_valid_domain, extract_domain

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'reconbuster_v3_secret_2025'
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


class IntelligentScanManager:
    """
    Enhanced Scan Manager with Intelligent Workflow
    Automatically chains tools based on findings
    """

    def __init__(self, scan_id: str, target: str, options: dict):
        self.scan_id = scan_id
        self.target = normalize_url(target) if '://' in target else f"http://{target}"
        self.domain = extract_domain(self.target)
        self.options = options
        self.start_time = time.time()
        self.status = "initializing"
        self.progress = 0
        self.current_phase = ""

        # Results storage
        self.workflow_report = {}
        self.findings = []
        self.ports = []
        self.services = []
        self.vulnerabilities = []
        self.stats = {
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

    def emit_update(self, event: str, data: dict):
        """Emit update via WebSocket"""
        socketio.emit(event, {
            "scan_id": self.scan_id,
            "timestamp": datetime.now().isoformat(),
            **data
        })

    async def progress_callback(self, progress_data: dict):
        """Progress callback for intelligent workflow"""
        self.emit_update("progress", progress_data)

    def run(self):
        """Run intelligent workflow scan"""
        try:
            self.status = "running"
            self.emit_update("scan_started", {
                "target": self.target,
                "mode": "intelligent_workflow",
                "message": "Starting intelligent workflow scan..."
            })

            # Run intelligent workflow
            if self.options.get("use_intelligent_workflow", True):
                self._run_intelligent_workflow()
            else:
                # Fallback to manual mode
                self._run_manual_scan()

            # Complete
            self.status = "completed"
            duration = time.time() - self.start_time
            self.emit_update("scan_complete", {
                "duration": f"{duration:.2f}s",
                "stats": self.stats,
                "total_findings": len(self.findings)
            })

        except Exception as e:
            self.status = "error"
            self.emit_update("scan_error", {"error": str(e)})
            import traceback
            traceback.print_exc()

    def _run_intelligent_workflow(self):
        """Run intelligent workflow with automatic tool chaining"""
        self.current_phase = "intelligent_workflow"
        self.progress = 10

        self.emit_update("phase_started", {
            "phase": "intelligent_workflow",
            "message": "Running intelligent vulnerability discovery workflow"
        })

        async def run_workflow():
            workflow = IntelligentWorkflow(
                self.target,
                config=self.options
            )

            # Run with progress callback
            report = await workflow.run(self.progress_callback)
            return report

        # Execute workflow
        report = run_async(run_workflow())

        # Store results
        self.workflow_report = report
        self.findings = report.get("findings", [])

        # Update stats
        findings_by_severity = report.get("findings_by_severity", {})
        self.stats.update({
            "total_findings": report.get("total_findings", 0),
            "critical": findings_by_severity.get("critical", 0),
            "high": findings_by_severity.get("high", 0),
            "medium": findings_by_severity.get("medium", 0),
            "low": findings_by_severity.get("low", 0),
            "info": findings_by_severity.get("info", 0)
        })

        self.progress = 90
        self.emit_update("workflow_complete", {
            "findings": len(self.findings),
            "stats": self.stats
        })

    def _run_manual_scan(self):
        """Run manual scan with selected modules"""
        # Port Scanning
        if self.options.get("port_scan", True):
            self._run_port_scan()

        # Subdomain Enumeration
        if self.options.get("subdomain_enum", False):
            self._run_subdomain_enum()

        # Directory Fuzzing
        if self.options.get("directory_enum", False):
            self._run_directory_enum()

        # 403 Bypass
        if self.options.get("bypass_403", False):
            self._run_403_bypass()

        # Nuclei Scan
        if self.options.get("nuclei_scan", False):
            self._run_nuclei()

        # SQLMap
        if self.options.get("sqlmap", False):
            self._run_sqlmap()

    def _run_port_scan(self):
        """Run port scanning"""
        self.current_phase = "port_scan"
        self.progress = 20

        self.emit_update("phase_started", {
            "phase": "port_scan",
            "message": f"Scanning ports on {self.target}"
        })

        async def run():
            scanner = PortScanner(
                target=self.domain,
                timeout=3,
                threads=100
            )

            # Scan top 100 ports
            open_ports = await scanner.scan_ports(
                ports=scanner.TOP_PORTS,
                grab_banner=True
            )

            return open_ports

        ports = run_async(run())

        self.ports = [
            {
                "port": p.port,
                "state": p.state,
                "service": p.service,
                "version": p.version,
                "banner": p.banner
            }
            for p in ports
        ]

        self.emit_update("ports_found", {
            "ports": self.ports,
            "count": len(self.ports)
        })

        self.stats["ports_open"] = len(self.ports)
        self.progress = 30

    def _run_subdomain_enum(self):
        """Run subdomain enumeration"""
        self.current_phase = "subdomain_enum"
        self.progress = 40

        self.emit_update("phase_started", {
            "phase": "subdomain_enum",
            "message": f"Enumerating subdomains for {self.domain}"
        })

        async def run():
            enumerator = SubdomainEnumerator(self.domain)
            results = await enumerator.enumerate()
            return results

        subdomains = run_async(run())

        self.emit_update("subdomains_found", {
            "count": len(subdomains)
        })

        self.stats["subdomains"] = len(subdomains)
        self.progress = 50

    def _run_directory_enum(self):
        """Run directory enumeration"""
        self.current_phase = "directory_enum"
        self.progress = 60

        self.emit_update("phase_started", {
            "phase": "directory_enum",
            "message": f"Fuzzing directories on {self.target}"
        })

        async def run():
            integrator = KaliToolsIntegrator(self.target)
            result = await integrator.run_ffuf(rate=50)
            return result

        result = run_async(run())

        if result.success:
            self.emit_update("directories_found", {
                "count": len(result.findings)
            })

        self.progress = 70

    def _run_403_bypass(self):
        """Run 403 bypass testing"""
        self.current_phase = "bypass_403"
        self.progress = 75

        self.emit_update("phase_started", {
            "phase": "bypass_403",
            "message": f"Testing 403 bypass techniques"
        })

        async def run():
            engine = Bypass403Engine(self.target, threads=10)
            bypasses = await engine.run()
            return bypasses

        bypasses = run_async(run())

        if bypasses:
            self.findings.extend([
                {
                    "type": "403_bypass",
                    "severity": "high" if b.confidence == "high" else "medium",
                    "technique": b.technique,
                    "url": b.bypass_url,
                    "evidence": b.evidence
                }
                for b in bypasses
            ])

            self.emit_update("bypasses_found", {
                "count": len(bypasses)
            })

        self.progress = 80

    def _run_nuclei(self):
        """Run Nuclei vulnerability scanner"""
        self.current_phase = "nuclei"
        self.progress = 85

        self.emit_update("phase_started", {
            "phase": "nuclei",
            "message": f"Running Nuclei vulnerability scanner"
        })

        async def run():
            integrator = KaliToolsIntegrator(self.target)
            result = await integrator.run_nuclei(severity=["critical", "high", "medium"])
            return result

        result = run_async(run())

        if result.success and result.findings:
            self.findings.extend([
                {
                    "type": "nuclei",
                    "severity": f.get("severity", "medium"),
                    "title": f.get("name", "Unknown"),
                    "description": f.get("description", ""),
                    "evidence": f
                }
                for f in result.findings
            ])

            self.emit_update("nuclei_complete", {
                "findings": len(result.findings),
                "critical": result.severity_critical,
                "high": result.severity_high,
                "medium": result.severity_medium
            })

        self.progress = 90

    def _run_sqlmap(self):
        """Run SQLMap"""
        self.current_phase = "sqlmap"
        self.progress = 95

        self.emit_update("phase_started", {
            "phase": "sqlmap",
            "message": f"Testing for SQL injection"
        })

        async def run():
            integrator = KaliToolsIntegrator(self.target)
            result = await integrator.run_sqlmap(risk=2, level=2)
            return result

        result = run_async(run())

        if result.success and result.findings:
            self.findings.extend([
                {
                    "type": "sql_injection",
                    "severity": "critical",
                    "parameter": f.get("parameter", ""),
                    "sqli_type": f.get("type", ""),
                    "evidence": f
                }
                for f in result.findings
            ])

            self.emit_update("sqlmap_complete", {
                "findings": len(result.findings)
            })

        self.progress = 100


# ==================== ROUTES ====================

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan"""
    data = request.json
    target = data.get('target')

    if not target:
        return jsonify({"error": "Target required"}), 400

    # Generate scan ID
    scan_id = str(uuid.uuid4())

    # Extract options
    options = {
        "use_intelligent_workflow": data.get("intelligent_workflow", True),
        "port_scan": data.get("port_scan", True),
        "subdomain_enum": data.get("subdomain_enum", False),
        "directory_enum": data.get("directory_enum", False),
        "bypass_403": data.get("bypass_403", False),
        "nuclei_scan": data.get("nuclei_scan", False),
        "sqlmap": data.get("sqlmap", False),
        "threads": data.get("threads", 50),
        "timeout": data.get("timeout", 10)
    }

    # Create scan manager
    scan_manager = IntelligentScanManager(scan_id, target, options)
    active_scans[scan_id] = scan_manager

    # Run scan in background thread
    thread = Thread(target=scan_manager.run)
    thread.daemon = True
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "target": scan_manager.target,
        "status": "started"
    })


@app.route('/api/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status"""
    scan = active_scans.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "scan_id": scan_id,
        "target": scan.target,
        "status": scan.status,
        "progress": scan.progress,
        "current_phase": scan.current_phase,
        "stats": scan.stats,
        "duration": time.time() - scan.start_time
    })


@app.route('/api/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results"""
    scan = active_scans.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "scan_id": scan_id,
        "target": scan.target,
        "status": scan.status,
        "findings": scan.findings,
        "ports": scan.ports,
        "stats": scan.stats,
        "workflow_report": scan.workflow_report
    })


@app.route('/api/scan/<scan_id>/download', methods=['GET'])
def download_report(scan_id):
    """Download scan report"""
    scan = active_scans.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    # Generate JSON report
    report = {
        "scan_id": scan_id,
        "target": scan.target,
        "timestamp": datetime.now().isoformat(),
        "status": scan.status,
        "duration": time.time() - scan.start_time,
        "stats": scan.stats,
        "findings": scan.findings,
        "ports": scan.ports,
        "workflow_report": scan.workflow_report
    }

    # Save to file
    report_path = f"/tmp/reconbuster_report_{scan_id}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    return send_file(report_path, as_attachment=True, download_name=f"reconbuster_{scan_id}.json")


@app.route('/api/tools/available', methods=['GET'])
def get_available_tools():
    """Get list of available Kali tools"""
    integrator = KaliToolsIntegrator("http://example.com")
    return jsonify({
        "tools": integrator.available_tools
    })


# ==================== WEBSOCKET EVENTS ====================

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    emit('connected', {"message": "Connected to ReconBuster v3.0"})


@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print('Client disconnected')


@socketio.on('subscribe_scan')
def handle_subscribe(data):
    """Subscribe to scan updates"""
    scan_id = data.get('scan_id')
    if scan_id in active_scans:
        emit('subscribed', {"scan_id": scan_id})
    else:
        emit('error', {"message": "Scan not found"})


if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         ReconBuster v3.0 - Web Dashboard                     ║
║         Intelligent Workflow Engine                          ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

Starting server on http://localhost:5000
    """)

    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
