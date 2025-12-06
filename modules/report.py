"""
ReconBuster Report Generator
Clean, simple, and professional reports
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path

class ReportGenerator:
    """
    Simple and clean report generator
    - Easy to read HTML
    - JSON for data export
    """

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or str(Path(__file__).parent.parent / "reports")
        os.makedirs(self.output_dir, exist_ok=True)

        self.scan_data = {
            "target": "",
            "scan_date": datetime.now().isoformat(),
            "scan_duration": "",
            "subdomains": [],
            "directories": [],
            "bypasses": [],
            "vulnerabilities": [],
            "technologies": {},
            "stats": {}
        }

    def set_target(self, target: str):
        self.scan_data["target"] = target

    def set_duration(self, duration: str):
        self.scan_data["scan_duration"] = duration

    def add_subdomains(self, subdomains: List[Dict]):
        self.scan_data["subdomains"] = subdomains

    def add_directories(self, directories: List[Dict]):
        self.scan_data["directories"] = directories

    def add_bypasses(self, bypasses: List[Dict]):
        self.scan_data["bypasses"] = bypasses

    def add_vulnerabilities(self, vulnerabilities: List[Dict]):
        self.scan_data["vulnerabilities"] = vulnerabilities

    def add_technologies(self, technologies: Dict):
        self.scan_data["technologies"] = technologies

    def add_stats(self, stats: Dict):
        self.scan_data["stats"] = stats

    def generate_html(self) -> str:
        """Generate simple HTML report"""
        target = self.scan_data['target']
        date = datetime.now().strftime("%Y-%m-%d %H:%M")
        duration = self.scan_data.get('scan_duration', 'N/A')

        subdomains = self.scan_data.get('subdomains', [])
        directories = self.scan_data.get('directories', [])
        bypasses = self.scan_data.get('bypasses', [])
        vulns = self.scan_data.get('vulnerabilities', [])

        # Count by severity
        critical = len([v for v in vulns if v.get('severity') == 'critical'])
        high = len([v for v in vulns if v.get('severity') == 'high'])
        medium = len([v for v in vulns if v.get('severity') == 'medium'])
        low = len([v for v in vulns if v.get('severity') == 'low'])

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ReconBuster Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}

        /* Header */
        .header {{ background: #2c3e50; color: white; padding: 30px; margin-bottom: 20px; border-radius: 8px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header-info {{ display: flex; gap: 30px; flex-wrap: wrap; margin-top: 15px; }}
        .header-item {{ background: rgba(255,255,255,0.1); padding: 10px 20px; border-radius: 5px; }}
        .header-item span {{ display: block; font-size: 12px; opacity: 0.8; }}
        .header-item strong {{ font-size: 16px; }}

        /* Stats */
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .stat-box {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .stat-box.critical {{ border-left: 4px solid #e74c3c; }}
        .stat-box.high {{ border-left: 4px solid #e67e22; }}
        .stat-box.medium {{ border-left: 4px solid #f1c40f; }}
        .stat-box.success {{ border-left: 4px solid #27ae60; }}
        .stat-box.info {{ border-left: 4px solid #3498db; }}
        .stat-number {{ font-size: 32px; font-weight: bold; }}
        .stat-box.critical .stat-number {{ color: #e74c3c; }}
        .stat-box.high .stat-number {{ color: #e67e22; }}
        .stat-box.success .stat-number {{ color: #27ae60; }}
        .stat-box.info .stat-number {{ color: #3498db; }}
        .stat-label {{ color: #666; font-size: 14px; }}

        /* Sections */
        .section {{ background: white; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .section-header {{ background: #34495e; color: white; padding: 15px 20px; border-radius: 8px 8px 0 0; font-size: 18px; font-weight: 600; }}
        .section-body {{ padding: 20px; }}

        /* Tables */
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #ecf0f1; text-align: left; padding: 12px; font-weight: 600; border-bottom: 2px solid #bdc3c7; }}
        td {{ padding: 12px; border-bottom: 1px solid #ecf0f1; }}
        tr:hover td {{ background: #f9f9f9; }}

        /* Status badges */
        .badge {{ padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
        .badge-success {{ background: #d4edda; color: #155724; }}
        .badge-warning {{ background: #fff3cd; color: #856404; }}
        .badge-danger {{ background: #f8d7da; color: #721c24; }}
        .badge-info {{ background: #d1ecf1; color: #0c5460; }}
        .badge-critical {{ background: #e74c3c; color: white; }}
        .badge-high {{ background: #e67e22; color: white; }}
        .badge-medium {{ background: #f1c40f; color: #333; }}
        .badge-low {{ background: #27ae60; color: white; }}

        /* Bypass cards */
        .bypass-card {{ background: #d4edda; border: 1px solid #c3e6cb; border-radius: 8px; padding: 15px; margin-bottom: 15px; }}
        .bypass-title {{ color: #155724; font-weight: 600; font-size: 16px; margin-bottom: 10px; }}
        .bypass-detail {{ display: flex; margin-bottom: 8px; }}
        .bypass-label {{ color: #666; min-width: 120px; }}
        .bypass-value {{ font-family: monospace; word-break: break-all; }}

        /* Vuln cards */
        .vuln-card {{ border: 1px solid #ddd; border-radius: 8px; margin-bottom: 15px; overflow: hidden; }}
        .vuln-header {{ padding: 12px 15px; font-weight: 600; }}
        .vuln-header.critical {{ background: #e74c3c; color: white; }}
        .vuln-header.high {{ background: #e67e22; color: white; }}
        .vuln-header.medium {{ background: #f1c40f; color: #333; }}
        .vuln-header.low {{ background: #27ae60; color: white; }}
        .vuln-header.info {{ background: #3498db; color: white; }}
        .vuln-body {{ padding: 15px; }}
        .vuln-field {{ margin-bottom: 10px; }}
        .vuln-field-label {{ font-weight: 600; color: #555; margin-bottom: 3px; }}

        /* Code blocks */
        code {{ background: #2c3e50; color: #2ecc71; padding: 10px 15px; border-radius: 5px; display: block; font-family: monospace; word-break: break-all; white-space: pre-wrap; }}

        /* Footer */
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 14px; }}

        /* Print styles */
        @media print {{
            body {{ background: white; }}
            .section {{ box-shadow: none; border: 1px solid #ddd; }}
            .header {{ background: #333; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>ReconBuster Security Report</h1>
            <div class="header-info">
                <div class="header-item">
                    <span>Target</span>
                    <strong>{target}</strong>
                </div>
                <div class="header-item">
                    <span>Scan Date</span>
                    <strong>{date}</strong>
                </div>
                <div class="header-item">
                    <span>Duration</span>
                    <strong>{duration}</strong>
                </div>
            </div>
        </div>

        <!-- Stats -->
        <div class="stats">
            <div class="stat-box info">
                <div class="stat-number">{len(subdomains)}</div>
                <div class="stat-label">Subdomains</div>
            </div>
            <div class="stat-box info">
                <div class="stat-number">{len(directories)}</div>
                <div class="stat-label">Directories</div>
            </div>
            <div class="stat-box success">
                <div class="stat-number">{len(bypasses)}</div>
                <div class="stat-label">403 Bypasses</div>
            </div>
            <div class="stat-box critical">
                <div class="stat-number">{critical}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box high">
                <div class="stat-number">{high}</div>
                <div class="stat-label">High</div>
            </div>
        </div>
'''

        # 403 Bypasses Section
        if bypasses:
            html += '''
        <div class="section">
            <div class="section-header">403 Bypass Results</div>
            <div class="section-body">
'''
            for b in bypasses:
                html += f'''
                <div class="bypass-card">
                    <div class="bypass-title">Bypass Found: {b.get('technique', 'Unknown')}</div>
                    <div class="bypass-detail">
                        <span class="bypass-label">Original URL:</span>
                        <span class="bypass-value">{b.get('original_url', '')}</span>
                    </div>
                    <div class="bypass-detail">
                        <span class="bypass-label">Bypass URL:</span>
                        <span class="bypass-value">{b.get('bypass_url', '')}</span>
                    </div>
                    <div class="bypass-detail">
                        <span class="bypass-label">Status:</span>
                        <span class="bypass-value">{b.get('original_status', 403)} -> {b.get('status_code', '')}</span>
                    </div>
                    <div class="bypass-detail">
                        <span class="bypass-label">Category:</span>
                        <span class="bypass-value">{b.get('category', '')}</span>
                    </div>
                    <div class="bypass-detail">
                        <span class="bypass-label">Confidence:</span>
                        <span class="bypass-value">{b.get('confidence', '').upper()}</span>
                    </div>
                </div>
'''
            html += '''
            </div>
        </div>
'''

        # Vulnerabilities Section
        if vulns:
            html += '''
        <div class="section">
            <div class="section-header">Vulnerabilities Found</div>
            <div class="section-body">
'''
            for v in sorted(vulns, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x.get('severity', 'info'), 5)):
                sev = v.get('severity', 'info')
                html += f'''
                <div class="vuln-card">
                    <div class="vuln-header {sev}">{v.get('title', 'Unknown')} [{sev.upper()}]</div>
                    <div class="vuln-body">
                        <div class="vuln-field">
                            <div class="vuln-field-label">URL</div>
                            <div>{v.get('url', '')}</div>
                        </div>
                        <div class="vuln-field">
                            <div class="vuln-field-label">Description</div>
                            <div>{v.get('description', '')}</div>
                        </div>
                        <div class="vuln-field">
                            <div class="vuln-field-label">Evidence</div>
                            <code>{v.get('evidence', '')}</code>
                        </div>
                        <div class="vuln-field">
                            <div class="vuln-field-label">Remediation</div>
                            <div>{v.get('remediation', '')}</div>
                        </div>
                    </div>
                </div>
'''
            html += '''
            </div>
        </div>
'''

        # Subdomains Section
        if subdomains:
            html += '''
        <div class="section">
            <div class="section-header">Subdomains Found</div>
            <div class="section-body">
                <table>
                    <thead>
                        <tr>
                            <th>Subdomain</th>
                            <th>IP Address</th>
                            <th>HTTP</th>
                            <th>HTTPS</th>
                            <th>Title</th>
                        </tr>
                    </thead>
                    <tbody>
'''
            for s in subdomains[:100]:  # Limit to 100
                http_status = s.get('http_status', '-')
                https_status = s.get('https_status', '-')
                http_class = 'badge-success' if http_status == 200 else 'badge-danger' if http_status in [403, 401] else 'badge-info'
                https_class = 'badge-success' if https_status == 200 else 'badge-danger' if https_status in [403, 401] else 'badge-info'

                html += f'''
                        <tr>
                            <td>{s.get('subdomain', '')}</td>
                            <td>{s.get('ip_address', '-')}</td>
                            <td><span class="badge {http_class}">{http_status}</span></td>
                            <td><span class="badge {https_class}">{https_status}</span></td>
                            <td>{(s.get('title', '') or '-')[:40]}</td>
                        </tr>
'''
            html += '''
                    </tbody>
                </table>
            </div>
        </div>
'''

        # Directories Section
        if directories:
            html += '''
        <div class="section">
            <div class="section-header">Directories Found</div>
            <div class="section-body">
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Size</th>
                        </tr>
                    </thead>
                    <tbody>
'''
            for d in directories[:100]:  # Limit to 100
                status = d.get('status_code', 0)
                status_class = 'badge-success' if status == 200 else 'badge-danger' if status in [403, 401] else 'badge-info'
                html += f'''
                        <tr>
                            <td>{d.get('url', '')}</td>
                            <td><span class="badge {status_class}">{status}</span></td>
                            <td>{d.get('content_length', 0)} bytes</td>
                        </tr>
'''
            html += '''
                    </tbody>
                </table>
            </div>
        </div>
'''

        # How it worked section
        html += '''
        <div class="section">
            <div class="section-header">How The Scan Worked</div>
            <div class="section-body">
                <h3 style="margin-bottom: 15px;">Scan Phases</h3>

                <p><strong>1. Subdomain Enumeration</strong></p>
                <p style="margin-bottom: 15px; color: #666;">Used 14+ sources including crt.sh, HackerTarget, AlienVault, Wayback Machine, VirusTotal, and more to discover all subdomains associated with the target.</p>

                <p><strong>2. Directory Fuzzing</strong></p>
                <p style="margin-bottom: 15px; color: #666;">Scanned for common directories, admin panels, and sensitive files using wordlists. Identified paths that returned 403 Forbidden status for bypass testing.</p>

                <p><strong>3. 403 Bypass Testing</strong></p>
                <p style="margin-bottom: 15px; color: #666;">Applied 150+ bypass techniques including header manipulation (X-Forwarded-For, X-Original-URL), path tricks (%2e, ..;/), and HTTP method switching to bypass access controls.</p>

                <p><strong>4. Vulnerability Scanning</strong></p>
                <p style="margin-bottom: 15px; color: #666;">Checked for sensitive file exposure (.env, .git), directory listing, missing security headers, and information disclosure vulnerabilities.</p>

                <h3 style="margin-top: 25px; margin-bottom: 15px;">Recommendations</h3>
                <ul style="color: #666; padding-left: 20px;">
                    <li>Fix all 403 bypass vulnerabilities by implementing proper access controls at the application layer</li>
                    <li>Remove or restrict access to sensitive files</li>
                    <li>Add missing security headers (X-Frame-Options, CSP, HSTS)</li>
                    <li>Disable directory listing</li>
                    <li>Regularly audit and test access controls</li>
                </ul>
            </div>
        </div>
'''

        # Footer
        html += f'''
        <div class="footer">
            Generated by ReconBuster | {date}
        </div>
    </div>
</body>
</html>
'''
        return html

    def save_html(self, filename: str = None) -> str:
        """Save HTML report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = self.scan_data['target'].replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
            filename = f"report_{target_clean}_{timestamp}.html"

        filepath = os.path.join(self.output_dir, filename)
        html_content = self.generate_html()

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return filepath

    def save_json(self, filename: str = None) -> str:
        """Save JSON data"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = self.scan_data['target'].replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
            filename = f"data_{target_clean}_{timestamp}.json"

        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.scan_data, f, indent=2, default=str)

        return filepath

    def generate_report(self) -> Dict[str, str]:
        """Generate both reports"""
        html_path = self.save_html()
        json_path = self.save_json()

        return {
            "html": html_path,
            "json": json_path
        }
