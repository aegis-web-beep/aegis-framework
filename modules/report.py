# aegis/modules/report.py
import os, json, logging, time
from modules.base import BaseModule
import config
from state import SHELL_OPENED

logger = logging.getLogger("aegis.report")

class ReportModule(BaseModule):
    async def run_audit(self, session):
        if SHELL_OPENED:
            return False
        print("[*] REPORTING: Generating executive report...")
        report = {
            "target": self.auditor.target_url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "findings": self.auditor.master_report["audit_findings_summary"],
            "exploits": self.auditor.exploit_results,
            "remediation": self._remediation()
        }
        html = self._to_html(report)
        html_path = os.path.join(config.REPORT_DIR, f"report_{int(time.time())}.html")
        with open(html_path, "w") as f:
            f.write(html)
        print(f"[+] Executive report: {html_path}")
        self.auditor.add_exploit_result("Report", {"path": html_path})
        return True

    def _remediation(self):
        return {
            "rce": "Avoid system() calls, use input validation",
            "sql": "Use parameterized queries",
            "xss": "Use CSP and output encoding",
            "lfi": "Validate file paths, use whitelist"
        }

    def _to_html(self, report):
        html = "<html><head><title>AEGIS Security Report</title>"
        html += "<style>body{font-family:monospace;padding:20px;background:#0a0a0a;color:#00ff00}"
        html += "h1{color:#00ff00;border-bottom:2px solid #00ff00}"
        html += ".finding{background:#111;padding:10px;margin:10px 0;border:1px solid #00ff00}"
        html += ".verdict{font-weight:bold}"
        html += ".critical{color:#ff0000}.high{color:#ff6600}.medium{color:#ffff00}.low{color:#00ff00}"
        html += "</style></head><body>"
        html += f"<h1>🔒 AEGIS Security Assessment Report</h1>"
        html += f"<p><strong>Target:</strong> {report['target']}</p>"
        html += f"<p><strong>Timestamp:</strong> {report['timestamp']}</p>"
        html += f"<h2>Findings ({len(report['findings'])})</h2>"
        for f in report['findings']:
            verdict = f.get('4_BEHAVIORAL_PROOF', {}).get('verdict_tier_status', 'UNKNOWN')
            payload = f.get('1_REQUEST_EVIDENCE', {}).get('tested_payload', '')
            html += f"<div class='finding'><span class='verdict {verdict.lower()}'>{verdict}</span> - {payload}</div>"
        html += f"<h2>Remediation</h2><ul>"
        for k, v in report['remediation'].items():
            html += f"<li><strong>{k}:</strong> {v}</li>"
        html += "</ul>"
        html += "</body></html>"
        return html
