# aegis/modules/vuln.py
import ssl, socket, logging, asyncio, aiohttp
from typing import Dict
from modules.base import BaseModule
import config
from state import SHELL_OPENED

logger = logging.getLogger("aegis.vuln")

class VulnModule(BaseModule):
    async def run_audit(self, session):
        if SHELL_OPENED: return False
        print("[*] VULNERABILITY ASSESSMENT: Checking misconfigurations...")
        target = self.auditor.target_url.split('//')[-1].split('/')[0]

        results = {
            "ssl": await self._check_ssl(target),
            "headers": await self._check_headers(session),
            "cves": await self._check_cves(session),
        }
        self.auditor.add_exploit_result("Vuln", results)
        return True

    async def _check_ssl(self, host):
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.connect((host, 443))
                cert = s.getpeercert()
                return {"valid": True, "expiry": cert.get('notAfter')}
        except:
            return {"valid": False}

    async def _check_headers(self, session):
        try:
            async with session.head(self.auditor.target_url) as res:
                headers = res.headers
                missing = []
                for h in ['X-Frame-Options','Content-Security-Policy','X-Content-Type-Options']:
                    if h not in headers:
                        missing.append(h)
                return {"missing_headers": missing}
        except:
            return {"error": "cannot fetch headers"}

    async def _check_cves(self, session):
        cves = []
        try:
            async with session.get(self.auditor.target_url) as res:
                server = res.headers.get('Server', '')
                if 'Apache/2.4.49' in server: cves.append('CVE-2021-41773')
                if 'nginx/1.20' in server: cves.append('CVE-2021-23017')
        except: pass
        return cves
