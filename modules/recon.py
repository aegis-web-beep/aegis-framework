# aegis/modules/recon.py
import re, logging, asyncio, aiohttp, socket
from typing import Dict, List, Set
from modules.base import BaseModule
import config
from state import SHELL_OPENED

logger = logging.getLogger("aegis.recon")

class ReconModule(BaseModule):
    async def run_audit(self, session):
        if SHELL_OPENED: return False
        print("[*] RECONNAISSANCE: Mapping target...")
        target = self.auditor.target_url
        domain = target.split('//')[-1].split('/')[0]

        results = {
            "domain": domain,
            "subdomains": await self._subdomains(session, domain),
            "technologies": await self._tech_detect(session),
            "headers": await self._get_headers(session),
            "emails": await self._extract_emails(session),
        }
        self.auditor.add_exploit_result("Recon", results)
        print(f"[+] Recon: {len(results['subdomains'])} subdomains, {len(results['emails'])} emails")
        return True

    async def _subdomains(self, session, domain):
        subdomains = set()
        try:
            async with session.get(f"https://crt.sh/?q=%.{domain}&output=json") as res:
                data = await res.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name.endswith(domain):
                        subdomains.add(name)
        except: pass
        common = ['www','mail','ftp','admin','dev','api','app','test']
        for sub in common:
            try:
                await session.get(f"http://{sub}.{domain}", timeout=3)
                subdomains.add(f"{sub}.{domain}")
            except: pass
        return list(subdomains)[:30]

    async def _tech_detect(self, session):
        tech = {}
        try:
            async with session.get(self.auditor.target_url) as res:
                html = await res.text()
                server = res.headers.get('Server', '')
                tech['server'] = server
                if 'wp-content' in html: tech['cms'] = 'WordPress'
                elif 'Drupal' in html: tech['cms'] = 'Drupal'
                elif 'laravel' in html: tech['framework'] = 'Laravel'
        except: pass
        return tech

    async def _get_headers(self, session):
        try:
            async with session.head(self.auditor.target_url) as res:
                return dict(res.headers)
        except: return {}

    async def _extract_emails(self, session):
        try:
            async with session.get(self.auditor.target_url) as res:
                html = await res.text()
                pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                return list(set(re.findall(pattern, html)))
        except: return []
