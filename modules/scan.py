# aegis/modules/scan.py
import asyncio, logging, aiohttp
from typing import List, Dict
from modules.base import BaseModule
import config
from state import SHELL_OPENED

logger = logging.getLogger("aegis.scan")

class ScanModule(BaseModule):
    async def run_audit(self, session):
        if SHELL_OPENED: return False
        print("[*] SCANNING: High-speed network mapping...")
        target = self.auditor.target_url.split('//')[-1].split('/')[0]

        results = {
            "open_ports": await self._port_scan(target),
            "directories": await self._dir_bust(session),
            "parameters": await self._param_discovery(session),
        }
        self.auditor.add_exploit_result("Scan", results)
        print(f"[+] Scan: {len(results['open_ports'])} open ports, {len(results['directories'])} dirs")
        return True

    async def _port_scan(self, target):
        ports = [80,443,8080,8443,22,21,25,3306,5432,6379,27017]
        open_ports = []
        for port in ports:
            try:
                await asyncio.wait_for(asyncio.open_connection(target, port), timeout=2)
                open_ports.append(port)
            except: pass
        return open_ports

    async def _dir_bust(self, session):
        dirs = ['admin','login','wp-admin','api','assets','uploads','backup','config','env','.git']
        found = []
        base = self.auditor.target_url.rstrip('/')
        for d in dirs:
            try:
                async with session.get(f"{base}/{d}", timeout=3) as res:
                    if res.status in [200,403,401]:
                        found.append(d)
            except: pass
        return found

    async def _param_discovery(self, session):
        params = ['id','user','file','page','lang','cat','product','view','action','cmd']
        found = []
        for p in params:
            try:
                async with session.get(self.auditor.target_url + "?" + p + "=1", timeout=3) as res:
                    if res.status == 200:
                        found.append(p)
            except: pass
        return found
