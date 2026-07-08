# aegis/main.py
import argparse, os, sys, asyncio, aiohttp, logging, re
from typing import List, Dict
import config
import state
from core import CoreAuditor
from modules import (
    ReconModule, ScanModule, VulnModule,
    CommandInjectionModule, SQLInjectionModule, PathTraversalModule,
    XSSModule, SSTIModule, SSRFModule,
    PostExploitModule, ReportModule
)
from display import *

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("aegis.main")

def validate_target_url(url: str) -> bool:
    return bool(re.match(r'^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$', url))
def validate_parameter(param: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9_]+$', param))

async def run_pipeline(target_url, param_name, method, session, reports_list, progress_callback):
    if state.SHELL_OPENED: return
    try:
        engine = CoreAuditor(target_url, param_name, method)
        await engine.capture_baseline_profile(session)
        modules = [
            ReconModule(engine), ScanModule(engine), VulnModule(engine),
            CommandInjectionModule(engine), SQLInjectionModule(engine),
            PathTraversalModule(engine), XSSModule(engine),
            SSTIModule(engine), SSRFModule(engine),
            PostExploitModule(engine), ReportModule(engine)
        ]
        for mod in modules:
            if state.SHELL_OPENED: break
            try:
                await mod.run_audit(session)
            except Exception as e:
                status_error(f"{mod.__class__.__name__}: {e}")
        if engine.master_report["audit_findings_summary"] or engine.exploit_results:
            reports_list.append(engine)
        if progress_callback:
            await progress_callback()
    except Exception as e:
        status_error(f"Pipeline error: {e}")

async def async_main():
    print_banner()
    spinner("Initializing AEGIS Engine", 2)
    status_success("Engine loaded successfully")
    print()

    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target-file", default="target.txt")
    parser.add_argument("-p","--param-file", default="param.txt")
    args = parser.parse_args()

    if not os.path.exists(args.target_file) or not os.path.exists(args.param_file):
        status_error("target.txt atau param.txt tidak ditemukan!")
        sys.exit(1)

    with open(args.target_file) as f:
        targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    with open(args.param_file) as f:
        params = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    targets = [t for t in targets if validate_target_url(t)]
    params = [p for p in params if validate_parameter(p)]

    if not targets or not params:
        status_error("Tidak ada target atau parameter yang valid.")
        sys.exit(1)

    total_combinations = len(targets) * len(params) * 2
    status_info(f"Targets: {len(targets)}, Parameters: {len(params)}")
    status_info(f"Total combinations: {total_combinations}")

    reports_list = []
    completed = 0
    progress_lock = asyncio.Lock()
    async def update_progress():
        nonlocal completed
        async with progress_lock:
            completed += 1
            progress_bar(completed, total_combinations, prefix="AEGIS Scanning")
            sys.stdout.flush()

    connector = aiohttp.TCPConnector(limit=config.TCP_POOL_LIMIT, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for target in targets:
            for param in params:
                for method in ["GET","POST"]:
                    if state.SHELL_OPENED: break
                    tasks.append(asyncio.create_task(
                        run_pipeline(target, param, method, session, reports_list, update_progress)
                    ))
                if state.SHELL_OPENED: break
            if state.SHELL_OPENED: break

        if tasks:
            try:
                await asyncio.gather(*tasks)
            except Exception as e:
                status_error(f"Gather error: {e}")

        progress_bar(total_combinations, total_combinations, prefix="AEGIS Scanning")
        sys.stdout.write('\n')

        if reports_list:
            for engine in reports_list:
        # Cek apakah ada temuan dengan status VERIFIED
                has_verified = any(
                    f.get("4_BEHAVIORAL_PROOF", {}).get("verdict_tier_status") == "VERIFIED"
                    for f in engine.master_report.get("audit_findings_summary", [])
                )
                if has_verified:
                    fpath = engine.save_report()
                    if fpath:
                        status_success(f"Report saved: {fpath}")
                else:
                    status_info("Tidak ada temuan terverifikasi. Laporan tidak dibuat.")
        else:
            status_info("Tidak ada celah ditemukan.")

        if state.SHELL_OPENED:
            status_shell("Menunggu shell ditutup...")
            if state.SHELL_TASK:
                await state.SHELL_TASK

def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        status_warning("Interrupted.")
        sys.exit(0)

if __name__ == "__main__":
    main()
