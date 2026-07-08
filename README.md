# 🔒 AEGIS Framework

Advanced Exploitation & Security Testing Suite

## 📋 6-Phase Lifecycle

1. **Reconnaissance** - OSINT, subdomain, email, technology detection
2. **Scanning & Enumeration** - Port scan, directory busting, parameter discovery
3. **Vulnerability Assessment** - SSL, headers, CVE detection
4. **Exploitation** - RCE, SQLi, LFI, XSS, SSTI, SSRF
5. **Post-Exploitation** - Privilege escalation, persistence
6. **Reporting** - Executive report with remediation

## 🚀 Quick Start

```bash
# Install
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env: set REVERSE_SHELL_IP

# Run
echo "https://target.com" > target.txt
echo "id" > param.txt
python -m aegis.main
```

📁 Structure

```
aegis/
├── modules/
│   ├── recon.py          # OSINT
│   ├── scan.py           # Scanning
│   ├── vuln.py           # Vulnerability
│   ├── exploit_*.py      # Exploitation
│   ├── post_exploit.py   # Post-Exploit
│   └── report.py         # Reporting
├── core.py
├── main.py
└── display.py
```

⚠️ Legal

This tool is for authorized security testing only.

```
