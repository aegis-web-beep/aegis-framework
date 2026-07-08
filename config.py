# aegis/config.py
import os
from dotenv import load_dotenv
load_dotenv()

FRAMEWORK_VERSION = os.getenv("FRAMEWORK_VERSION", "2.0")
ENGINE_NAME = "AEGIS"
FRAMEWORK_ID = f"{ENGINE_NAME}_V{FRAMEWORK_VERSION}"
ASSESSMENT_ENGINE = os.getenv("ASSESSMENT_ENGINE", "AEGIS_V2")

BASE_DIR = os.path.expanduser("~/aegis-framework")
REPORT_DIR = os.path.join(BASE_DIR, "reports", "json")
RAW_LOG_DIR = os.path.join(BASE_DIR, "reports", "raw_logs")
DOWNLOAD_DIR = os.path.join(BASE_DIR, "reports", "download")
SHELL_SESSION_DIR = os.path.join(BASE_DIR, "shell_sessions")

for d in [REPORT_DIR, RAW_LOG_DIR, DOWNLOAD_DIR, SHELL_SESSION_DIR]:
    os.makedirs(d, exist_ok=True)

TIMEOUT = float(os.getenv("TIMEOUT", "15.0"))
MAX_CONCURRENT_TASKS = int(os.getenv("MAX_CONCURRENT_TASKS", "5"))
TIME_DELAY_THRESHOLD = float(os.getenv("TIME_DELAY_THRESHOLD", "5.0"))
SHELL_IDLE_TIMEOUT = float(os.getenv("SHELL_IDLE_TIMEOUT", "600.0"))
SHELL_RESPONSE_TIMEOUT = float(os.getenv("SHELL_RESPONSE_TIMEOUT", "30.0"))
SHELL_MODE = os.getenv("SHELL_MODE", "water_shell")
REVERSE_SHELL_IP = os.getenv("REVERSE_SHELL_IP", "127.0.0.1")
REVERSE_SHELL_PORT = int(os.getenv("REVERSE_SHELL_PORT", "4444"))
OLLAMA_API_URL = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL_NAME = os.getenv("OLLAMA_MODEL_NAME", "llama3.2")
ENABLE_AI_BYPASS = os.getenv("ENABLE_AI_BYPASS", "True").lower() == "true"

# ================= TAMBAHAN INI =================
TCP_POOL_LIMIT = int(os.getenv("TCP_POOL_LIMIT", "20"))
TCP_POOL_TTL = int(os.getenv("TCP_POOL_TTL", "300"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

AUTO_EXPLOIT = os.getenv("AUTO_EXPLOIT", "True").lower() == "true"
DUMP_DATABASE = os.getenv("DUMP_DATABASE", "True").lower() == "true"
EXFIL_FILES = os.getenv("EXFIL_FILES", "True").lower() == "true"
UPLOAD_WEBSHELL = os.getenv("UPLOAD_WEBSHELL", "True").lower() == "true"

def get_report_filename(target, suffix="audit", ext="json"):
    from datetime import datetime
    import re
    safe = re.sub(r'[^a-zA-Z0-9.]', '_', target.split('://')[-1].split('/')[0])
    return f"{safe}_{suffix}_V{FRAMEWORK_VERSION}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
