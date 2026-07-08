# aegis/core.py
import json, logging, re, time, random, os, hashlib, math, asyncio, aiohttp, aiofiles
from typing import List, Dict, Any, Tuple, Optional
from collections import Counter
from functools import lru_cache
from urllib.parse import quote
import config
import state

logger = logging.getLogger("aegis.core")
PAYLOAD_CLEAN_REGEX = re.compile(r'^[`"\'\\]|[`"\'\\]$')
HTML_TAG_REGEX = re.compile(r'<[^>]+>', re.DOTALL)

class CoreAuditor:
    def __init__(self, target_url, parameter, method="POST"):
        self.target_url = target_url
        self.parameter = parameter
        self.method = method.upper()
        self.timeout = config.TIMEOUT
        self.framework_version = config.FRAMEWORK_VERSION
        self.baseline = {"status_code":200, "content_length":0, "response_time":0.0, "entropy_score":0.0, "captured":False}
        self.master_report = {
            "audit_metadata": {
                "framework_version": self.framework_version,
                "target_url": self.target_url,
                "tested_parameter": self.parameter,
                "http_method": self.method,
                "audit_timestamp_start": time.strftime("%Y-%m-%d %H:%M:%S"),
                "assessment_engine": config.ASSESSMENT_ENGINE
            },
            "audit_findings_summary": [],
            "exploit_results": {}
        }
        self.browser_pool = [
            {"name":"CHROME","ua":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            {"name":"FIREFOX","ua":"Mozilla/5.0 (Android 10; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0"}
        ]
        self._cached_cookies = None
        self.exploit_results = {}

    def add_exploit_result(self, module_name: str, data: Any):
        self.exploit_results[module_name] = data
        self.master_report["exploit_results"][module_name] = data

    async def _get_random_headers(self):
        identity = random.choice(self.browser_pool)
        headers = {
            "User-Agent": identity["ua"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive"
        }
        if self._cached_cookies:
            headers["Cookie"] = self._cached_cookies
        return headers

    async def capture_baseline_profile(self, session):
        try:
            headers = await self._get_random_headers()
            start = time.time()
            if self.method == "POST":
                async with session.post(self.target_url, data={self.parameter:"baseline"}, headers=headers, timeout=self.timeout) as res:
                    body = await res.text(); status = res.status
            else:
                async with session.get(self.target_url, params={self.parameter:"baseline"}, headers=headers, timeout=self.timeout) as res:
                    body = await res.text(); status = res.status
            self.baseline.update({
                "status_code": status,
                "content_length": len(body),
                "response_time": time.time()-start,
                "entropy_score": self._calc_entropy(body),
                "captured": True
            })
            print(f"[+] BASELINE LOCKED: Status={status} | Entropy={self.baseline['entropy_score']}")
        except Exception as e:
            logger.critical(f"Baseline capture failed: {e}")

    def _calc_entropy(self, text):
        if not text: return 0.0
        freq = Counter(text)
        entropy = 0.0
        for count in freq.values():
            p = count / len(text)
            entropy -= p * math.log2(p)
        return round(entropy, 4)

# aegis/core.py - potongan yang diubah pada evaluate_heuristic_evidence

    def evaluate_heuristic_evidence(self, response_text, status_code, response_time, sent_payload, indicators, evidence_type, module_specific_proof):
        if not self.baseline["captured"]:
            logger.warning("Baseline belum ditangkap, evaluasi mungkin tidak akurat.")
        verdict = "SECURE"
        score = 0
        has_resp = "response_diff" in indicators
        has_anom = "anomalous_output" in indicators
        has_ver = "consistent_evaluation_proof" in indicators
        has_time = "time_anomaly" in indicators
        has_conf = "server_state_change_confirmed" in indicators

    # Hanya jika ada bukti kuat (anomali + konsisten) maka dianggap
        if has_resp and has_anom:
            score += 25
        if has_anom and has_ver:
            score += 60
        if has_time and has_anom:
            score += 40
        if has_conf:
            score += 100

    # Skor minimal untuk dianggap
        if score >= 30 and score < 60:
            verdict = "OBSERVED"
        elif score >= 60 and score < 90:
            verdict = "SUSPECTED"
        elif score >= 90:
            verdict = "VERIFIED"
    # Jika hanya response_diff (tanpa anomali) tidak dianggap
        if verdict != "SECURE":
            self.master_report["audit_findings_summary"].append({
                "1_REQUEST_EVIDENCE": {"method": self.method, "endpoint": self.target_url, "parameter": self.parameter, "tested_payload": sent_payload},
                "2_BASELINE_EVIDENCE": self.baseline,
                "3_TEST_RESPONSE_EVIDENCE": {"http_status_code": status_code, "response_length": len(response_text), "actual_response_time": response_time, "matched_indicators": indicators},
                "4_BEHAVIORAL_PROOF": {"confidence_scoring_matrix": score, "verdict_tier_status": verdict, "evidence_verified": (verdict == "VERIFIED")},
                "5_MODULE_SPECIFIC_EVIDENCE": module_specific_proof
            })
            print(f"[!] EVIDENCE VERDICT: [{verdict}] (Score: {score})")
        return verdict

    def mutate_payload_for_waf(self, base_payload, strategy):
        if strategy == 0: return base_payload
        elif strategy == 1: return base_payload.replace(" ", "/**/").replace("UNION","uNiOn")
        elif strategy == 2: return quote(quote(base_payload))
        elif strategy == 3: return f"%00{base_payload}"
        return base_payload

    async def ask_local_ai_to_bypass_waf(self, session, base_payload, waf_response_text):
        if not config.ENABLE_AI_BYPASS: return ""
        prompt = f"Generate bypass for WAF block for payload: {base_payload}. Return only payload."
        req = {"model": config.OLLAMA_MODEL_NAME, "prompt": prompt, "stream": False}
        try:
            async with session.post(config.OLLAMA_API_URL, json=req, timeout=10) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    return PAYLOAD_CLEAN_REGEX.sub('', result.get("response","").strip())
        except:
            pass
        return ""

    def save_report(self):
        if not self.master_report["audit_findings_summary"] and not self.exploit_results:
            return None
        filename = config.get_report_filename(self.target_url)
        filepath = os.path.join(config.REPORT_DIR, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.master_report, f, indent=4, ensure_ascii=False)
        return filepath
