"""
RCE (Remote Code Execution) safe scanner:
- Approche similaire à Command Injection mais plus générique et toujours non-destructif.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse, parse_qs, quote

try:
    from ..utils.http_client import SecureHTTPClient
    from ..utils.payloads import get_payloads_for_type_mode
except ImportError:  # pragma: no cover
    import sys, os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    sys.path.insert(0, parent_dir)
    from utils.http_client import SecureHTTPClient
    from utils.payloads import get_payloads_for_type_mode


class RCESafeScanner:
    PARAM_CANDIDATES = {"cmd", "exec", "run", "process", "shell", "action", "task"}
    MARKERS = ["RCESAFE123", "ECHO_SAFE_456"]
    REFLECTION_PAYLOADS = [f"; echo {m}" for m in MARKERS] + [f"&& echo {m}" for m in MARKERS]
    TIMING_PAYLOADS = [
        "; sleep 2",
        "&& sleep 2",
        "| sleep 2",
        "& ping -n 2 127.0.0.1",
        "; ping -c 2 127.0.0.1",
    ]

    def __init__(self, base_url: str, threads: int = 4, timeout: int = 10, aggressive: bool = False, payload_mode: str = "safe"):
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        self.aggressive = aggressive
        # Étendre les payloads via le catalogue central (reuse 'command injection' type)
        central = get_payloads_for_type_mode('command injection', payload_mode or 'safe') or []
        ref_add = [p for p in central if 'echo' in p]
        time_add = [p for p in central if 'sleep' in p or 'ping' in p]
        # Concat sans doublons
        def dedup(base: list[str], extra: list[str]) -> list[str]:
            seen = set(base)
            out = list(base)
            for x in extra:
                if x not in seen:
                    out.append(x)
                    seen.add(x)
            return out
        self.REFLECTION_PAYLOADS = dedup(self.REFLECTION_PAYLOADS, ref_add)
        self.TIMING_PAYLOADS = dedup(self.TIMING_PAYLOADS, time_add)

    def scan(self) -> Dict:
        results: Dict = {"vulnerabilities": [], "summary": {"total_tests": 0, "suspected_rce": 0}}
        if not self.client.test_connection():
            return results
        candidates = self._discover_candidates()
        for cand in candidates:
            pname = cand["parameter"]
            if pname.lower() not in self.PARAM_CANDIDATES:
                continue
            base_url = cand["url"]
            baseline_url = self._build_url_with_param(base_url, pname, cand.get("value", ""))
            base_elapsed, _base_len, _ = self._metrics(baseline_url)
            # reflection
            for payload in self.REFLECTION_PAYLOADS:
                test_url = self._build_url_with_param(base_url, pname, payload)
                elapsed, _tlen, text = self._metrics(test_url)
                results["summary"]["total_tests"] += 1
                if text and any(m in text for m in self.MARKERS):
                    results["vulnerabilities"].append({
                        "type": "RCE (safe)",
                        "severity": "High",
                        "parameter": pname,
                        "payload": payload,
                        "url": test_url,
                        "method": "GET",
                        "description": f"Paramètre '{pname}' reflète un marqueur d'exécution.",
                        "evidence": "Marqueur echo présent",
                    })
                    results["summary"]["suspected_rce"] += 1
                    break
            # timing
            if self.aggressive and results["summary"]["suspected_rce"] == 0:
                for payload in self.TIMING_PAYLOADS:
                    test_url = self._build_url_with_param(base_url, pname, payload)
                    elapsed, _, _ = self._metrics(test_url)
                    results["summary"]["total_tests"] += 1
                    if elapsed - base_elapsed >= 2.0:
                        results["vulnerabilities"].append({
                            "type": "RCE (safe)",
                            "severity": "High",
                            "parameter": pname,
                            "payload": payload,
                            "url": test_url,
                            "method": "GET",
                            "description": f"Paramètre '{pname}' cause un délai significatif.",
                            "evidence": f"Delta délai {elapsed - base_elapsed:.2f}s",
                        })
                        results["summary"]["suspected_rce"] += 1
                        break
        return results

    def _discover_candidates(self) -> List[Dict[str, str]]:
        pts: List[Dict[str, str]] = []
        parsed = urlparse(self.base_url)
        if parsed.query or parsed.query == "":
            params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in params.items():
                pts.append({"url": self.base_url, "parameter": name, "value": values[0] if values else ""})
        return pts

    def _build_url_with_param(self, base_url: str, param: str, value: str) -> str:
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        pairs = []
        for k, vs in params.items():
            enc_k = quote(k, safe='*()')
            if not vs:
                pairs.append(f"{enc_k}=")
            else:
                for v in vs:
                    enc_v = quote(v, safe='*()')
                    pairs.append(f"{enc_k}={enc_v}")
        new_query = "&".join(pairs)
        return urlunparse(parsed._replace(query=new_query))

    def _metrics(self, full_url: str) -> tuple[float, int, Optional[str]]:
        rel = self._relative_to_base(full_url)
        start = time.time()
        resp = self.client.get(rel)
        elapsed = time.time() - start
        if not resp:
            return (elapsed, 0, None)
        text = resp.text or ""
        tlen = len(text)
        return (elapsed, tlen, text)

    def _relative_to_base(self, full_url: str) -> str:
        p = urlparse(full_url)
        path = p.path or '/'
        return path + (('?' + p.query) if p.query else '')
