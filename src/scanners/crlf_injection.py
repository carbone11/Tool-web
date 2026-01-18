"""
Scanner CRLF Injection (HTTP Response Splitting) non-destructif.

Objectif: vérifier si l'injection de CRLF dans des paramètres peut altérer les en-têtes
de la réponse (header splitting) ou provoquer des anomalies (codes 400/500 inattendus,
doublons d'en-têtes, Set-Cookie injecté).

IMPORTANT: Utilisation autorisée uniquement. Les payloads sont ciblés et non-destructifs.
"""
from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from bs4 import BeautifulSoup, Tag

try:
    from ..utils.http_client import SecureHTTPClient
    from ..utils.payloads import get_payloads_for_type_mode, get_contextual_payloads
except ImportError:  # pragma: no cover
    import sys, os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    sys.path.insert(0, parent_dir)
    from utils.http_client import SecureHTTPClient
    from utils.payloads import get_payloads_for_type_mode


class CRLFInjectionScanner:
    """Tester l'injection CRLF dans des paramètres GET (et influencer headers)."""

    PARAM_CANDIDATES = {"q", "search", "file", "path", "redirect", "next", "download", "header", "name"}
    PAYLOADS = [
        "%0d%0aInjected: test",
        "%0D%0AInjected: test",
        "%0d%0aSet-Cookie: crlf=1",
        "%0d%0aX-Test: injected",
    ]

    ANOMALY_STATUS = {400, 500, 502, 503, 504}
    INJECT_MARKERS = re.compile(r"(Injected:|X-Test:|crlf=1)", re.I)

    def __init__(self, base_url: str, threads: int = 4, timeout: int = 10, payload_mode: str = "safe", proof_actions: bool = False):
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        central = get_payloads_for_type_mode('crlf injection', payload_mode or 'safe') or []
        self.payloads = central if central else list(self.PAYLOADS)
        self.proof_actions = bool(proof_actions)

    def scan(self) -> Dict:
        results: Dict = {
            "vulnerabilities": [],
            "summary": {"total_tests": 0, "suspected_crlf": 0},
        }

        if not self.client.test_connection():
            return results

        candidates = self._discover_candidates()
        # Heuristic: we look for anomalies when not following redirects, then compare with normal
        for cand in candidates:
            pname = cand["parameter"]
            if pname.lower() not in self.PARAM_CANDIDATES:
                continue
            for payload in self.payloads:
                test_url = self._build_url_with_param(cand["url"], pname, payload)
                relative = self._relative_to_base(test_url)
                # First request without following redirects to inspect headers/state
                resp = self.client.get(relative, allow_redirects=False)
                results["summary"]["total_tests"] += 1
                if not resp:
                    continue
                headers_blob = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
                evidence = None
                # 1) Status anomaly
                if resp.status_code in self.ANOMALY_STATUS:
                    evidence = f"Code HTTP anormal: {resp.status_code} après injection"
                # 2) Header reflection/injection markers
                elif self.INJECT_MARKERS.search(headers_blob):
                    evidence = "Marqueurs d'en-têtes injectés observés (X-Test / Set-Cookie)"
                # 3) Duplicate headers heuristic: any header name repeated unusually
                else:
                    seen = {}
                    for k in resp.headers.keys():
                        seen[k.lower()] = seen.get(k.lower(), 0) + 1
                    if any(c > 1 for c in seen.values()):
                        evidence = "Doublons d'en-têtes détectés après injection"

                if evidence:
                    vuln = {
                        "type": "CRLF Injection",
                        "severity": "Medium",
                        "parameter": pname,
                        "payload": payload,
                        "url": test_url,
                        "method": "GET",
                        "description": f"Paramètre '{pname}' susceptible au header splitting.",
                        "evidence": evidence,
                    }
                    if self.proof_actions:
                        pproofs = get_contextual_payloads('crlf injection', 'proof-header', mode='safe')
                        if pproofs:
                            try:
                                pproof = pproofs[0]
                                vuln["proof_url"] = self._build_url_with_param(cand["url"], pname, pproof)
                                vuln["proof_payload"] = pproof
                            except Exception:
                                pass
                    results["vulnerabilities"].append(vuln)
                    results["summary"]["suspected_crlf"] += 1
                    break

        return results

    # --- Helpers (similar to other scanners) ---
    def _discover_candidates(self) -> List[Dict[str, str]]:
        points: List[Dict[str, str]] = []
        response = self.client.get()
        if response is None:
            return points
        parsed = urlparse(self.base_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for name, values in params.items():
                points.append({"url": self.base_url, "parameter": name, "value": values[0] if values else ""})
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for a in soup.find_all("a"):
                if not isinstance(a, Tag):
                    continue
                raw_href = a.get("href")
                href = raw_href if isinstance(raw_href, str) else (raw_href[0] if isinstance(raw_href, list) and raw_href else "")
                if not href:
                    continue
                if "?" in href:
                    abs_url = href if href.startswith("http") else self._urljoin(self.base_url, href)
                    p2 = urlparse(abs_url)
                    params = parse_qs(p2.query)
                    for name, values in params.items():
                        points.append({"url": str(abs_url), "parameter": str(name), "value": str(values[0]) if values else ""})
        except (ValueError, AttributeError, TypeError):
            pass
        # Deduplicate
        seen = set()
        unique: List[Dict[str, str]] = []
        for p in points:
            key = (p["url"], p["parameter"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(p)
        return unique

    def _build_url_with_param(self, base_url: str, param: str, value: str) -> str:
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _relative_to_base(self, full_url: str) -> str:
        base = self.base_url.rstrip('/')
        if full_url.startswith(base):
            rel = full_url[len(base):]
            if not rel.startswith('/'):
                rel = '/' + rel
            return rel
        return full_url

    def _urljoin(self, base: str, path: str) -> str:
        # simple join without importing again
        if path.startswith('http'):
            return path
        if base.endswith('/') and path.startswith('/'):
            return base[:-1] + path
        if not base.endswith('/') and not path.startswith('/'):
            return base + '/' + path
        return base + path
