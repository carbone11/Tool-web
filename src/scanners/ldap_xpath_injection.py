"""
LDAP/XPath Injection scanner (safe):
 - Injecte des caractères spéciaux (*)(|)(&)(=)(') et opérateurs pour provoquer des erreurs de filtre
   ou variations de cardinalité, sans action destructive.
"""
from __future__ import annotations

from typing import Dict, List
from urllib.parse import urlparse, urlunparse, parse_qs, quote

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


class LDAPXPathInjectionScanner:
    PARAM_CANDIDATES = {"user", "username", "email", "uid", "filter", "query", "search"}
    ERROR_MARKERS = (
        "LDAP", "Protocol Error", "Bad search filter", "javax.naming", "DirectoryServices",
        "XPathException", "InvalidXPathExpressionException", "SAXParseException"
    )
    PAYLOADS = [
        "*",
        "(objectClass=*)",
        "admin*)(&(|(uid=*)))",
        "') or '1'='1",
        "') or true() or ('a'='a",
        "] | * | [",
    ]

    def __init__(self, base_url: str, threads: int = 4, timeout: int = 10, payload_mode: str = "safe", proof_actions: bool = False):
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        central = get_payloads_for_type_mode('ldap injection', payload_mode or 'safe') or []
        # Inclure aussi XPath depuis le même sélecteur si disponible
        xp = get_payloads_for_type_mode('xpath injection', payload_mode or 'safe') or []
        merged = central + [p for p in xp if p not in central]
        self.payloads = merged if merged else list(self.PAYLOADS)
        self.proof_actions = bool(proof_actions)

    def scan(self) -> Dict:
        results: Dict = {"vulnerabilities": [], "summary": {"total_tests": 0, "suspected_ldap_xpath": 0}}
        if not self.client.test_connection():
            return results
        candidates = self._discover_candidates()
        for cand in candidates:
            pname = cand["parameter"]
            if pname.lower() not in self.PARAM_CANDIDATES:
                continue
            base_url = cand["url"]
            baseline_url = self._build_url_with_param(base_url, pname, cand.get("value", ""))
            try:
                base_resp = self.client.get(self._relative_to_base(baseline_url))
            except Exception:
                base_resp = None
            base_status = getattr(base_resp, "status_code", 0) if base_resp else 0
            base_len = len(base_resp.text) if (base_resp and base_resp.text) else 0
            for payload in self.payloads:
                try:
                    test_url = self._build_url_with_param(base_url, pname, payload)
                except Exception:
                    test_url = base_url
                try:
                    resp = self.client.get(self._relative_to_base(test_url))
                except Exception:
                    resp = None
                results["summary"]["total_tests"] += 1
                if not resp:
                    continue
                text = resp.text or ""
                status = resp.status_code
                tlen = len(text)
                evidence = None
                if any(m in text for m in self.ERROR_MARKERS):
                    evidence = "Erreur LDAP/XPath détectée"
                elif status != base_status or abs(tlen - base_len) > 100:
                    evidence = "Variation de cardinalité/longueur vs baseline"
                if evidence:
                    vuln = {
                        "type": "LDAP/XPath Injection",
                        "severity": "Medium",
                        "parameter": pname,
                        "payload": payload,
                        "url": test_url,
                        "method": "GET",
                        "description": f"Paramètre '{pname}' susceptible à LDAP/XPath injection.",
                        "evidence": evidence,
                    }
                    if self.proof_actions:
                        pproofs = get_contextual_payloads('ldap injection', 'proof-error', mode='safe')
                        if pproofs:
                            try:
                                pproof = pproofs[0]
                                vuln["proof_url"] = self._build_url_with_param(base_url, pname, pproof)
                                vuln["proof_payload"] = pproof
                            except Exception:
                                pass
                    results["vulnerabilities"].append(vuln)
                    results["summary"]["suspected_ldap_xpath"] += 1
                    break
        return results

    def _discover_candidates(self) -> List[Dict[str, str]]:
        pts: List[Dict[str, str]] = []
        parsed = urlparse(self.base_url)
        # Consider even empty values like '?filter='
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

    def _relative_to_base(self, full_url: str) -> str:
        p = urlparse(full_url)
        path = p.path or '/'
        return path + (('?' + p.query) if p.query else '')
