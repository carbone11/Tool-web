"""
XXE (XML eXternal Entity) scanner (safe):
 - Inject des DOCTYPE/ENTITY inoffensifs dans des paramètres XML présumés
 - Détecte des erreurs de parser, messages de sécurité (XXE disabled), ou comportements différenciés.
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


class XXEScanner:
    PARAM_CANDIDATES = {"xml", "data", "payload", "doc", "request"}
    ERROR_MARKERS = (
        "DOCTYPE is disallowed", "External entity", "XXE", "XML parser error", "ENTITY is not allowed"
    )
    # Safe XXE payloads (no external network), local entity usage
    PAYLOADS = [
        """<?xml version='1.0'?>\n<!DOCTYPE root [ <!ENTITY xxe "test"> ]>\n<root>&xxe;</root>""",
        """<?xml version='1.0'?>\n<!DOCTYPE root [ <!ENTITY xxe "123"> ]>\n<root><a>&xxe;</a></root>""",
    ]

    def __init__(self, base_url: str, threads: int = 4, timeout: int = 10, payload_mode: str = "safe", proof_actions: bool = False):
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        # Charger les payloads centraux (xxe) avec repli local
        central = get_payloads_for_type_mode('xxe', payload_mode or 'safe') or []
        self.payloads = central if central else list(self.PAYLOADS)
        self.proof_actions = bool(proof_actions)

    def scan(self) -> Dict:
        results: Dict = {"vulnerabilities": [], "summary": {"total_tests": 0, "suspected_xxe": 0}}
        if not self.client.test_connection():
            return results
        candidates = self._discover_candidates()
        for cand in candidates:
            pname = cand["parameter"]
            if pname.lower() not in self.PARAM_CANDIDATES:
                continue
            for payload in self.payloads:
                try:
                    # Prefer GET, but fallback to POST if URL becomes too long (avoid 414)
                    test_url = self._build_url_with_param(cand["url"], pname, payload)
                except Exception:
                    test_url = cand["url"]
                rel = self._relative_to_base(test_url)
                use_post = len(rel) > 1800  # conservative threshold
                resp = None
                if use_post:
                    try:
                        resp = self.client.post(self._relative_to_base(cand["url"]), data={pname: payload})
                    except Exception:
                        resp = None
                else:
                    resp = self.client.get(rel)
                results["summary"]["total_tests"] += 1
                if not resp:
                    continue
                text = resp.text or ""
                if any(m in text for m in self.ERROR_MARKERS):
                    vuln = {
                        "type": "XXE (safe)",
                        "severity": "Medium",
                        "parameter": pname,
                        "payload": payload,
                        "url": test_url,
                        "method": "GET",
                        "description": f"Paramètre '{pname}' déclenche des erreurs liées au traitement DOCTYPE/ENTITY.",
                        "evidence": "Erreur parser/XXE détectée",
                    }
                    if use_post:
                        vuln["method"] = "POST"
                    if self.proof_actions:
                        pproofs = get_contextual_payloads('xxe', 'proof-entity', mode='safe')
                        if pproofs:
                            try:
                                pproof = pproofs[0]
                                vuln["proof_url"] = self._build_url_with_param(cand["url"], pname, pproof)
                                vuln["proof_payload"] = pproof
                            except Exception:
                                pass
                    results["vulnerabilities"].append(vuln)
                    results["summary"]["suspected_xxe"] += 1
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
        params = parse_qs(parsed.query)
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
