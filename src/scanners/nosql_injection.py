"""
NoSQL Injection scanner (Mongo-like) non-destructif.

Heuristiques:
- Différences de code/taille/texte vs baseline lorsque des opérateurs $ne/$gt/$regex sont injectés
- Messages d'erreur caractéristiques (MongoError, Cast to ObjectId failed, E11000, etc.)
"""
from __future__ import annotations

from typing import Dict, List
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


class NoSQLInjectionScanner:
    PARAM_CANDIDATES = {"user", "username", "email", "id", "q", "query", "filter", "search"}
    ERROR_MARKERS = (
        "MongoError", "E11000", "Cast to ObjectId failed", "MongoServerError", "BSON", "$where"
    )
    # URL-encoded friendly payloads
    PAYLOADS = [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '[{"$match": {"$ne": null}}]',  # basic pipeline-like
    ]

    def __init__(self, base_url: str, threads: int = 4, timeout: int = 10, payload_mode: str = "safe", proof_actions: bool = False):
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        central = get_payloads_for_type_mode('nosql injection', payload_mode or 'safe') or []
        self.payloads = central if central else list(self.PAYLOADS)
        # Align with CLI instantiation; proofs not used for NoSQL but accepted
        self.proof_actions = bool(proof_actions)

    def scan(self) -> Dict:
        results: Dict = {
            "vulnerabilities": [],
            "summary": {"total_tests": 0, "suspected_nosql": 0},
        }
        if not self.client.test_connection():
            return results
        candidates = self._discover_candidates()

        for cand in candidates:
            pname = cand["parameter"]
            if pname.lower() not in self.PARAM_CANDIDATES:
                continue
            base_url = cand["url"]
            baseline_url = self._build_url_with_param(base_url, pname, cand.get("value", ""))
            base_resp = self.client.get(self._relative_to_base(baseline_url))
            base_status = getattr(base_resp, "status_code", 0) if base_resp else 0
            base_len = len(base_resp.text) if (base_resp and base_resp.text) else 0

            for payload in self.payloads:
                test_url = self._build_url_with_param(base_url, pname, payload)
                resp = self.client.get(self._relative_to_base(test_url))
                results["summary"]["total_tests"] += 1
                if not resp:
                    continue
                text = resp.text or ""
                status = resp.status_code
                tlen = len(text)
                evidence = None
                # Error markers
                if any(m in text for m in self.ERROR_MARKERS):
                    evidence = "Message d'erreur NoSQL/Mongo détecté"
                # Differential behavior
                elif status != base_status or abs(tlen - base_len) > 100:
                    evidence = f"Comportement différentiel (status/longueur) vs baseline ({base_status}/{base_len} -> {status}/{tlen})"

                if evidence:
                    results["vulnerabilities"].append({
                        "type": "NoSQL Injection",
                        "severity": "High",
                        "parameter": pname,
                        "payload": payload,
                        "url": test_url,
                        "method": "GET",
                        "description": f"Paramètre '{pname}' susceptible à une injection NoSQL.",
                        "evidence": evidence,
                    })
                    results["summary"]["suspected_nosql"] += 1
                    break

        # POST path via simple heuristics: try sending JSON as value if a form expects it
        # For safety and simplicity, we reuse GET discovery and POST to '/' if applicable isn't discovered here.
        return results

    def _discover_candidates(self) -> List[Dict[str, str]]:
        pts: List[Dict[str, str]] = []
        resp = self.client.get()
        if resp is None:
            return pts
        parsed = urlparse(self.base_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for name, values in params.items():
                pts.append({"url": self.base_url, "parameter": name, "value": values[0] if values else ""})
        return pts

    def _build_url_with_param(self, base_url: str, param: str, value: str) -> str:
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        # Build query manually to control encoding: spaces as %20, keep '*' and parentheses unencoded
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
        # Always return path + query relative to host, e.g. '/path?query'
        p = urlparse(full_url)
        path = p.path or '/'
        return path + (('?' + p.query) if p.query else '')
