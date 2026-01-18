"""
Scanner SSRF (Server-Side Request Forgery) non-destructif.

Objectif: détecter des comportements où l'application cible récupère des URLs fournies
par l'utilisateur (GET/POST) et renvoie des indices (contenu proxyfié, messages d'erreur,
ou timings) suggérant une SSRF.

IMPORTANT: Utiliser uniquement avec autorisation explicite. Tests prudents, pas de charge
destructive ni brute-force. Les payloads visent des adresses locales connues et metadata.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, TypedDict
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup, Tag

try:
    from ..utils.http_client import SecureHTTPClient
    from ..utils.payloads import get_payloads_for_type_mode, get_contextual_payloads
except ImportError:  # pragma: no cover - fallback absolute
    import sys, os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    sys.path.insert(0, parent_dir)
    from utils.http_client import SecureHTTPClient
    from utils.payloads import get_payloads_for_type_mode


class SSRFScanner:
    """Détecteur SSRF basique (GET/POST) avec heuristiques non-destructives.

    - Cibles de paramètres fréquents: url, link, image, fetch, endpoint, target, next, redirect
    - Payloads: adresses internes et metadata cloud; on recherche des indices côté réponse.
    """

    PARAM_CANDIDATES = {
        "url", "link", "image", "img", "avatar", "callback", "endpoint",
        "target", "next", "redirect", "return", "resource", "feed", "rss"
    }

    # Payloads non-destructifs visant des hôtes internes communs
    PAYLOADS = [
        "http://127.0.0.1/",
        "http://127.1/",
        "http://[::1]/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://192.168.0.1/",
        "http://172.16.0.1/",
    ]

    # Marqueurs de contenus typiques
    METADATA_MARKERS = re.compile(r"meta-data|iam|security-credentials|hostname|public-keys", re.I)
    LOCAL_ERROR_MARKERS = re.compile(r"(connection refused|ECONNREFUSED|timed out|Invalid URL|refused)", re.I)

    class PostForm(TypedDict):
        action: str
        inputs: List[Dict[str, str]]

    def __init__(self, base_url: str, threads: int = 4, timeout: int = 10, payload_mode: str = "safe", proof_actions: bool = False):
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        # Payloads depuis le catalogue central (ssrf) avec repli local
        central = get_payloads_for_type_mode('ssrf', payload_mode or 'safe') or []
        self.payloads = central if central else list(self.PAYLOADS)
        self.proof_actions = bool(proof_actions)

    def scan(self) -> Dict:
        results: Dict = {
            "vulnerabilities": [],
            "summary": {
                "total_tests": 0,
                "suspected_ssrf": 0,
            },
        }

        if not self.client.test_connection():
            return results

        candidates = self._discover_candidates()

        # GET-based probes
        for cand in candidates:
            pname = cand["parameter"]
            if pname.lower() not in self.PARAM_CANDIDATES:
                continue
            for payload in self.payloads:
                test_url = self._build_url_with_param(cand["url"], pname, payload)
                relative = self._relative_to_base(test_url)
                start = time.time()
                resp = self.client.get(relative)
                elapsed = time.time() - start
                results["summary"]["total_tests"] += 1
                if not resp:
                    continue
                text = resp.text or ""
                evidence = self._analyze_evidence(text, resp.status_code, elapsed, payload)
                if evidence:
                    results["vulnerabilities"].append({
                        "type": "SSRF",
                        "severity": "High",
                        "parameter": pname,
                        "payload": payload,
                        "url": test_url,
                        "method": "GET",
                        "description": f"Paramètre '{pname}' susceptible à une SSRF (comportement externe).",
                        "evidence": evidence,
                    })
                    if self.proof_actions:
                        # Attach an echo endpoint proof URL (non-sensitive)
                        pproofs = get_contextual_payloads('ssrf', 'proof-echo', mode='safe')
                        if pproofs:
                            pproof = pproofs[0]
                            try:
                                proof_url = self._build_url_with_param(cand["url"], pname, pproof)
                                results["vulnerabilities"][-1]["proof_url"] = proof_url
                                results["vulnerabilities"][-1]["proof_payload"] = pproof
                            except Exception:
                                pass
                    results["summary"]["suspected_ssrf"] += 1
                    break

        # POST-based via forms
        post_forms = self._discover_post_forms()
        for form in post_forms:
            action = form["action"] or "/"
            inputs = form["inputs"]
            fields = [i["name"] for i in inputs if i.get("name") and i["name"].lower() in self.PARAM_CANDIDATES]
            if not fields:
                continue
            for field in fields:
                for payload in self.payloads:
                    data = {}
                    for inp in inputs:
                        name = inp.get("name")
                        if not name:
                            continue
                        data[name] = payload if name == field else (inp.get("value") or "test")
                    start = time.time()
                    resp = self.client.post(action, data=data)
                    elapsed = time.time() - start
                    results["summary"]["total_tests"] += 1
                    if not resp:
                        continue
                    text = resp.text or ""
                    evidence = self._analyze_evidence(text, resp.status_code, elapsed, payload)
                    if evidence:
                        results["vulnerabilities"].append({
                            "type": "SSRF",
                            "severity": "High",
                            "parameter": field,
                            "payload": payload,
                            "url": urljoin(self.base_url, action),
                            "method": "POST",
                            "description": f"Champ '{field}' susceptible à une SSRF (POST).",
                            "evidence": evidence,
                        })
                        if self.proof_actions:
                            pproofs = get_contextual_payloads('ssrf', 'proof-echo', mode='safe')
                            if pproofs:
                                pproof = pproofs[0]
                                try:
                                    data2 = {}
                                    for inp in inputs:
                                        name = inp.get("name")
                                        if not name:
                                            continue
                                        data2[name] = pproof if name == field else (inp.get("value") or "test")
                                    # build proof_url for reporting
                                    q = urlencode(data2)
                                    results["vulnerabilities"][-1]["proof_url"] = urljoin(self.base_url, f"{action}?{q}")
                                    results["vulnerabilities"][-1]["proof_payload"] = pproof
                                except Exception:
                                    pass
                        results["summary"]["suspected_ssrf"] += 1
                        break

        return results

    # --- Helpers ---
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
            # Links
            for a in soup.find_all("a"):
                if not isinstance(a, Tag):
                    continue
                raw_href = a.get("href")
                href = raw_href if isinstance(raw_href, str) else (raw_href[0] if isinstance(raw_href, list) and raw_href else "")
                if not href:
                    continue
                if "?" in href:
                    abs_url = href if href.startswith("http") else urljoin(self.base_url, href)
                    p2 = urlparse(abs_url)
                    params = parse_qs(p2.query)
                    for name, values in params.items():
                        points.append({"url": str(abs_url), "parameter": str(name), "value": str(values[0]) if values else ""})
            # GET forms
            for form in soup.find_all("form"):
                if not isinstance(form, Tag):
                    continue
                method = str(form.get("method") or "GET").upper()
                if method != "GET":
                    continue
                action = form.get("action") or "/"
                inputs = form.find_all(["input", "select", "textarea"])
                for inp in inputs:
                    if not isinstance(inp, Tag):
                        continue
                    name = inp.get("name") or ""
                    if not name:
                        continue
                    base = urlunparse(parsed._replace(path=str(action), query=""))
                    points.append({"url": str(base), "parameter": str(name), "value": str(inp.get("value") or "")})
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

    def _discover_post_forms(self) -> List[PostForm]:
        forms_info: List[SSRFScanner.PostForm] = []
        response = self.client.get()
        if response is None:
            return forms_info
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                if not isinstance(form, Tag):
                    continue
                method = str(form.get("method") or "GET").upper()
                if method != "POST":
                    continue
                action_attr = form.get("action")
                action = action_attr if isinstance(action_attr, str) else (action_attr[0] if isinstance(action_attr, list) and action_attr else "/")
                inputs = []
                for inp in form.find_all(["input", "select", "textarea"]):
                    if not isinstance(inp, Tag):
                        continue
                    itype = inp.get("type") or "text"
                    if itype in ["submit", "button", "image"]:
                        continue
                    raw_name = inp.get("name")
                    name = raw_name if isinstance(raw_name, str) else (raw_name[0] if isinstance(raw_name, list) and raw_name else "")
                    if not name:
                        continue
                    inputs.append({"name": str(name), "value": str(inp.get("value") or "")})
                if inputs:
                    forms_info.append({"action": str(action or "/"), "inputs": inputs})
        except (ValueError, AttributeError, TypeError):
            return forms_info
        return forms_info

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

    def _analyze_evidence(self, text: str, _status: int, elapsed: float, payload: str) -> Optional[str]:
        """Retourne une chaîne d'évidence si un indice SSRF plausible est détecté."""
        # 1) Contenu metadata cloud
        if "169.254.169.254" in payload and self.METADATA_MARKERS.search(text):
            return "Indice metadata cloud renvoyé par l'application (poss. SSRF)"
        # 2) Messages d'erreur locaux
        if self.LOCAL_ERROR_MARKERS.search(text):
            return "Message d'erreur réseau local renvoyé (refused/timeout)"
        # 3) Temps de réponse anormal (> 2.5s) après un payload réseau
        if elapsed > 2.5:
            return f"Délai de réponse inhabituel ({elapsed:.2f}s) après injection d'URL"
        # 4) Écho de l'URL interne dans le contenu
        if any(h in text for h in ["127.0.0.1", "localhost", "::1", "169.254.169.254"]):
            return "Trace d'URL interne reflétée dans la réponse"
        return None
