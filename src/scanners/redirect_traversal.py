"""
Scanner combiné pour Open Redirect et Path Traversal (LFI basique).
Détection prudente et non-destructive pour aligner la reproduction dans le menu.

IMPORTANT: Utiliser uniquement avec autorisation explicite.
"""
from __future__ import annotations

import re
from typing import Dict, List, TypedDict
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, urljoin
from bs4 import BeautifulSoup, Tag

try:
    from ..utils.http_client import SecureHTTPClient
    from ..utils.payloads import get_payloads_for_type_mode, get_contextual_payloads
except ImportError:  # fallback absolute
    import sys, os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    sys.path.insert(0, parent_dir)
    from utils.http_client import SecureHTTPClient
    from utils.payloads import get_payloads_for_type_mode


class RedirectTraversalScanner:
    """Scanner pour Open Redirect et Path Traversal.

    - Open Redirect: paramètres comme url, next, redirect, return, continue, dest, target
    - Path Traversal: paramètres comme file, path, page, include, document
    """

    REDIR_PARAM_CANDIDATES = {
        "url", "next", "redirect", "return", "continue", "dest", "destination", "target", "goto"
    }
    TRAVERSAL_PARAM_CANDIDATES = {
        "file", "path", "page", "include", "document", "doc", "template", "view"
    }

    REDIR_PAYLOADS = [
        "//example.com",
        "https://example.com",
        "%2f%2fexample.com",
        "///example.com",
        "//@example.com",
    ]

    TRAVERSAL_PAYLOADS = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    ]

    PASSWD_MARKER = re.compile(r"root:.*:0:0:", re.IGNORECASE)
    WININI_MARKER = re.compile(r"\[(fonts|extensions|mci)\]|for 16-bit", re.IGNORECASE)

    def __init__(self, base_url: str, threads: int = 4, timeout: int = 10, payload_mode: str = "safe", proof_actions: bool = False):
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        # Charge des payloads centraux pour chaque type avec repli local
        redir_central = get_payloads_for_type_mode('open redirect', payload_mode or 'safe') or []
        trav_central = get_payloads_for_type_mode('path traversal', payload_mode or 'safe') or []
        self.redir_payloads = redir_central if redir_central else list(self.REDIR_PAYLOADS)
        self.traversal_payloads = trav_central if trav_central else list(self.TRAVERSAL_PAYLOADS)
        self.proof_actions = bool(proof_actions)

    def scan(self) -> Dict:
        results: Dict = {
            "vulnerabilities": [],
            "summary": {
                "total_tests": 0,
                "vulnerable_params_redirect": 0,
                "vulnerable_params_traversal": 0,
            },
        }

        # Test de connectivité
        if not self.client.test_connection():
            return results

        # Découverte rapide des endpoints/paramètres sur la page d'accueil
        candidates = self._discover_candidates()

        # Test Open Redirect
        for cand in candidates:
            pname = cand["parameter"]
            if pname.lower() not in self.REDIR_PARAM_CANDIDATES:
                continue
            for payload in self.redir_payloads:
                test_url = self._build_url_with_param(cand["url"], pname, payload)
                relative = self._relative_to_base(test_url)
                # Observer l'en-tête Location sans suivre la redirection
                resp = self.client.get(relative, allow_redirects=False)
                results["summary"]["total_tests"] += 1
                if resp is not None and 300 <= getattr(resp, "status_code", 0) < 400:
                    location = resp.headers.get("Location", "")
                    if "example.com" in location:
                        vuln = {
                            "type": "Open Redirect",
                            "severity": "Medium",
                            "parameter": pname,
                            "payload": payload,
                            "url": test_url,
                            "method": "GET",
                            "description": f"Paramètre '{pname}' vulnérable à une redirection non validée",
                            "evidence": f"Location: {location}",
                        }
                        if self.proof_actions:
                            pproofs = get_contextual_payloads('open redirect', 'proof-external', mode='safe')
                            if pproofs:
                                try:
                                    pproof = pproofs[0]
                                    vuln["proof_url"] = self._build_url_with_param(cand["url"], pname, pproof)
                                    vuln["proof_payload"] = pproof
                                except Exception:
                                    pass
                        results["vulnerabilities"].append(vuln)
                        results["summary"]["vulnerable_params_redirect"] += 1
                        break  # un payload suffit pour ce param

        # Test Path Traversal (GET)
        for cand in candidates:
            pname = cand["parameter"]
            if pname.lower() not in self.TRAVERSAL_PARAM_CANDIDATES:
                continue
            for payload in self.traversal_payloads:
                test_url = self._build_url_with_param(cand["url"], pname, payload)
                relative = self._relative_to_base(test_url)
                resp = self.client.get(relative)
                results["summary"]["total_tests"] += 1
                if not resp:
                    continue
                text = resp.text or ""
                evidence = None
                if self.PASSWD_MARKER.search(text):
                    evidence = "Extrait /etc/passwd détecté"
                elif self.WININI_MARKER.search(text):
                    evidence = "Extrait win.ini détecté"
                if evidence:
                    vuln = {
                        "type": "Path Traversal",
                        "severity": "High",
                        "parameter": pname,
                        "payload": payload,
                        "url": test_url,
                        "method": "GET",
                        "description": f"Paramètre '{pname}' vulnérable au Path Traversal",
                        "evidence": evidence,
                    }
                    if self.proof_actions:
                        pproofs = get_contextual_payloads('path traversal', 'proof-hosts', mode='safe')
                        if pproofs:
                            try:
                                pproof = pproofs[0]
                                vuln["proof_url"] = self._build_url_with_param(cand["url"], pname, pproof)
                                vuln["proof_payload"] = pproof
                            except Exception:
                                pass
                    results["vulnerabilities"].append(vuln)
                    results["summary"]["vulnerable_params_traversal"] += 1
                    break

        # Test Path Traversal (POST via formulaires)
        post_forms = self._discover_post_forms()
        for form in post_forms:
            action = form["action"] or "/"
            inputs = form["inputs"]
            # Liste des champs cibles potentiels
            target_fields = [i["name"] for i in inputs if i.get("name") and i["name"].lower() in self.TRAVERSAL_PARAM_CANDIDATES]
            if not target_fields:
                continue
            for field in target_fields:
                for payload in self.traversal_payloads:
                    # Construire les données du formulaire
                    data = {}
                    for inp in inputs:
                        name = inp.get("name")
                        if not name:
                            continue
                        if name == field:
                            data[name] = payload
                        else:
                            # Conserver une valeur par défaut raisonnable
                            data[name] = inp.get("value") or "test"
                    resp = self.client.post(action, data=data)
                    results["summary"]["total_tests"] += 1
                    if not resp:
                        continue
                    text = resp.text or ""
                    evidence = None
                    if self.PASSWD_MARKER.search(text):
                        evidence = "Extrait /etc/passwd détecté (POST)"
                    elif self.WININI_MARKER.search(text):
                        evidence = "Extrait win.ini détecté (POST)"
                    if evidence:
                        vuln = {
                            "type": "Path Traversal",
                            "severity": "High",
                            "parameter": field,
                            "payload": payload,
                            "url": urljoin(self.base_url, action),
                            "method": "POST",
                            "description": f"Champ '{field}' vulnérable au Path Traversal (POST)",
                            "evidence": evidence,
                        }
                        if self.proof_actions:
                            pproofs = get_contextual_payloads('path traversal', 'proof-hosts', mode='safe')
                            if pproofs:
                                try:
                                    pproof = pproofs[0]
                                    data2 = {}
                                    for inp in inputs:
                                        name = inp.get("name")
                                        if not name:
                                            continue
                                        data2[name] = pproof if name == field else (inp.get("value") or "test")
                                    q = urlencode(data2)
                                    vuln["proof_url"] = urljoin(self.base_url, f"{action}?{q}")
                                    vuln["proof_payload"] = pproof
                                except Exception:
                                    pass
                        results["vulnerabilities"].append(vuln)
                        results["summary"]["vulnerable_params_traversal"] += 1
                        break

        return results

    def _discover_candidates(self) -> List[Dict[str, str]]:
        """Découvre les paramètres GET de la page d'accueil et des formulaires.
        Retourne des entrées {url, parameter, value}.
        """
        points: List[Dict[str, str]] = []
        response = self.client.get()
        if response is None:
            return points

        # Paramètres de l'URL de base
        parsed = urlparse(self.base_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for name, values in params.items():
                points.append({
                    "url": self.base_url,
                    "parameter": name,
                    "value": values[0] if values else "",
                })

        # Inspecter les formulaires et liens
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Liens avec query string
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
                        points.append({
                            "url": str(abs_url),
                            "parameter": str(name),
                            "value": str(values[0]) if values else "",
                        })
            # Formulaires GET avec inputs nommés
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
                    points.append({
                        "url": str(base),
                        "parameter": str(name),
                        "value": str(inp.get("value") or ""),
                    })
        except (ValueError, AttributeError, TypeError):
            # En cas d'échec de parsing, on retourne juste les params de l'URL de base
            pass

        # Dédupliquer (url, parameter)
        seen = set()
        unique: List[Dict[str, str]] = []
        for p in points:
            key = (p["url"], p["parameter"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(p)
        return unique

    class PostForm(TypedDict):
        action: str
        inputs: List[Dict[str, str]]

    def _discover_post_forms(self) -> List[PostForm]:
        """Découvre les formulaires POST avec leurs champs.
        Retourne une liste d'objets: { action: str, inputs: [{name, value}] }
        """
        forms_info: List[RedirectTraversalScanner.PostForm] = []
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
        # Convertit une URL absolue en chemin relatif par rapport à self.base_url
        base = self.base_url.rstrip('/')
        if full_url.startswith(base):
            rel = full_url[len(base):]
            if not rel.startswith('/'):
                rel = '/' + rel
            return rel
        return full_url
