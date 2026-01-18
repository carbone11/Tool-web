"""
Scanner Command Injection (non-destructif) avec heuristiques de réflexion et de timing.

Note: Ce scanner tente des payloads sûrs (echo marqueur) et, si activé en mode agressif,
des payloads de temporisation légers (sleep/ping local) pour détecter une exécution de commande.
Utilisation uniquement avec autorisation.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
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


@dataclass
class CmdiConfig:
    aggressive: bool = False
    delay_threshold: float = 2.0  # seconds


class CommandInjectionScanner:
    """Scanner d'injection de commandes (GET/POST) non destructif.

    - Paramètres candidats: cmd, command, exec, ping, host, ip, dir, file, target, q
    - Payloads: echo d'un marqueur unique + payloads de délai (si agressif)
    """

    PARAM_CANDIDATES = {"cmd", "command", "exec", "ping", "host", "ip", "dir", "file", "target", "q"}
    MARKER = "CYBERINJECT123"
    REFLECTION_PAYLOADS = [
        f"; echo {MARKER}",
        f"&& echo {MARKER}",
        f"| echo {MARKER}",
    ]
    # Payloads de temporisation multi-OS (UNIX/Windows). Certains échoueront inoffensivement.
    TIMING_PAYLOADS = [
        "; sleep 2",
        "&& sleep 2",
        "| sleep 2",
        "& ping -n 2 127.0.0.1",
        "; ping -c 2 127.0.0.1",
    ]

    class PostForm(TypedDict):
        action: str
        inputs: List[Dict[str, str]]

    def __init__(self, base_url: str, threads: int = 4, timeout: int = 10, aggressive: bool = False, payload_mode: str = "safe", proof_actions: bool = False):
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        self.cfg = CmdiConfig(aggressive=aggressive)
        self.payload_mode = payload_mode or "safe"
        self.proof_actions = bool(proof_actions)
        # Enrichir les payloads via le catalogue central (command injection)
        central = get_payloads_for_type_mode('command injection', payload_mode or 'safe') or []
        # Séparer ceux qui contiennent 'echo' (réflexion) et ceux de timing connus
        ref_add = [p for p in central if 'echo' in p]
        time_add = [p for p in central if 'sleep' in p or 'ping' in p]
        # Fusionner en conservant l'ordre et sans doublons
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
        results: Dict = {
            "vulnerabilities": [],
            "summary": {
                "total_tests": 0,
                "suspected_cmdi": 0,
            },
        }

        if not self.client.test_connection():
            return results

        get_candidates = self._discover_get_candidates()
        post_forms = self._discover_post_forms()

        # GET path
        for cand in get_candidates:
            pname = cand["parameter"]
            if pname.lower() not in self.PARAM_CANDIDATES:
                continue
            base_url = cand["url"]
            baseline_url = self._build_url_with_param(base_url, pname, cand.get("value", ""))
            baseline_elapsed, _baseline_len, _ = self._fetch_metrics(baseline_url)
            # Reflection payloads
            for payload in self.REFLECTION_PAYLOADS:
                test_url = self._build_url_with_param(base_url, pname, payload)
                elapsed, _text_len, text = self._fetch_metrics(test_url)
                results["summary"]["total_tests"] += 1
                if text and self.MARKER in text:
                    vuln = {
                        "type": "Command Injection",
                        "severity": "High",
                        "parameter": pname,
                        "payload": payload,
                        "url": test_url,
                        "method": "GET",
                        "description": f"Paramètre '{pname}' reflète une exécution de commande (echo marqueur)",
                        "evidence": "Marqueur d'echo présent dans la réponse",
                    }
                    # Tentative de preuve (expert-deep uniquement): écrire et lire un marqueur temporaire
                    if self.proof_actions and self.payload_mode.strip().lower() == "expert-deep":
                        proof_payloads = get_contextual_payloads('command injection', 'proof-marker-file', mode='expert-deep')
                        if proof_payloads:
                            pproof = proof_payloads[0]
                            try:
                                proof_url = self._build_url_with_param(base_url, pname, pproof)
                                _elapsed_p, _len_p, text_p = self._fetch_metrics(proof_url)
                                if text_p and "PROOF_MARK" in text_p:
                                    vuln["proof_payload"] = pproof
                                    vuln["proof_url"] = proof_url
                                    vuln["proof_evidence"] = "Marqueur PROOF_MARK reflété"
                            except Exception:
                                pass
                    results["vulnerabilities"].append(vuln)
                    results["summary"]["suspected_cmdi"] += 1
                    break
            # Timing payloads (aggressif)
            if self.cfg.aggressive and results["summary"]["suspected_cmdi"] == 0:
                for payload in self.TIMING_PAYLOADS:
                    test_url = self._build_url_with_param(base_url, pname, payload)
                    elapsed, _text_len2, _ = self._fetch_metrics(test_url)
                    results["summary"]["total_tests"] += 1
                    if elapsed - baseline_elapsed >= self.cfg.delay_threshold:
                        results["vulnerabilities"].append({
                            "type": "Command Injection",
                            "severity": "High",
                            "parameter": pname,
                            "payload": payload,
                            "url": test_url,
                            "method": "GET",
                            "description": (
                                f"Paramètre '{pname}' provoque un délai significatif (timing)"
                            ),
                            "evidence": (
                                f"Delta délai {elapsed - baseline_elapsed:.2f}s (>"
                                f"{self.cfg.delay_threshold}s)"
                            ),
                        })
                        results["summary"]["suspected_cmdi"] += 1
                        break

        # POST path
        for form in post_forms:
            action = form["action"] or "/"
            inputs = form["inputs"]
            fields = [i["name"] for i in inputs if i.get("name") and i["name"].lower() in self.PARAM_CANDIDATES]
            if not fields:
                continue
            for field in fields:
                # Baseline
                data_base = {i["name"]: (i.get("value") or "test") for i in inputs if i.get("name")}
                baseline_elapsed, _baseline_len2, _ = self._fetch_metrics_post(action, data_base)
                # Reflection
                for payload in self.REFLECTION_PAYLOADS:
                    data = data_base.copy()
                    data[field] = payload
                    elapsed, _text_len3, text = self._fetch_metrics_post(action, data)
                    results["summary"]["total_tests"] += 1
                    if text and self.MARKER in text:
                        vuln = {
                            "type": "Command Injection",
                            "severity": "High",
                            "parameter": field,
                            "payload": payload,
                            "url": urljoin(self.base_url, action),
                            "method": "POST",
                            "description": f"Champ '{field}' reflète une exécution de commande (POST)",
                            "evidence": "Marqueur d'echo présent dans la réponse",
                        }
                        # Tentative de preuve (expert-deep uniquement)
                        if self.proof_actions and self.payload_mode.strip().lower() == "expert-deep":
                            proof_payloads = get_contextual_payloads('command injection', 'proof-marker-file', mode='expert-deep')
                            if proof_payloads:
                                pproof = proof_payloads[0]
                                try:
                                    data = data_base.copy()
                                    data[field] = pproof
                                    _elapsed_p, _len_p, text_p = self._fetch_metrics_post(action, data)
                                    if text_p and "PROOF_MARK" in text_p:
                                        vuln["proof_payload"] = pproof
                                        vuln["proof_url"] = urljoin(self.base_url, action)
                                        vuln["proof_evidence"] = "Marqueur PROOF_MARK reflété"
                                except Exception:
                                    pass
                        results["vulnerabilities"].append(vuln)
                        results["summary"]["suspected_cmdi"] += 1
                        break
                # Timing
                if self.cfg.aggressive and results["summary"]["suspected_cmdi"] == 0:
                    for payload in self.TIMING_PAYLOADS:
                        data = data_base.copy()
                        data[field] = payload
                        elapsed, _text_len4, _ = self._fetch_metrics_post(action, data)
                        results["summary"]["total_tests"] += 1
                        if elapsed - baseline_elapsed >= self.cfg.delay_threshold:
                            results["vulnerabilities"].append({
                                "type": "Command Injection",
                                "severity": "High",
                                "parameter": field,
                                "payload": payload,
                                "url": urljoin(self.base_url, action),
                                "method": "POST",
                                "description": (
                                    f"Champ '{field}' provoque un délai significatif (POST)"
                                ),
                                "evidence": (
                                    f"Delta délai {elapsed - baseline_elapsed:.2f}s (>"
                                    f"{self.cfg.delay_threshold}s)"
                                ),
                            })
                            results["summary"]["suspected_cmdi"] += 1
                            break

        return results

    # --- helpers ---
    def _discover_get_candidates(self) -> List[Dict[str, str]]:
        pts: List[Dict[str, str]] = []
        response = self.client.get()
        if response is None:
            return pts
        parsed = urlparse(self.base_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for name, values in params.items():
                pts.append({
                    "url": self.base_url,
                    "parameter": name,
                    "value": values[0] if values else "",
                })
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for a in soup.find_all("a"):
                if not isinstance(a, Tag):
                    continue
                raw_href = a.get("href")
                href = (
                    raw_href if isinstance(raw_href, str)
                    else (raw_href[0] if isinstance(raw_href, list) and raw_href else "")
                )
                if not href:
                    continue
                if "?" in href:
                    abs_url = href if href.startswith("http") else urljoin(self.base_url, href)
                    p2 = urlparse(abs_url)
                    params = parse_qs(p2.query)
                    for name, values in params.items():
                        pts.append({
                            "url": str(abs_url),
                            "parameter": str(name),
                            "value": str(values[0]) if values else "",
                        })
        except (ValueError, AttributeError, TypeError):
            pass
        # de-dup
        seen = set()
        out: List[Dict[str, str]] = []
        for p in pts:
            key = (p["url"], p["parameter"])
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
        return out

    # PostForm re-déclarée plus bas précédemment: éviter doublon

    def _discover_post_forms(self) -> List[PostForm]:
        forms_info: List[CommandInjectionScanner.PostForm] = []
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
                action = (
                    action_attr if isinstance(action_attr, str)
                    else (action_attr[0] if isinstance(action_attr, list) and action_attr else "/")
                )
                inputs = []
                for inp in form.find_all(["input", "select", "textarea"]):
                    if not isinstance(inp, Tag):
                        continue
                    itype = inp.get("type") or "text"
                    if itype in ["submit", "button", "image"]:
                        continue
                    raw_name = inp.get("name")
                    name = (
                        raw_name if isinstance(raw_name, str)
                        else (raw_name[0] if isinstance(raw_name, list) and raw_name else "")
                    )
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

    def _fetch_metrics(self, full_url: str) -> tuple[float, int, Optional[str]]:
        relative = self._relative_to_base(full_url)
        start = time.time()
        resp = self.client.get(relative)
        elapsed = time.time() - start
        if not resp:
            return elapsed, 0, None
        text = resp.text or ""
        return elapsed, len(text), text

    def _fetch_metrics_post(self, action: str, data: Dict[str, str]) -> tuple[float, int, Optional[str]]:
        start = time.time()
        resp = self.client.post(action, data=data)
        elapsed = time.time() - start
        if not resp:
            return elapsed, 0, None
        text = resp.text or ""
        return elapsed, len(text), text

    def _relative_to_base(self, full_url: str) -> str:
        base = self.base_url.rstrip('/')
        if full_url.startswith(base):
            rel = full_url[len(base):]
            if not rel.startswith('/'):
                rel = '/' + rel
            return rel
        return full_url
