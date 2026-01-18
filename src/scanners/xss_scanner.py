"""
Scanner XSS (Cross-Site Scripting)
Détecte les vulnérabilités XSS dans les applications web
"""

import requests
from typing import List, Dict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import logging
from bs4 import BeautifulSoup, Tag

try:
    from ..utils.http_client import SecureHTTPClient
    from ..utils.payloads import get_payloads_for_type_mode, get_contextual_payloads
except ImportError:
    # Import absolu pour compatibilité avec menu_cli
    import sys
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    sys.path.insert(0, parent_dir)
    from utils.http_client import SecureHTTPClient
    from utils.payloads import get_payloads_for_type_mode


class XSSScanner:
    """Scanner pour détecter les vulnérabilités XSS"""
    
    def __init__(self, base_url: str, threads: int = 10, timeout: int = 10, payload_mode: str = "safe", proof_actions: bool = False, force_css_only: bool = False):
        """
        Initialise le scanner XSS
        
        Args:
            base_url: URL de base à scanner
            threads: Nombre de threads pour les tests parallèles
            timeout: Timeout des requêtes
        """
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        self.logger = logging.getLogger('cybersec_tool.xss_scanner')
        self.proof_actions = bool(proof_actions)
        self.force_css_only = bool(force_css_only)
        
        # Payloads XSS depuis le catalogue central, selon le mode demandé
        # Fallback sur un set local si le catalogue ne retourne rien
        central = get_payloads_for_type_mode('xss', payload_mode or 'safe') or []
        default_local = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "'\"><script>alert('XSS')</script>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "' onmouseover=alert(1) x='",
            '" onfocus=alert(1) x="',
            "<iframe srcdoc=\"<script>alert(1)<\\/script>\"></iframe>",
            "<svg><script>alert(1)</script></svg>",
        ]
        # Utiliser central si dispo, sinon fallback
        self.xss_payloads = central if central else default_local
        
        # Marqueurs uniques pour identifier les payloads réfléchis
        self.unique_markers = [
            "XSSTEST12345",
            "XSS_UNIQUE_MARKER",
            "REFLECTED_XSS_TEST"
        ]
    
    def scan(self) -> Dict:
        """
        Lance le scan XSS
        
        Returns:
            Dictionnaire avec les résultats du scan
        """
        self.logger.info("🔍 Début du scan XSS")
        
        results = {
            'vulnerabilities': [],
            'summary': {
                'total_tests': 0,
                'vulnerable_params': 0,
                'vulnerable_forms': 0
            }
        }
        
        # Test de connectivité
        if not self.client.test_connection():
            self.logger.error("❌ Impossible de se connecter à la cible")
            return results
        
        # Découverte des points d'injection
        injection_points = self._discover_injection_points()
        
        # Test des paramètres GET
        for point in injection_points['get_params']:
            vulns = self._test_get_parameter(point)
            results['vulnerabilities'].extend(vulns)
            results['summary']['total_tests'] += len(self.xss_payloads)
            if vulns:
                results['summary']['vulnerable_params'] += 1
        
        # Test des formulaires
        for form in injection_points['forms']:
            vulns = self._test_form(form)
            results['vulnerabilities'].extend(vulns)
            results['summary']['total_tests'] += len(self.xss_payloads) * len(form['inputs'])
            if vulns:
                results['summary']['vulnerable_forms'] += 1
        
        self.logger.info("✅ Scan XSS terminé - %s vulnérabilités trouvées", len(results['vulnerabilities']))
        return results
    
    def _discover_injection_points(self) -> Dict:
        """
        Découvre les points d'injection potentiels
        
        Returns:
            Dictionnaire avec les points d'injection
        """
        points = {
            'get_params': [],
            'forms': []
        }
        
        try:
            # Analyse de la page principale
            response = self.client.get()
            if not response:
                return points
            
            # Extraction des paramètres GET de l'URL
            parsed_url = urlparse(self.base_url)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param, values in params.items():
                    points['get_params'].append({
                        'url': self.base_url,
                        'parameter': param,
                        'value': values[0] if values else ''
                    })
            
            # Analyse du HTML pour trouver les formulaires
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                if isinstance(form, Tag):
                    try:
                        action = form.get('action') or ''
                        method_attr = form.get('method') or 'GET'
                        method = str(method_attr).upper() if isinstance(method_attr, str) else 'GET'
                        
                        form_data = {
                            'action': action,
                            'method': method,
                            'inputs': []
                        }
                        
                        # Récupération des champs du formulaire
                        inputs = form.find_all(['input', 'select', 'textarea'])
                        for input_field in inputs:
                            if isinstance(input_field, Tag):
                                input_type = input_field.get('type') or 'text'
                                if input_type not in ['submit', 'button', 'image']:
                                    form_data['inputs'].append({
                                        'name': input_field.get('name') or '',
                                        'type': input_type,
                                        'value': input_field.get('value') or ''
                                    })
                        
                        if form_data['inputs']:
                            points['forms'].append(form_data)
                    except (KeyError, ValueError, AttributeError):
                        continue
            
            self.logger.info(
                "📊 Trouvé %s paramètres GET et %s formulaires",
                len(points['get_params']),
                len(points['forms']),
            )
            
        except (requests.RequestException, ConnectionError) as e:
            self.logger.error("Erreur lors de la découverte: %s", str(e))
        
        return points
    
    def _test_get_parameter(self, param_info: Dict) -> List[Dict]:
        """
        Teste un paramètre GET pour les vulnérabilités XSS
        
        Args:
            param_info: Informations sur le paramètre
            
        Returns:
            Liste des vulnérabilités trouvées
        """
        vulnerabilities = []
        base_url = param_info['url']
        param_name = param_info['parameter']
        
        for payload in self.xss_payloads:
            try:
                # Construction de l'URL avec payload
                parsed_url = urlparse(base_url)
                params = parse_qs(parsed_url.query)
                params[param_name] = [payload]
                
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                # Extraire le path relatif
                relative_path = test_url[len(self.base_url.rstrip('/')):]
                relative_path = str(relative_path)
                if not relative_path.startswith('/'):
                    relative_path = '/' + relative_path
                
                # Envoi de la requête
                response = self.client.get(relative_path)
                
                if response and self._detect_xss_reflection(response.text, payload):
                    vulnerability = {
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'Medium',
                        'parameter': param_name,
                        'payload': payload,
                        'url': test_url,
                        'method': 'GET',
                        'description': f'XSS réfléchi détecté dans le paramètre "{param_name}"',
                        'evidence': self._extract_xss_evidence(response.text, payload)
                    }
                    # Tentative de preuve visuelle (panel de contrôle ou fond rouge) non destructive
                    if self.proof_actions:
                        # Détection CSP: si 'script-src' bloque les scripts inline, choisir une preuve CSS uniquement
                        csp = ''
                        try:
                            csp = response.headers.get('Content-Security-Policy', '') or ''
                        except Exception:
                            csp = ''
                        def _blocks_inline_js(csp_str: str) -> bool:
                            s = csp_str.lower()
                            if 'script-src' in s:
                                # Extraire la directive script-src
                                try:
                                    parts = [p.strip() for p in s.split(';')]
                                    script = next((p for p in parts if p.strip().startswith('script-src')), '')
                                    # inline autorisé si 'unsafe-inline' ou un nonce/hash est présent
                                    allows_inline = ("'unsafe-inline'" in script) or ('nonce-' in script) or ('sha256-' in script) or ('sha384-' in script)
                                    return not allows_inline
                                except Exception:
                                    return True
                            return False
                        prefer_css = _blocks_inline_js(csp) or self.force_css_only
                        if prefer_css:
                            proof_payloads = get_contextual_payloads('xss', 'proof-bg-red', mode='safe')
                            # choisir une preuve CSS (style tag) et éviter les scripts
                            css_only = [p for p in (proof_payloads or []) if ('<style' in p.lower()) and ('<script' not in p.lower())]
                            proof_payloads = css_only or proof_payloads
                        else:
                            proof_payloads = get_contextual_payloads('xss', 'proof-control-panel', mode='safe') or []
                            if not proof_payloads:
                                proof_payloads = get_contextual_payloads('xss', 'proof-bg-red', mode='safe') or []
                        if proof_payloads:
                            pproof = proof_payloads[0]
                            try:
                                proof_url = self._build_url_with_param(base_url, param_name, pproof)
                                rel_proof = self._relative_to_base(proof_url)
                                _ = self.client.get(rel_proof)
                                vulnerability['proof_payload'] = pproof
                                vulnerability['proof_url'] = proof_url
                            except Exception:
                                pass
                    vulnerabilities.append(vulnerability)
                    self.logger.warning("🚨 XSS trouvé: %s avec payload: %s", param_name, payload)
                    break  # Une vulnérabilité trouvée suffit pour ce paramètre
                    
            except (requests.RequestException, ValueError, KeyError) as e:
                self.logger.debug("Erreur test GET XSS %s: %s", param_name, str(e))
        
        return vulnerabilities
    
    def _test_form(self, form_info: Dict) -> List[Dict]:
        """
        Teste un formulaire pour les vulnérabilités XSS
        
        Args:
            form_info: Informations sur le formulaire
            
        Returns:
            Liste des vulnérabilités trouvées
        """
        vulnerabilities = []
        action = form_info['action']
        method = form_info['method']
        inputs = form_info['inputs']
        
        if not action:
            action = '/'
        
        # URL complète pour l'action
        form_url = urljoin(self.base_url, action)
        
        for input_field in inputs:
            field_name = input_field['name']
            if not field_name:
                continue
            
            for payload in self.xss_payloads:
                try:
                    # Préparation des données du formulaire
                    form_data = {}
                    for inp in inputs:
                        if inp['name']:
                            if inp['name'] == field_name:
                                form_data[inp['name']] = payload
                            else:
                                form_data[inp['name']] = inp['value'] or 'test'
                    
                    # Envoi de la requête
                    if method == 'POST':
                        response = self.client.post(action, data=form_data)
                    else:
                        # GET avec paramètres
                        query_string = urlencode(form_data)
                        response = self.client.get(f"{action}?{query_string}")
                    
                    if response and self._detect_xss_reflection(response.text, payload):
                        vulnerability = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'Medium',
                            'parameter': field_name,
                            'payload': payload,
                            'url': form_url,
                            'method': method,
                            'description': f'XSS réfléchi détecté dans le champ "{field_name}" du formulaire',
                            'evidence': self._extract_xss_evidence(response.text, payload)
                        }
                        # Tentative de preuve visuelle (panel de contrôle ou fond rouge) non destructive
                        if self.proof_actions:
                            # Détection CSP pour choisir CSS-only si nécessaire
                            csp = ''
                            try:
                                csp = response.headers.get('Content-Security-Policy', '') or ''
                            except Exception:
                                csp = ''
                            def _blocks_inline_js(csp_str: str) -> bool:
                                s = csp_str.lower()
                                if 'script-src' in s:
                                    try:
                                        parts = [p.strip() for p in s.split(';')]
                                        script = next((p for p in parts if p.strip().startswith('script-src')), '')
                                        allows_inline = ("'unsafe-inline'" in script) or ('nonce-' in script) or ('sha256-' in script) or ('sha384-' in script)
                                        return not allows_inline
                                    except Exception:
                                        return True
                                return False
                            prefer_css = _blocks_inline_js(csp) or self.force_css_only
                            if prefer_css:
                                proof_payloads = get_contextual_payloads('xss', 'proof-bg-red', mode='safe') or []
                                css_only = [p for p in proof_payloads if ('<style' in p.lower()) and ('<script' not in p.lower())]
                                proof_payloads = css_only or proof_payloads
                            else:
                                proof_payloads = get_contextual_payloads('xss', 'proof-control-panel', mode='safe') or []
                                if not proof_payloads:
                                    proof_payloads = get_contextual_payloads('xss', 'proof-bg-red', mode='safe') or []
                            if proof_payloads:
                                pproof = proof_payloads[0]
                                try:
                                    if method == 'POST':
                                        data = {}
                                        for inp in inputs:
                                            name = inp['name']
                                            if not name:
                                                continue
                                            data[name] = pproof if name == field_name else (inp.get('value') or 'test')
                                        _ = self.client.post(action, data=data)
                                        vulnerability['proof_payload'] = pproof
                                        vulnerability['proof_url'] = urljoin(self.base_url, action)
                                    else:
                                        proof_data = {}
                                        for inp in inputs:
                                            name = inp['name']
                                            if not name:
                                                continue
                                            proof_data[name] = pproof if name == field_name else (inp.get('value') or 'test')
                                        q = urlencode(proof_data)
                                        _ = self.client.get(f"{action}?{q}")
                                        vulnerability['proof_payload'] = pproof
                                        # Inclure la query dans l'URL de preuve pour un clic direct
                                        vulnerability['proof_url'] = f"{urljoin(self.base_url, action)}?{q}"
                                except Exception:
                                    pass
                        vulnerabilities.append(vulnerability)
                        self.logger.warning("🚨 XSS trouvé: %s avec payload: %s", field_name, payload)
                        break  # Une vulnérabilité trouvée suffit pour ce champ
                        
                except (requests.RequestException, ValueError, KeyError) as e:
                    self.logger.debug("Erreur test formulaire XSS %s: %s", field_name, str(e))
        
        return vulnerabilities
    
    def _detect_xss_reflection(self, content: str, payload: str) -> bool:
        """
        Détecte si le payload XSS est réfléchi dans la réponse
        
        Args:
            content: Contenu HTML de la réponse
            payload: Payload XSS testé
            
        Returns:
            True si le payload est réfléchi
        """
        # Recherche directe du payload
        if payload in content:
            return True
        
        # Recherche de parties du payload (pour les payloads encodés/filtrés)
        if 'alert' in payload and 'alert' in content.lower():
            return True
        
        if 'script' in payload and 'script' in content.lower():
            return True
        
        if 'onerror' in payload and 'onerror' in content.lower():
            return True
        
        if 'onload' in payload and 'onload' in content.lower():
            return True
        
        return False
    
    def _extract_xss_evidence(self, content: str, payload: str) -> str:
        """
        Extrait l'évidence de la vulnérabilité XSS
        
        Args:
            content: Contenu de la réponse
            payload: Payload utilisé
            
        Returns:
            Texte de l'évidence trouvée
        """
        lines = content.split('\n')
        for i, line in enumerate(lines):
            keywords = ['alert', 'script', 'onerror', 'onload']
            reflected = payload in line
            weak_match = any(
                (k in line.lower()) for k in keywords if k in payload.lower()
            )
            if reflected or weak_match:
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                return '\n'.join(lines[start:end])
        
        return f"Payload réfléchi: {payload}"

    # --- URL helpers ---
    def _build_url_with_param(self, base_url: str, param: str, value: str) -> str:
        parsed_url = urlparse(base_url)
        params = parse_qs(parsed_url.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed_url._replace(query=new_query))

    def _relative_to_base(self, full_url: str) -> str:
        base = self.base_url.rstrip('/')
        if full_url.startswith(base):
            rel = full_url[len(base):]
            if not rel.startswith('/'):
                rel = '/' + rel
            return rel
        return full_url
