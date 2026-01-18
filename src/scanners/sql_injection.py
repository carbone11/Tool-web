"""
Scanner pour les injections SQL
Détecte les vulnérabilités d'injection SQL dans les applications web
"""

import re
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


class SQLInjectionScanner:
    """Scanner pour détecter les vulnérabilités d'injection SQL"""
    
    def __init__(self, base_url: str, threads: int = 10, timeout: int = 10, payload_mode: str = "safe", proof_actions: bool = False):
        """
        Initialise le scanner SQL injection
        
        Args:
            base_url: URL de base à scanner
            threads: Nombre de threads pour les tests parallèles
            timeout: Timeout des requêtes
        """
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        self.logger = logging.getLogger('cybersec_tool.sql_scanner')
        self.proof_actions = bool(proof_actions)
        
        # Payloads SQL injection depuis le catalogue central (repli: liste locale)
        central = get_payloads_for_type_mode('sql injection', payload_mode or 'safe') or []
        self.sql_payloads = central if central else [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 'a'='a",
            "' UNION SELECT NULL--",
            "admin'--",
            "admin' #",
            "' OR 1=1#",
            "') OR '1'='1--",
            "1' OR '1'='1",
            "1 OR 1=1"
        ]
        
        # Signatures d'erreurs SQL
        self.error_signatures = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"Driver.* SQL[-_ ]*Server",
            r"OLE DB.* SQL Server",
            r"Warning.*mssql_.*",
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"Oracle error",
            r"Oracle.*Driver"
        ]
    
    def scan(self) -> Dict:
        """
        Lance le scan d'injection SQL
        
        Returns:
            Dictionnaire avec les résultats du scan
        """
        self.logger.info("🔍 Début du scan d'injection SQL")
        
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
            results['summary']['total_tests'] += len(self.sql_payloads)
            if vulns:
                results['summary']['vulnerable_params'] += 1
        
        # Test des formulaires POST
        for form in injection_points['forms']:
            vulns = self._test_form(form)
            results['vulnerabilities'].extend(vulns)
            results['summary']['total_tests'] += len(self.sql_payloads) * len(form['inputs'])
            if vulns:
                results['summary']['vulnerable_forms'] += 1
        
        self.logger.info("✅ Scan SQL terminé - %s vulnérabilités trouvées", len(results['vulnerabilities']))
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
                    except (ValueError, AttributeError, TypeError):
                        continue
            
            self.logger.info("📊 Trouvé %s paramètres GET et %s formulaires", len(points['get_params']), len(points['forms']))
            
        except (requests.exceptions.RequestException, ValueError, AttributeError) as e:
            self.logger.error("Erreur lors de la découverte: %s", str(e))
        
        return points
    
    def _test_get_parameter(self, param_info: Dict) -> List[Dict]:
        """
        Teste un paramètre GET pour les injections SQL
        
        Args:
            param_info: Informations sur le paramètre
            
        Returns:
            Liste des vulnérabilités trouvées
        """
        vulnerabilities = []
        base_url = param_info['url']
        param_name = param_info['parameter']
        
        for payload in self.sql_payloads:
            try:
                # Construction de l'URL avec payload
                parsed_url = urlparse(base_url)
                params = parse_qs(parsed_url.query)
                params[param_name] = [payload]
                
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed_url._replace(query=new_query))
                
                # Extraire le path relatif
                relative_path = test_url[len(self.base_url.rstrip('/')):]
                relative_path = str(relative_path)  # Assurer que c'est une string
                if not relative_path.startswith('/'):
                    relative_path = '/' + relative_path
                
                # Envoi de la requête
                response = self.client.get(relative_path)
                
                if response and self._detect_sql_error(response.text):
                    vulnerability = {
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'parameter': param_name,
                        'payload': payload,
                        'url': test_url,
                        'method': 'GET',
                        'description': f'Injection SQL détectée dans le paramètre "{param_name}"',
                        'evidence': self._extract_error_evidence(response.text)
                    }
                    if self.proof_actions:
                        pproofs = get_contextual_payloads('sql injection', 'proof-toggle', mode='safe')
                        if pproofs:
                            try:
                                pproof = pproofs[0]
                                proof_url = self._build_url_with_param(base_url, param_name, pproof)
                                vulnerability['proof_url'] = proof_url
                                vulnerability['proof_payload'] = pproof
                            except Exception:
                                pass
                    vulnerabilities.append(vulnerability)
                    self.logger.warning("🚨 SQL Injection trouvée: %s avec payload: %s", param_name, payload)
                    break  # Une vulnérabilité trouvée suffit pour ce paramètre
                    
            except (requests.exceptions.RequestException, ValueError, KeyError) as e:
                self.logger.debug("Erreur test GET %s: %s", param_name, str(e))
        
        return vulnerabilities
    
    def _test_form(self, form_info: Dict) -> List[Dict]:
        """
        Teste un formulaire pour les injections SQL
        
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
            
            for payload in self.sql_payloads:
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
                    
                    if response and self._detect_sql_error(response.text):
                        vulnerability = {
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'parameter': field_name,
                            'payload': payload,
                            'url': form_url,
                            'method': method,
                            'description': f'Injection SQL détectée dans le champ "{field_name}" du formulaire',
                            'evidence': self._extract_error_evidence(response.text)
                        }
                        if self.proof_actions:
                            pproofs = get_contextual_payloads('sql injection', 'proof-toggle', mode='safe')
                            if pproofs:
                                try:
                                    pproof = pproofs[0]
                                    # build GET proof even for POST forms (non-destructive)
                                    proof_data = {}
                                    for inp in inputs:
                                        if inp['name']:
                                            proof_data[inp['name']] = pproof if inp['name'] == field_name else (inp['value'] or 'test')
                                    q = urlencode(proof_data)
                                    vulnerability['proof_url'] = urljoin(self.base_url, f"{action}?{q}")
                                    vulnerability['proof_payload'] = pproof
                                except Exception:
                                    pass
                        vulnerabilities.append(vulnerability)
                        self.logger.warning("🚨 SQL Injection trouvée: %s avec payload: %s", field_name, payload)
                        break  # Une vulnérabilité trouvée suffit pour ce champ
                        
                except (requests.exceptions.RequestException, ValueError, KeyError) as e:
                    self.logger.debug("Erreur test formulaire %s: %s", field_name, str(e))
        
        return vulnerabilities
    
    def _detect_sql_error(self, content: str) -> bool:
        """
        Détecte les erreurs SQL dans le contenu de la réponse
        
        Args:
            content: Contenu HTML de la réponse
            
        Returns:
            True si une erreur SQL est détectée
        """
        for signature in self.error_signatures:
            if re.search(signature, content, re.IGNORECASE):
                return True
        return False
    
    def _extract_error_evidence(self, content: str) -> str:
        """
        Extrait l'évidence de l'erreur SQL
        
        Args:
            content: Contenu de la réponse
            
        Returns:
            Texte de l'erreur trouvée
        """
        for signature in self.error_signatures:
            match = re.search(signature, content, re.IGNORECASE)
            if match:
                # Extraire quelques lignes autour de l'erreur
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if re.search(signature, line, re.IGNORECASE):
                        start = max(0, i - 2)
                        end = min(len(lines), i + 3)
                        return '\n'.join(lines[start:end])
        return "Erreur SQL détectée"

    # Helpers
    def _build_url_with_param(self, base_url: str, param: str, value: str) -> str:
        parsed_url = urlparse(base_url)
        params = parse_qs(parsed_url.query)
        params[param] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed_url._replace(query=new_query))