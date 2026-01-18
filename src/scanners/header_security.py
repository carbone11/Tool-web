"""
Scanner de sécurité des en-têtes HTTP
Analyse les en-têtes de sécurité et détecte les configurations faibles
"""

from typing import Dict, List, Any
import logging
import re

try:
    from ..utils.http_client import SecureHTTPClient
except ImportError:
    # Import absolu pour compatibilité avec menu_cli
    import sys
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    sys.path.insert(0, parent_dir)
    from utils.http_client import SecureHTTPClient


class HeaderSecurityScanner:
    """Scanner pour analyser la sécurité des en-têtes HTTP"""
    
    def __init__(self, base_url: str, timeout: int = 10):
        """
        Initialise le scanner d'en-têtes de sécurité
        
        Args:
            base_url: URL de base à scanner
            threads: Nombre de threads (non utilisé pour ce scanner)
            timeout: Timeout des requêtes
        """
        self.base_url = base_url
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout)
        self.logger = logging.getLogger('cybersec_tool.header_scanner')
        
        # En-têtes de sécurité attendus
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'Force l\'utilisation de HTTPS',
                'severity': 'Medium',
                'recommendation': 'Ajouter: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'Content-Security-Policy': {
                'description': 'Prévient les attaques XSS et injection de code',
                'severity': 'High',
                'recommendation': 'Implémenter une politique CSP stricte'
            },
            'X-Frame-Options': {
                'description': 'Prévient le clickjacking',
                'severity': 'Medium',
                'recommendation': 'Ajouter: X-Frame-Options: DENY ou SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'Empêche le MIME type sniffing',
                'severity': 'Low',
                'recommendation': 'Ajouter: X-Content-Type-Options: nosniff'
            },
            'Referrer-Policy': {
                'description': 'Contrôle les informations de référent',
                'severity': 'Low',
                'recommendation': 'Ajouter: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'description': 'Contrôle les fonctionnalités du navigateur',
                'severity': 'Low',
                'recommendation': 'Implémenter une politique de permissions restrictive'
            }
        }
        
        # En-têtes dangereux qui exposent des informations
        self.dangerous_headers = {
            'Server': 'Expose le type et version du serveur',
            'X-Powered-By': 'Expose la technologie utilisée',
            'X-AspNet-Version': 'Expose la version ASP.NET',
            'X-AspNetMvc-Version': 'Expose la version ASP.NET MVC'
        }
    
    def scan(self) -> Dict:
        """
        Lance le scan des en-têtes de sécurité
        
        Returns:
            Dictionnaire avec les résultats du scan
        """
        self.logger.info("🔍 Début du scan des en-têtes de sécurité")
        
        results = {
            'vulnerabilities': [],
            'summary': {
                'missing_headers': 0,
                'weak_headers': 0,
                'information_disclosure': 0,
                'total_checks': len(self.security_headers) + len(self.dangerous_headers)
            }
        }
        
        # Test de connectivité
        if not self.client.test_connection():
            self.logger.error("❌ Impossible de se connecter à la cible")
            return results
        
        # Récupération des en-têtes
        response = self.client.get()
        if not response:
            self.logger.error("❌ Impossible d'obtenir les en-têtes")
            return results
        
        headers = response.headers
        self.logger.info("📊 Analyse de %s en-têtes HTTP", len(headers))
        
        # Vérification des en-têtes de sécurité manquants
        missing_vulns = self._check_missing_security_headers(headers)
        results['vulnerabilities'].extend(missing_vulns)
        results['summary']['missing_headers'] = len(missing_vulns)
        
        # Vérification des en-têtes de sécurité faibles
        weak_vulns = self._check_weak_security_headers(headers)
        results['vulnerabilities'].extend(weak_vulns)
        results['summary']['weak_headers'] = len(weak_vulns)
        
        # Vérification de la divulgation d'informations
        info_vulns = self._check_information_disclosure(headers)
        results['vulnerabilities'].extend(info_vulns)
        results['summary']['information_disclosure'] = len(info_vulns)
        
        # Vérifications supplémentaires
        additional_vulns = self._additional_security_checks(response)
        results['vulnerabilities'].extend(additional_vulns)
        
        self.logger.info("✅ Scan des en-têtes terminé - %s problèmes trouvés", len(results['vulnerabilities']))
        return results
    
    def _check_missing_security_headers(self, headers: Any) -> List[Dict]:
        """
        Vérifie les en-têtes de sécurité manquants
        
        Args:
            headers: En-têtes HTTP de la réponse
            
        Returns:
            Liste des vulnérabilités trouvées
        """
        vulnerabilities = []
        
        for header_name, header_info in self.security_headers.items():
            if header_name not in headers:
                vulnerability = {
                    'type': 'Missing Security Header',
                    'severity': header_info['severity'],
                    'header': header_name,
                    'description': f'En-tête de sécurité manquant: {header_name}',
                    'impact': header_info['description'],
                    'recommendation': header_info['recommendation']
                }
                vulnerabilities.append(vulnerability)
                self.logger.warning("⚠️ En-tête manquant: %s", header_name)
        
        return vulnerabilities
    
    def _check_weak_security_headers(self, headers: Any) -> List[Dict]:
        """
        Vérifie la configuration des en-têtes de sécurité présents
        
        Args:
            headers: En-têtes HTTP de la réponse
            
        Returns:
            Liste des vulnérabilités trouvées
        """
        vulnerabilities = []
        
        # Vérification de Content-Security-Policy
        csp = headers.get('Content-Security-Policy', '')
        if csp:
            if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
                vulnerabilities.append({
                    'type': 'Weak Content Security Policy',
                    'severity': 'Medium',
                    'header': 'Content-Security-Policy',
                    'value': csp,
                    'description': 'CSP contient des directives dangereuses (unsafe-inline/unsafe-eval)',
                    'recommendation': 'Supprimer unsafe-inline et unsafe-eval, utiliser des nonces ou hashes'
                })
        
        # Vérification de Strict-Transport-Security
        hsts = headers.get('Strict-Transport-Security', '')
        if hsts:
            # Extraction de max-age
            max_age_match = re.search(r'max-age=(\d+)', hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # Moins d'un an
                    vulnerabilities.append({
                        'type': 'Weak HSTS Configuration',
                        'severity': 'Low',
                        'header': 'Strict-Transport-Security',
                        'value': hsts,
                        'description': f'HSTS max-age trop court: {max_age} secondes',
                        'recommendation': 'Utiliser max-age=31536000 (1 an) minimum'
                    })
        
        # Vérification de X-Frame-Options
        xfo = headers.get('X-Frame-Options', '')
        if xfo and xfo.upper() == 'ALLOWALL':
            vulnerabilities.append({
                'type': 'Weak X-Frame-Options',
                'severity': 'Medium',
                'header': 'X-Frame-Options',
                'value': xfo,
                'description': 'X-Frame-Options permet le framing de toutes les sources',
                'recommendation': 'Utiliser DENY ou SAMEORIGIN'
            })
        
        return vulnerabilities
    
    def _check_information_disclosure(self, headers: Any) -> List[Dict]:
        """
        Vérifie la divulgation d'informations via les en-têtes
        
        Args:
            headers: En-têtes HTTP de la réponse
            
        Returns:
            Liste des vulnérabilités trouvées
        """
        vulnerabilities = []
        
        for header_name, description in self.dangerous_headers.items():
            if header_name in headers:
                vulnerability = {
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'header': header_name,
                    'value': headers[header_name],
                    'description': f'Divulgation d\'information: {description}',
                    'recommendation': f'Supprimer ou masquer l\'en-tête {header_name}'
                }
                vulnerabilities.append(vulnerability)
                self.logger.warning("ℹ️ Information exposée: %s: %s", header_name, headers[header_name])
        
        return vulnerabilities
    
    def _additional_security_checks(self, response) -> List[Dict]:
        """
        Effectue des vérifications de sécurité supplémentaires
        
        Args:
            response: Réponse HTTP complète
            
        Returns:
            Liste des vulnérabilités trouvées
        """
        vulnerabilities = []
        headers = response.headers
        
        # Vérification des cookies sécurisés
        set_cookies = headers.get('Set-Cookie', '')
        if set_cookies:
            if 'Secure' not in set_cookies:
                vulnerabilities.append({
                    'type': 'Insecure Cookie',
                    'severity': 'Medium',
                    'description': 'Cookie sans attribut Secure',
                    'recommendation': 'Ajouter l\'attribut Secure aux cookies'
                })
            
            if 'HttpOnly' not in set_cookies:
                vulnerabilities.append({
                    'type': 'Cookie without HttpOnly',
                    'severity': 'Medium',
                    'description': 'Cookie sans attribut HttpOnly',
                    'recommendation': 'Ajouter l\'attribut HttpOnly aux cookies'
                })
            
            if 'SameSite' not in set_cookies:
                vulnerabilities.append({
                    'type': 'Cookie without SameSite',
                    'severity': 'Low',
                    'description': 'Cookie sans attribut SameSite',
                    'recommendation': 'Ajouter l\'attribut SameSite aux cookies'
                })
        
        # Vérification de la version HTTP
        if hasattr(response, 'raw') and hasattr(response.raw, 'version'):
            http_version = response.raw.version
            if http_version < 20:  # HTTP/2 = 20
                vulnerabilities.append({
                    'type': 'Outdated HTTP Version',
                    'severity': 'Low',
                    'description': f'Version HTTP obsolète: HTTP/{http_version/10}',
                    'recommendation': 'Migrer vers HTTP/2 ou HTTP/3'
                })
        
        # Vérification de la compression
        content_encoding = headers.get('Content-Encoding', '')
        if 'gzip' in content_encoding or 'deflate' in content_encoding:
            # Possible vulnérabilité BREACH si HTTPS + compression + secrets
            if response.url.startswith('https://'):
                vulnerabilities.append({
                    'type': 'Potential BREACH Vulnerability',
                    'severity': 'Low',
                    'description': 'Compression activée sur HTTPS (risque BREACH)',
                    'recommendation': 'Éviter la compression de contenu contenant des secrets'
                })
        
        return vulnerabilities