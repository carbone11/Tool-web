"""
Client HTTP sécurisé avec gestion des sessions et rate limiting

Options:
- Vérification TLS configurable via variable d'environnement `CYBERSEC_VERIFY_TLS`
    ("1"/"true" pour activer, "0"/"false" pour désactiver). Par défaut: activé.
"""

import requests
import time
import random
from urllib.parse import urljoin
from typing import Dict, Optional
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os


class SecureHTTPClient:
    """Client HTTP avec fonctionnalités de sécurité et rate limiting"""
    
    def __init__(self, base_url: str, timeout: int = 10, rate_limit: float = 0.5):
        """
        Initialise le client HTTP
        
        Args:
            base_url: URL de base pour les requêtes
            timeout: Timeout des requêtes en secondes
            rate_limit: Délai minimum entre les requêtes
        """
        self.base_url = base_url
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.last_request = 0
        self.logger = logging.getLogger('cybersec_tool.http_client')
        # Vérification TLS par défaut (activée), configurable via env
        env_val = str(os.getenv('CYBERSEC_VERIFY_TLS', '1')).lower().strip()
        self.verify_tls = env_val not in ('0', 'false', 'no')
        
        # User agents rotatifs - DOIT être défini AVANT _setup_session
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        # Configuration de la session
        self.session = requests.Session()
        self._setup_session()
    
    def _setup_session(self):
        """Configure la session avec retry strategy et headers"""
        # Strategy de retry
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Headers par défaut
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def _rate_limit(self):
        """Applique le rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request
        
        if time_since_last < self.rate_limit:
            sleep_time = self.rate_limit - time_since_last
            time.sleep(sleep_time)
        
        self.last_request = time.time()
    
    def get(self, path: str = '', **kwargs) -> Optional[requests.Response]:
        """
        Effectue une requête GET avec rate limiting
        
        Args:
            path: Chemin relatif à ajouter à l'URL de base
            **kwargs: Arguments supplémentaires pour requests
            
        Returns:
            Réponse HTTP ou None en cas d'erreur
        """
        return self._request('GET', path, **kwargs)
    
    def post(self, path: str = '', data: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        """Effectue une requête POST"""
        return self._request('POST', path, data=data, **kwargs)
    
    def _request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        """
        Méthode générique pour les requêtes HTTP
        
        Args:
            method: Méthode HTTP (GET, POST, etc.)
            path: Chemin relatif
            **kwargs: Arguments pour requests
            
        Returns:
            Réponse HTTP ou None
        """
        self._rate_limit()
        
        # Construction de l'URL complète
        url = urljoin(self.base_url, path)
        
        # Rotation du User-Agent
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents)
        })
        
        try:
            # Timeout par défaut
            kwargs.setdefault('timeout', self.timeout)
            # Vérification TLS selon configuration
            kwargs.setdefault('verify', self.verify_tls)
            kwargs.setdefault('allow_redirects', True)
            
            response = self.session.request(method, url, **kwargs)
            
            self.logger.debug("%s %s -> %s", method, url, response.status_code)
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.warning("Erreur requête %s %s: %s", method, url, str(e))
            return None
    
    def test_connection(self) -> bool:
        """
        Teste la connectivité avec la cible
        
        Returns:
            True si la connexion fonctionne
        """
        try:
            response = self.get()
            return response is not None and response.status_code < 500
        except (requests.exceptions.RequestException, ValueError, TypeError):
            return False
    
    def get_server_info(self) -> Dict[str, str]:
        """
        Récupère les informations du serveur
        
        Returns:
            Dictionnaire avec les informations du serveur
        """
        info = {}
        
        try:
            response = self.get()
            if response:
                headers = response.headers
                info['server'] = headers.get('Server', 'Unknown')
                info['powered_by'] = headers.get('X-Powered-By', 'Unknown')
                info['status_code'] = str(response.status_code)
                info['content_type'] = headers.get('Content-Type', 'Unknown')
        except (requests.exceptions.RequestException, ValueError, TypeError):
            pass
        
        return info
    
    def close(self):
        """Ferme la session"""
        self.session.close()