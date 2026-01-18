"""
Directory Buster - Découverte de répertoires et fichiers cachés
Énumère les répertoires et fichiers potentiellement accessibles
"""

from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional
import logging
import time
from urllib.parse import urljoin
import requests

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


class DirectoryBuster:
    """Scanner pour découvrir les répertoires et fichiers cachés"""
    
    def __init__(self, base_url: str, threads: int = 20, timeout: int = 10):
        """
        Initialise le directory buster
        
        Args:
            base_url: URL de base à scanner
            threads: Nombre de threads pour les requêtes parallèles
            timeout: Timeout des requêtes
        """
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.client = SecureHTTPClient(base_url, timeout, rate_limit=0.1)
        self.logger = logging.getLogger('cybersec_tool.directory_buster')
        
        # Dictionnaire de répertoires communs
        self.common_directories = [
            'admin', 'administrator', 'management', 'manager',
            'login', 'auth', 'authentication',
            'backup', 'backups', 'bak', 'old',
            'test', 'testing', 'dev', 'development',
            'config', 'configuration', 'conf',
            'api', 'rest', 'webapi',
            'docs', 'documentation', 'help',
            'images', 'img', 'pics', 'photos',
            'css', 'js', 'javascript', 'assets',
            'uploads', 'files', 'download', 'downloads',
            'private', 'secret', 'hidden',
            'temp', 'tmp', 'cache',
            'logs', 'log', 'debug',
            'db', 'database', 'data',
            'src', 'source', 'code',
            'include', 'inc', 'lib', 'libs',
            'vendor', 'modules', 'plugins',
            'wp-admin', 'wp-content', 'wp-includes',
            'phpMyAdmin', 'phpmyadmin', 'pma'
        ]
        
        # Fichiers sensibles communs
        self.common_files = [
            'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
            'config.php', 'config.inc.php', 'settings.php',
            'database.php', 'db.php', 'connection.php',
            'backup.sql', 'dump.sql', 'database.sql',
            '.env', '.git/config', '.svn/entries',
            'admin.php', 'login.php', 'auth.php',
            'test.php', 'phpinfo.php', 'info.php',
            'readme.txt', 'README.md', 'INSTALL.txt',
            'changelog.txt', 'version.txt',
            'error.log', 'access.log', 'debug.log',
            'package.json', 'composer.json', 'requirements.txt'
        ]
        
        # Extensions intéressantes
        self.interesting_extensions = [
            '.bak', '.backup', '.old', '.orig', '.tmp',
            '.conf', '.config', '.ini', '.xml',
            '.sql', '.db', '.sqlite',
            '.log', '.txt', '.md'
        ]
    
    def scan(self) -> Dict:
        """
        Lance la découverte de répertoires et fichiers
        
        Returns:
            Dictionnaire avec les résultats du scan
        """
        self.logger.info("🔍 Début de la découverte de répertoires et fichiers")
        
        results = {
            'vulnerabilities': [],
            'summary': {
                'total_requests': 0,
                'found_directories': 0,
                'found_files': 0,
                'interesting_responses': 0
            },
            'found_paths': []
        }
        
        # Test de connectivité
        if not self.client.test_connection():
            self.logger.error("❌ Impossible de se connecter à la cible")
            return results
        
        # Liste complète des chemins à tester
        paths_to_test = []
        
        # Ajouter les répertoires
        for directory in self.common_directories:
            paths_to_test.append(f"/{directory}/")
            paths_to_test.append(f"/{directory}")
        
        # Ajouter les fichiers
        for file in self.common_files:
            paths_to_test.append(f"/{file}")
        
        # Ajouter des variantes avec extensions
        for directory in self.common_directories[:10]:  # Limiter pour éviter trop de requêtes
            for ext in self.interesting_extensions:
                paths_to_test.append(f"/{directory}{ext}")
        
        results['summary']['total_requests'] = len(paths_to_test)
        
        # Scanner les chemins en parallèle
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for path in paths_to_test:
                future = executor.submit(self._test_path, path)
                futures.append((future, path))
            
            # Collecte des résultats
            for future, path in futures:
                try:
                    path_result = future.result(timeout=self.timeout + 2)
                    if path_result and path_result['accessible']:
                        results['found_paths'].append(path_result)
                        
                        if path_result['type'] == 'directory':
                            results['summary']['found_directories'] += 1
                        else:
                            results['summary']['found_files'] += 1
                        
                        # Vérifier si c'est une découverte intéressante
                        vuln = self._analyze_discovery(path_result)
                        if vuln:
                            results['vulnerabilities'].append(vuln)
                            results['summary']['interesting_responses'] += 1
                
                except (requests.RequestException, ConnectionError, TimeoutError) as e:
                    self.logger.debug("Erreur test chemin %s: %s", path, str(e))
        
        scan_duration = time.time() - start_time
        total_found = results['summary']['found_directories'] + results['summary']['found_files']
        self.logger.info("✅ Découverte terminée en %.2fs - %s éléments trouvés", scan_duration, total_found)
        
        return results
    
    def _test_path(self, path: str) -> Optional[Dict]:
        """
        Teste l'accessibilité d'un chemin
        
        Args:
            path: Chemin à tester
            
        Returns:
            Dictionnaire avec les informations du chemin ou None
        """
        try:
            response = self.client.get(path)
            
            if response is None:
                return None
            
            # Analyser la réponse
            result = {
                'path': path,
                'url': urljoin(self.base_url, path),
                'status_code': response.status_code,
                'accessible': False,
                'type': 'directory' if path.endswith('/') else 'file',
                'size': len(response.content) if response.content else 0,
                'content_type': response.headers.get('Content-Type', ''),
                'interesting': False
            }
            
            # Déterminer si le chemin est accessible
            if response.status_code in [200, 201, 202]:
                result['accessible'] = True
                self.logger.info("✅ Trouvé: %s (HTTP %s)", path, response.status_code)
            elif response.status_code in [301, 302, 307, 308]:
                result['accessible'] = True
                result['redirect'] = response.headers.get('Location', '')
                self.logger.info("🔄 Redirection: %s -> %s", path, result['redirect'])
            elif response.status_code == 403:
                result['accessible'] = True
                result['forbidden'] = True
                self.logger.info("🚫 Interdit: %s (HTTP 403)", path)
            elif response.status_code == 401:
                result['accessible'] = True
                result['requires_auth'] = True
                self.logger.info("🔐 Authentification requise: %s (HTTP 401)", path)
            
            return result if result['accessible'] else None
            
        except (requests.RequestException, ConnectionError, TimeoutError) as e:
            self.logger.debug("Erreur requête %s: %s", path, str(e))
            return None
    
    def _analyze_discovery(self, path_result: Dict) -> Optional[Dict]:
        """
        Analyse une découverte pour déterminer si elle présente un intérêt sécuritaire
        
        Args:
            path_result: Résultat de la découverte
            
        Returns:
            Dictionnaire de vulnérabilité ou None
        """
        path = path_result['path']
        status_code = path_result['status_code']
        
        # Fichiers sensibles
        sensitive_files = {
            'robots.txt': 'Fichier robots.txt accessible - peut révéler des chemins sensibles',
            '.htaccess': 'Fichier .htaccess accessible - configuration Apache exposée',
            'web.config': 'Fichier web.config accessible - configuration IIS exposée',
            '.env': 'Fichier .env accessible - variables d\'environnement exposées',
            'config.php': 'Fichier de configuration PHP accessible',
            'phpinfo.php': 'Page phpinfo accessible - informations système exposées',
            'backup.sql': 'Fichier de sauvegarde SQL accessible',
            'error.log': 'Fichier de log d\'erreurs accessible'
        }
        
        # Vérifier les fichiers sensibles
        for sensitive_file, description in sensitive_files.items():
            if sensitive_file in path:
                severity = 'High' if sensitive_file in ['.env', 'config.php', 'backup.sql'] else 'Medium'
                return {
                    'type': 'Sensitive File Exposure',
                    'severity': severity,
                    'path': path,
                    'url': path_result['url'],
                    'status_code': status_code,
                    'description': description,
                    'recommendation': f'Restreindre l\'accès au fichier {sensitive_file}'
                }
        
        # Répertoires d'administration
        admin_dirs = ['admin', 'administrator', 'management', 'manager']
        for admin_dir in admin_dirs:
            if admin_dir in path and status_code == 200:
                return {
                    'type': 'Administrative Interface Exposure',
                    'severity': 'High',
                    'path': path,
                    'url': path_result['url'],
                    'status_code': status_code,
                    'description': f'Interface d\'administration accessible: {path}',
                    'recommendation': 'Sécuriser l\'accès à l\'interface d\'administration'
                }
        
        # Répertoires de sauvegarde
        backup_indicators = ['backup', 'bak', 'old', 'tmp']
        for indicator in backup_indicators:
            if indicator in path and status_code == 200:
                return {
                    'type': 'Backup Directory Exposure',
                    'severity': 'Medium',
                    'path': path,
                    'url': path_result['url'],
                    'status_code': status_code,
                    'description': f'Répertoire de sauvegarde accessible: {path}',
                    'recommendation': 'Restreindre l\'accès aux répertoires de sauvegarde'
                }
        
        # Répertoires de développement
        dev_indicators = ['test', 'dev', 'debug']
        for indicator in dev_indicators:
            if indicator in path and status_code == 200:
                return {
                    'type': 'Development Directory Exposure',
                    'severity': 'Medium',
                    'path': path,
                    'url': path_result['url'],
                    'status_code': status_code,
                    'description': f'Répertoire de développement accessible: {path}',
                    'recommendation': 'Supprimer ou restreindre l\'accès aux répertoires de développement'
                }
        
        # Contrôle de version exposé
        vcs_indicators = ['.git', '.svn', '.hg']
        for vcs in vcs_indicators:
            if vcs in path:
                return {
                    'type': 'Version Control Exposure',
                    'severity': 'High',
                    'path': path,
                    'url': path_result['url'],
                    'status_code': status_code,
                    'description': f'Répertoire de contrôle de version exposé: {vcs}',
                    'recommendation': 'Bloquer l\'accès aux répertoires de contrôle de version'
                }
        
        # Erreurs 403 sur des répertoires sensibles (indique leur existence)
        if status_code == 403 and any(sensitive in path for sensitive in ['admin', 'private', 'secret']):
            return {
                'type': 'Sensitive Directory Existence',
                'severity': 'Low',
                'path': path,
                'url': path_result['url'],
                'status_code': status_code,
                'description': f'Répertoire sensible détecté (403): {path}',
                'recommendation': 'Vérifier la nécessité et la sécurisation du répertoire'
            }
        
        return None