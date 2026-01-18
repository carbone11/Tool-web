"""
Scanner de ports
Découvre les ports ouverts et services exposés
"""

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional
import logging
import time

class PortScanner:
    """Scanner de ports pour découvrir les services ouverts"""
    
    def __init__(self, base_url: str, threads: int = 50, timeout: int = 3):
        """
        Initialise le scanner de ports
        
        Args:
            base_url: URL de base contenant l'hôte à scanner
            threads: Nombre de threads pour le scan parallèle
            timeout: Timeout pour chaque connexion
        """
        self.base_url = base_url
        self.threads = threads
        self.timeout = timeout
        self.logger = logging.getLogger('cybersec_tool.port_scanner')
        
        # Extraction de l'hôte depuis l'URL
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        self.target_host = parsed.hostname or parsed.netloc or base_url
        
        # Ports par défaut à scanner
        self.default_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
            1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200
        ]
        
        # Services connus par port
        self.known_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            9200: 'Elasticsearch'
        }
        
        self.ports_to_scan = self.default_ports[:]
    
    def set_ports(self, ports_spec: str):
        """
        Configure les ports à scanner
        
        Args:
            ports_spec: Spécification des ports (ex: "80,443" ou "1-1000")
        """
        try:
            if '-' in ports_spec:
                # Plage de ports
                start, end = map(int, ports_spec.split('-'))
                self.ports_to_scan = list(range(start, end + 1))
            elif ',' in ports_spec:
                # Liste de ports
                self.ports_to_scan = [int(p.strip()) for p in ports_spec.split(',')]
            else:
                # Port unique
                self.ports_to_scan = [int(ports_spec)]
        except ValueError:
            self.logger.warning("Format de ports invalide: %s, utilisation des ports par défaut", ports_spec)
    
    def scan(self) -> Dict:
        """
        Lance le scan de ports
        
        Returns:
            Dictionnaire avec les résultats du scan
        """
        self.logger.info("🔍 Début du scan de ports sur %s", self.target_host)
        
        results = {
            'vulnerabilities': [],
            'summary': {
                'total_ports_scanned': len(self.ports_to_scan),
                'open_ports': 0,
                'closed_ports': 0,
                'filtered_ports': 0
            },
            'open_ports': []
        }
        
        if not self.target_host:
            self.logger.error("❌ Impossible d'extraire l'hôte de l'URL")
            return results
        
        # Test de connectivité de base
        if not self._test_host_reachable():
            self.logger.error("❌ Hôte %s injoignable", self.target_host)
            return results
        
        start_time = time.time()
        
        # Scan des ports en parallèle
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for port in self.ports_to_scan:
                future = executor.submit(self._scan_port, port)
                futures.append((future, port))
            
            # Collecte des résultats
            for future, port in futures:
                try:
                    port_result = future.result(timeout=self.timeout + 1)
                    if port_result['status'] == 'open':
                        results['open_ports'].append(port_result)
                        results['summary']['open_ports'] += 1
                        
                        # Vérifier si c'est un service potentiellement vulnérable
                        vuln = self._check_service_vulnerability(port_result)
                        if vuln:
                            results['vulnerabilities'].append(vuln)
                    
                    elif port_result['status'] == 'closed':
                        results['summary']['closed_ports'] += 1
                    else:
                        results['summary']['filtered_ports'] += 1
                        
                except (OSError, socket.error, ConnectionError) as e:
                    self.logger.debug("Erreur scan port %s: %s", port, str(e))
                    results['summary']['filtered_ports'] += 1
        
        scan_duration = time.time() - start_time
        self.logger.info("✅ Scan de ports terminé en %.2fs - %s ports ouverts", scan_duration, results['summary']['open_ports'])
        
        return results
    
    def _test_host_reachable(self) -> bool:
        """
        Teste si l'hôte est joignable
        
        Returns:
            True si l'hôte répond
        """
        try:
            if self.target_host:
                socket.gethostbyname(self.target_host)
                return True
            return False
        except socket.gaierror:
            return False
    
    def _scan_port(self, port: int) -> Dict:
        """
        Scanne un port spécifique
        
        Args:
            port: Numéro du port à scanner
            
        Returns:
            Dictionnaire avec le résultat du scan
        """
        result = {
            'port': port,
            'status': 'closed',
            'service': self.known_services.get(port, 'Unknown'),
            'banner': '',
            'response_time': 0
        }
        
        start_time = time.time()
        
        try:
            # Création de la socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Tentative de connexion
            connection_result = sock.connect_ex((self.target_host, port))
            
            if connection_result == 0:
                result['status'] = 'open'
                result['response_time'] = (time.time() - start_time) * 1000
                
                # Tentative de récupération de banner
                try:
                    sock.send(b'\\r\\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    result['banner'] = banner[:200]  # Limiter la taille
                except (socket.error, UnicodeDecodeError):
                    pass
                
                self.logger.info("✅ Port ouvert: %s (%s)", port, result['service'])
            
            sock.close()
            
        except socket.timeout:
            result['status'] = 'filtered'
        except (socket.error, OSError):
            result['status'] = 'closed'
        
        return result
    
    def _check_service_vulnerability(self, port_result: Dict) -> Optional[Dict]:
        """
        Vérifie si un service ouvert présente des vulnérabilités connues
        
        Args:
            port_result: Résultat du scan de port
            
        Returns:
            Dictionnaire de vulnérabilité ou None
        """
        port = port_result['port']
        service = port_result['service']
        banner = port_result['banner'].lower()
        
        # Services potentiellement dangereux
        dangerous_services = {
            21: 'FTP - Service de transfert de fichiers souvent mal configuré',
            23: 'Telnet - Protocole non chiffré, préférer SSH',
            53: 'DNS - Peut être utilisé pour des attaques par amplification',
            3389: 'RDP - Service de bureau à distance, cible d\'attaques',
            5900: 'VNC - Service de bureau à distance souvent mal sécurisé'
        }
        
        if port in dangerous_services:
            return {
                'type': 'Potentially Dangerous Service',
                'severity': 'Medium',
                'port': port,
                'service': service,
                'description': dangerous_services[port],
                'recommendation': f'Vérifier la configuration et la nécessité du service {service} sur le port {port}'
            }
        
        # Vérification de versions obsolètes dans les banners
        if banner:
            obsolete_indicators = [
                ('ssh-1.', 'SSH version 1 obsolète et vulnérable'),
                ('microsoft-iis/6.', 'IIS 6.0 obsolète avec vulnérabilités connues'),
                ('apache/1.', 'Apache 1.x obsolète'),
                ('apache/2.0', 'Apache 2.0 obsolète'),
                ('nginx/0.', 'Nginx 0.x obsolète'),
                ('openssl/0.', 'OpenSSL 0.x avec vulnérabilités critiques')
            ]
            
            for indicator, description in obsolete_indicators:
                if indicator in banner:
                    return {
                        'type': 'Obsolete Service Version',
                        'severity': 'High',
                        'port': port,
                        'service': service,
                        'banner': banner[:100],
                        'description': description,
                        'recommendation': f'Mettre à jour le service {service} vers une version récente'
                    }
        
        # Services avec authentification par défaut
        default_auth_services = {
            3306: 'MySQL - Vérifier les comptes par défaut',
            5432: 'PostgreSQL - Vérifier les comptes par défaut',
            6379: 'Redis - Souvent sans authentification par défaut',
            9200: 'Elasticsearch - Souvent sans authentification'
        }
        
        if port in default_auth_services:
            return {
                'type': 'Service with Potential Default Authentication',
                'severity': 'Medium',
                'port': port,
                'service': service,
                'description': default_auth_services[port],
                'recommendation': f'Vérifier et sécuriser l\'authentification du service {service}'
            }
        
        return None