#!/usr/bin/env python3
"""
CyberSec Web Testing Tool - Professional CLI Interface
Advanced security testing toolkit for authorized penetration testing

Author: snaken18
Version: 2.0
License: MIT (Educational Use Only)
"""

import os
import sys
import time
from typing import Dict
from pathlib import Path

# Ajouter le répertoire src au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import avec gestion d'erreurs
try:
    from utils.logger import setup_logger
    from utils.report_generator import ReportGenerator
    from utils.cyberpunk_style import (
        console, get_cyber_banner, print_cyber_success, print_cyber_error, 
        print_cyber_warning, print_cyber_info, create_cyber_progress,
        cyber_loading_effect, show_scan_summary, display_cyber_footer,
        create_cyber_panel, create_status_table, show_cyber_menu
    )
    from scanners.sql_injection import SQLInjectionScanner
    from scanners.xss_scanner import XSSScanner
    from scanners.header_security import HeaderSecurityScanner
    from scanners.port_scanner import PortScanner
    from scanners.directory_buster import DirectoryBuster
except ImportError as e:
    print(f"Erreur d'importation: {e}")
    print("Veuillez vérifier que tous les modules sont présents dans le répertoire src/")
    sys.exit(1)
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    REVERSE = '\033[7m'
    
    # Arrière-plan
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    # Reset
    RESET = '\033[0m'
    END = '\033[0m'

    @classmethod
    def disable(cls):
        """Désactive les couleurs pour les terminaux incompatibles"""
        for attr in dir(cls):
            if not attr.startswith('_') and attr not in ['disable', 'is_supported']:
                setattr(cls, attr, '')
    
    @classmethod
    def is_supported(cls):
        """Vérifie si le terminal supporte les couleurs"""
        return (
            hasattr(sys.stdout, 'isatty') and sys.stdout.isatty() and
            os.environ.get('TERM') != 'dumb' and
            sys.platform != 'win32' or os.environ.get('ANSICON') is not None
        )


class ProfessionalInterface:
    """Interface CLI professionnelle pour CyberSec Web Testing Tool"""
    
    def __init__(self):
        """Initialise l'interface professionnelle"""
        self.target_url = ""
        self.scan_config = {
            'threads': 10,
            'timeout': 10,
            'output_file': "",
            'verbose': False
        }
        self.selected_modules = []
        self.logger = None
        
        # Configuration des couleurs selon le terminal
        if not Colors.is_supported():
            Colors.disable()
        
        # Modules disponibles
        self.available_modules = {
            'sql': {
                'name': 'SQL Injection Scanner',
                'description': 'Detecte les vulnerabilites d\'injection SQL',
                'symbol': '[SQL]',
                'class': SQLInjectionScanner
            },
            'xss': {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'Detecte les failles XSS reflechies',
                'symbol': '[XSS]',
                'class': XSSScanner
            },
            'headers': {
                'name': 'Security Headers Analysis',
                'description': 'Verifie les en-tetes de securite HTTP',
                'symbol': '[HDR]',
                'class': HeaderSecurityScanner
            },
            'ports': {
                'name': 'Port Scanner',
                'description': 'Decouvre les ports ouverts et services',
                'symbol': '[PRT]',
                'class': PortScanner
            },
            'dirs': {
                'name': 'Directory Enumeration',
                'description': 'Enumere les fichiers et dossiers caches',
                'symbol': '[DIR]',
                'class': DirectoryBuster
            }
        }
    
    def clear_screen(self):
        """Efface l'écran de manière compatible"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        """Affiche la bannière principale"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
================================================================================
                    CYBERSEC WEB TESTING TOOL v2.0
                     Professional Security Scanner
                           
                            Created by snaken18
                     Advanced Penetration Testing Suite
================================================================================
{Colors.END}

{Colors.BRIGHT_RED}{Colors.BOLD}[!] LEGAL WARNING - AUTHORIZED TESTING ONLY [!]{Colors.END}
{Colors.RED}
This tool is designed EXCLUSIVELY for authorized security testing.
Unauthorized use may violate local, national, and international laws.
Users are solely responsible for compliance with applicable regulations.
{Colors.END}

{Colors.YELLOW}================================================================================{Colors.END}
"""
        print(banner)
    
    def print_status(self):
        """Affiche le statut actuel de la configuration"""
        print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}[*] CURRENT CONFIGURATION{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.END}")
        
        # URL cible
        url_status = f"{Colors.BRIGHT_GREEN}[OK]" if self.target_url else f"{Colors.BRIGHT_RED}[--]"
        url_display = self.target_url or "Not configured"
        print(f"{url_status}{Colors.END} Target URL: {Colors.YELLOW}{url_display}{Colors.END}")
        
        # Modules sélectionnés
        modules_status = f"{Colors.BRIGHT_GREEN}[OK]" if self.selected_modules else f"{Colors.BRIGHT_RED}[--]"
        modules_list = ", ".join(self.selected_modules) if self.selected_modules else "None selected"
        print(f"{modules_status}{Colors.END} Modules: {Colors.YELLOW}{modules_list}{Colors.END}")
        
        # Configuration
        print(f"{Colors.BLUE}[CFG]{Colors.END} Threads: {Colors.YELLOW}{self.scan_config['threads']}{Colors.END}")
        print(f"{Colors.BLUE}[CFG]{Colors.END} Timeout: {Colors.YELLOW}{self.scan_config['timeout']}s{Colors.END}")
        
        # Fichier de sortie
        output_status = f"{Colors.BRIGHT_GREEN}[OK]" if self.scan_config['output_file'] else f"{Colors.BLUE}[OPT]"
        output_file = self.scan_config['output_file'] or "Console output only"
        print(f"{output_status}{Colors.END} Report: {Colors.YELLOW}{output_file}{Colors.END}")
        
        print(f"{Colors.CYAN}{'=' * 50}{Colors.END}")
    
    def print_menu(self):
        """Affiche le menu principal"""
        print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}[*] MAIN MENU{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 30}{Colors.END}")
        print(f"{Colors.BRIGHT_GREEN}[1]{Colors.END} Configure Target URL")
        print(f"{Colors.BRIGHT_GREEN}[2]{Colors.END} Select Security Modules")
        print(f"{Colors.BRIGHT_GREEN}[3]{Colors.END} Advanced Settings")
        print(f"{Colors.BRIGHT_GREEN}[4]{Colors.END} Report Configuration")
        print(f"{Colors.BRIGHT_GREEN}[5]{Colors.END} Execute Security Scan")
        print(f"{Colors.BRIGHT_GREEN}[6]{Colors.END} Help & Information")
        print(f"{Colors.BRIGHT_RED}[0]{Colors.END} Exit Program")
        print(f"{Colors.CYAN}{'=' * 30}{Colors.END}")
    
    def main_menu(self):
        """Boucle principale du menu"""
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_status()
            self.print_menu()
            
            try:
                choice = input(f"\n{Colors.BRIGHT_CYAN}[?] Enter your choice: {Colors.END}").strip()
                
                if choice == '1':
                    self.configure_target()
                elif choice == '2':
                    self.select_modules()
                elif choice == '3':
                    self.configure_settings()
                elif choice == '4':
                    self.configure_output()
                elif choice == '5':
                    self.run_scan()
                elif choice == '6':
                    self.show_help()
                elif choice == '0':
                    if self.confirm_exit():
                        break
                else:
                    self.show_error("Invalid choice. Please select a valid option.")
            except KeyboardInterrupt:
                print(f"\n\n{Colors.YELLOW}[!] Interrupted by user. Exiting...{Colors.END}")
                break
            except (ValueError, TypeError, AttributeError) as e:
                self.show_error(f"Unexpected error: {str(e)}")
    
    def configure_target(self):
        """Configure l'URL cible"""
        self.clear_screen()
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}[*] TARGET CONFIGURATION{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 40}{Colors.END}")
        
        if self.target_url:
            print(f"\n{Colors.BLUE}[INFO]{Colors.END} Current target: {Colors.YELLOW}{self.target_url}{Colors.END}")
        
        print(f"\n{Colors.YELLOW}[EXAMPLES]{Colors.END}")
        print("  https://example.com")
        print("  http://testsite.local")
        print("  https://app.company.com:8080")
        
        while True:
            url = input(f"\n{Colors.BRIGHT_CYAN}[?] Enter target URL (or 'back' to return): {Colors.END}").strip()
            
            if url.lower() == 'back':
                return
            
            if not url:
                continue
            
            # Ajouter http:// si pas de protocole
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Validation basique
            if self.validate_url(url):
                # Confirmation d'autorisation
                if self.confirm_authorization(url):
                    self.target_url = url
                    self.show_success(f"Target configured: {url}")
                    break
            else:
                self.show_error("Invalid URL format. Please check and try again.")
    
    def validate_url(self, url: str) -> bool:
        """Valide une URL"""
        try:
            from urllib.parse import urlparse
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except (ValueError, TypeError):
            return False
    
    def confirm_authorization(self, url: str) -> bool:
        """Demande confirmation d'autorisation"""
        print(f"\n{Colors.BG_RED}{Colors.BRIGHT_WHITE}{Colors.BOLD} LEGAL AUTHORIZATION REQUIRED {Colors.END}")
        print(f"\n{Colors.BRIGHT_YELLOW}Target to configure: {Colors.BRIGHT_WHITE}{url}{Colors.END}")
        print(f"\n{Colors.BRIGHT_RED}{Colors.BOLD}CRITICAL VERIFICATION:{Colors.END}")
        print("  1. Do you have written authorization from the system owner?")
        print("  2. Are you the legitimate owner of this system?")
        print("  3. Do you understand the legal implications?")
        
        while True:
            confirm = input(f"\n{Colors.BRIGHT_CYAN}[?] Confirm authorization (yes/no): {Colors.END}").strip().lower()
            if confirm in ['yes', 'y', 'oui', 'o']:
                return True
            elif confirm in ['no', 'n', 'non']:
                self.show_error("Authorization required to proceed.")
                return False
            else:
                print(f"{Colors.RED}[!] Please answer 'yes' or 'no'{Colors.END}")
    
    def select_modules(self):
        """Sélection des modules de scan"""
        while True:
            self.clear_screen()
            print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}[*] MODULE SELECTION{Colors.END}")
            print(f"{Colors.CYAN}{'=' * 40}{Colors.END}")
            
            print(f"\n{Colors.YELLOW}[AVAILABLE MODULES]{Colors.END}")
            
            for i, (key, module) in enumerate(self.available_modules.items(), 1):
                status = f"{Colors.BRIGHT_GREEN}[ON]" if key in self.selected_modules else f"{Colors.RED}[OFF]"
                symbol = module['symbol']
                print(f"{status}{Colors.END} {Colors.BRIGHT_GREEN}[{i}]{Colors.END} {symbol} {module['name']}")
                print(f"      {Colors.WHITE}{module['description']}{Colors.END}")
            
            print(f"\n{Colors.CYAN}[OPTIONS]{Colors.END}")
            print(f"{Colors.BRIGHT_GREEN}[A]{Colors.END} Select All Modules")
            print(f"{Colors.BRIGHT_YELLOW}[C]{Colors.END} Clear Selection")
            print(f"{Colors.BRIGHT_BLUE}[B]{Colors.END} Back to Main Menu")
            
            choice = input(f"\n{Colors.BRIGHT_CYAN}[?] Your choice (number, A, C, B): {Colors.END}").strip().lower()
            
            if choice == 'b':
                break
            elif choice == 'a':
                self.selected_modules = list(self.available_modules.keys())
                self.show_success("All modules selected!")
            elif choice == 'c':
                self.selected_modules = []
                self.show_success("Selection cleared!")
            else:
                try:
                    module_num = int(choice)
                    if 1 <= module_num <= len(self.available_modules):
                        module_key = list(self.available_modules.keys())[module_num - 1]
                        if module_key in self.selected_modules:
                            self.selected_modules.remove(module_key)
                            module_name = self.available_modules[module_key]['name']
                            self.show_success(f"Module {module_name} deselected")
                        else:
                            self.selected_modules.append(module_key)
                            module_name = self.available_modules[module_key]['name']
                            self.show_success(f"Module {module_name} selected")
                    else:
                        self.show_error("Invalid module number")
                except ValueError:
                    self.show_error("Invalid choice")
    
    def configure_settings(self):
        """Configuration des paramètres avancés"""
        while True:
            self.clear_screen()
            print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}[*] ADVANCED SETTINGS{Colors.END}")
            print(f"{Colors.CYAN}{'=' * 40}{Colors.END}")
            
            print(f"\n{Colors.YELLOW}[CURRENT SETTINGS]{Colors.END}")
            print(f"[1] Threads: {Colors.BRIGHT_GREEN}{self.scan_config['threads']}{Colors.END}")
            print(f"[2] Timeout: {Colors.BRIGHT_GREEN}{self.scan_config['timeout']}s{Colors.END}")
            verbose_status = "Enabled" if self.scan_config['verbose'] else "Disabled"
            print(f"[3] Verbose Mode: {Colors.BRIGHT_GREEN}{verbose_status}{Colors.END}")
            
            print(f"\n{Colors.CYAN}[MODIFY SETTINGS]{Colors.END}")
            print(f"{Colors.BRIGHT_GREEN}[1]{Colors.END} Thread Count")
            print(f"{Colors.BRIGHT_GREEN}[2]{Colors.END} Request Timeout")
            print(f"{Colors.BRIGHT_GREEN}[3]{Colors.END} Verbose Mode")
            print(f"{Colors.BRIGHT_BLUE}[B]{Colors.END} Back to Main Menu")
            
            choice = input(f"\n{Colors.BRIGHT_CYAN}[?] Your choice: {Colors.END}").strip().lower()
            
            if choice == 'b':
                break
            elif choice == '1':
                self.configure_threads()
            elif choice == '2':
                self.configure_timeout()
            elif choice == '3':
                self.scan_config['verbose'] = not self.scan_config['verbose']
                status = "enabled" if self.scan_config['verbose'] else "disabled"
                self.show_success(f"Verbose mode {status}")
            else:
                self.show_error("Invalid choice")
    
    def configure_threads(self):
        """Configure le nombre de threads"""
        print(f"\n{Colors.YELLOW}[THREAD CONFIGURATION]{Colors.END}")
        print("  Recommended: 10-20 for most websites")
        print("  Higher = faster but more detectable")
        print("  Lower = more stealthy but slower")
        
        while True:
            try:
                threads_input = input(f"\n{Colors.BRIGHT_CYAN}[?] Number of threads (1-50, current: {self.scan_config['threads']}): {Colors.END}").strip()
                if not threads_input:
                    return
                
                threads = int(threads_input)
                if 1 <= threads <= 50:
                    self.scan_config['threads'] = threads
                    self.show_success(f"Threads configured: {threads}")
                    break
                else:
                    self.show_error("Thread count must be between 1 and 50")
            except ValueError:
                self.show_error("Please enter a valid number")
    
    def configure_timeout(self):
        """Configure le timeout"""
        print(f"\n{Colors.YELLOW}[TIMEOUT CONFIGURATION]{Colors.END}")
        print("  Recommended: 10-30 seconds")
        print("  Longer = better chance to detect slow services")
        print("  Shorter = faster scan completion")
        
        while True:
            try:
                timeout_input = input(f"\n{Colors.BRIGHT_CYAN}[?] Timeout in seconds (1-120, current: {self.scan_config['timeout']}): {Colors.END}").strip()
                if not timeout_input:
                    return
                
                timeout = int(timeout_input)
                if 1 <= timeout <= 120:
                    self.scan_config['timeout'] = timeout
                    self.show_success(f"Timeout configured: {timeout}s")
                    break
                else:
                    self.show_error("Timeout must be between 1 and 120 seconds")
            except ValueError:
                self.show_error("Please enter a valid number")
    
    def configure_output(self):
        """Configuration du fichier de sortie"""
        self.clear_screen()
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}[*] REPORT CONFIGURATION{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 40}{Colors.END}")
        
        if self.scan_config['output_file']:
            print(f"\n{Colors.BLUE}[INFO]{Colors.END} Current file: {Colors.YELLOW}{self.scan_config['output_file']}{Colors.END}")
        
        print(f"\n{Colors.YELLOW}[SUPPORTED FORMATS]{Colors.END}")
        print("  .html - Complete HTML report with charts")
        print("  .json - Structured data for processing")
        print("  Leave empty for console output only")
        
        while True:
            filename = input(f"\n{Colors.BRIGHT_CYAN}[?] Report filename (or 'back'): {Colors.END}").strip()
            
            if filename.lower() == 'back':
                break
            elif not filename:
                self.scan_config['output_file'] = ""
                self.show_success("Output configured: Console only")
                break
            else:
                # Ajouter extension si manquante
                if not filename.endswith(('.html', '.json')):
                    print(f"\n{Colors.YELLOW}[AVAILABLE EXTENSIONS]{Colors.END}")
                    print("[1] .html (recommended)")
                    print("[2] .json")
                    
                    ext_choice = input(f"{Colors.BRIGHT_CYAN}[?] Choose extension (1/2): {Colors.END}").strip()
                    if ext_choice == '1':
                        filename += '.html'
                    elif ext_choice == '2':
                        filename += '.json'
                    else:
                        filename += '.html'  # Par défaut
                
                # Vérifier le répertoire
                reports_dir = Path("reports")
                reports_dir.mkdir(exist_ok=True)
                
                full_path = reports_dir / filename
                self.scan_config['output_file'] = str(full_path)
                self.show_success(f"Report configured: {full_path}")
                break
    
    def run_scan(self):
        """Lance le scan de sécurité"""
        # Vérifications préalables
        if not self.target_url:
            self.show_error("Please configure a target URL first")
            return
        
        if not self.selected_modules:
            self.show_error("Please select at least one security module")
            return
        
        # Confirmation finale
        self.clear_screen()
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}[*] SECURITY SCAN EXECUTION{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 40}{Colors.END}")
        
        print(f"\n{Colors.YELLOW}[SCAN SUMMARY]{Colors.END}")
        print(f"  Target: {Colors.BRIGHT_GREEN}{self.target_url}{Colors.END}")
        print(f"  Modules: {Colors.BRIGHT_GREEN}{', '.join(self.selected_modules)}{Colors.END}")
        print(f"  Threads: {Colors.BRIGHT_GREEN}{self.scan_config['threads']}{Colors.END}")
        print(f"  Timeout: {Colors.BRIGHT_GREEN}{self.scan_config['timeout']}s{Colors.END}")
        
        confirm = input(f"\n{Colors.BRIGHT_CYAN}[?] Confirm scan execution? (yes/no): {Colors.END}").strip().lower()
        if confirm not in ['yes', 'y', 'oui', 'o']:
            return
        
        # Initialisation du logger
        self.logger = setup_logger(self.scan_config['verbose'])
        
        # Lancement du scan
        print(f"\n{Colors.BRIGHT_GREEN}{Colors.BOLD}[*] SECURITY SCAN IN PROGRESS{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 50}{Colors.END}")
        
        try:
            scan_results = {}
            
            # Exécution des modules sélectionnés
            for module_key in self.selected_modules:
                module_info = self.available_modules[module_key]
                print(f"\n{Colors.BRIGHT_CYAN}[SCANNING]{Colors.END} {module_info['symbol']} {module_info['name']}")
                
                # Initialisation du scanner
                scanner_class = module_info['class']
                scanner = scanner_class(
                    self.target_url,
                    threads=self.scan_config['threads'],
                    timeout=self.scan_config['timeout']
                )
                
                # Configuration spéciale pour le port scanner
                if module_key == 'ports':
                    scanner.set_ports("21,22,23,25,53,80,110,143,443,993,995,3389,8080,8443")
                
                # Exécution du scan
                results = scanner.scan()
                scan_results[module_key] = results
                
                # Affichage des résultats sommaires
                if 'vulnerabilities' in results:
                    vuln_count = len(results['vulnerabilities'])
                    if vuln_count > 0:
                        print(f"  {Colors.BRIGHT_RED}[ALERT]{Colors.END} {vuln_count} vulnerability(ies) detected")
                    else:
                        print(f"  {Colors.BRIGHT_GREEN}[CLEAN]{Colors.END} No vulnerabilities found")
            
            # Génération du rapport
            if self.scan_config['output_file']:
                print(f"\n{Colors.BRIGHT_CYAN}[GENERATING]{Colors.END} Security report...")
                report_gen = ReportGenerator()
                report_path = report_gen.generate_report(
                    scan_results,
                    self.target_url,
                    self.scan_config['output_file']
                )
                print(f"{Colors.BRIGHT_GREEN}[SUCCESS]{Colors.END} Report generated: {report_path}")
            
            # Résumé final
            self.show_scan_summary(scan_results)
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        except (ImportError, AttributeError, ValueError) as e:
            print(f"\n{Colors.BRIGHT_RED}[ERROR]{Colors.END} Scan failed: {str(e)}")
        
        input(f"\n{Colors.BRIGHT_CYAN}[?] Press Enter to continue...{Colors.END}")
    
    def show_scan_summary(self, scan_results: Dict):
        """Affiche le résumé du scan"""
        total_vulns = 0
        vulns_by_severity = {'High': 0, 'Medium': 0, 'Low': 0}
        
        for results in scan_results.values():
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    total_vulns += 1
                    severity = vuln.get('severity', 'Low')
                    if severity in vulns_by_severity:
                        vulns_by_severity[severity] += 1
        
        print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}[*] SCAN SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 30}{Colors.END}")
        print(f"  Total Vulnerabilities: {Colors.YELLOW}{total_vulns}{Colors.END}")
        print(f"  Critical/High: {Colors.BRIGHT_RED}{vulns_by_severity['High']}{Colors.END}")
        print(f"  Medium: {Colors.YELLOW}{vulns_by_severity['Medium']}{Colors.END}")
        print(f"  Low/Info: {Colors.BLUE}{vulns_by_severity['Low']}{Colors.END}")
        print(f"\n{Colors.BRIGHT_WHITE}Scan completed by snaken18 CyberSec Tool{Colors.END}")
    
    def show_help(self):
        """Affiche l'aide et les informations"""
        self.clear_screen()
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}[*] HELP & INFORMATION{Colors.END}")
        print(f"{Colors.CYAN}{'=' * 40}{Colors.END}")
        
        print(f"\n{Colors.YELLOW}[MODULE DESCRIPTIONS]{Colors.END}")
        for module in self.available_modules.values():
            print(f"\n{Colors.BRIGHT_GREEN}{module['symbol']}{Colors.END} {Colors.BOLD}{module['name']}{Colors.END}")
            print(f"  {module['description']}")
        
        print(f"\n{Colors.YELLOW}[USAGE RECOMMENDATIONS]{Colors.END}")
        print("  1. Start with header analysis (fast and non-intrusive)")
        print("  2. Use fewer threads for stealth scanning")
        print("  3. Increase timeout for slow target systems")
        print("  4. Always generate reports for documentation")
        print("  5. Respect rate limits and target resources")
        
        print(f"\n{Colors.YELLOW}[LEGAL CONSIDERATIONS]{Colors.END}")
        print("  • Only use on systems you own or have written authorization")
        print("  • Obtain explicit permission before any security testing")
        print("  • Comply with local and international cybersecurity laws")
        print("  • Use results responsibly for defensive purposes only")
        print("  • Follow responsible disclosure practices")
        
        print(f"\n{Colors.YELLOW}[TECHNICAL SUPPORT]{Colors.END}")
        print("  • Check logs for detailed error information")
        print("  • Consult README.md for complete documentation")
        print("  • Verify network connectivity and target accessibility")
        print("  • Report bugs through appropriate channels")
        
        print(f"\n{Colors.BRIGHT_WHITE}CyberSec Web Testing Tool v2.0 - Created by snaken18{Colors.END}")
        print(f"{Colors.DIM}Professional security testing for authorized environments{Colors.END}")
        
        input(f"\n{Colors.BRIGHT_CYAN}[?] Press Enter to continue...{Colors.END}")
    
    def show_success(self, message: str):
        """Affiche un message de succès"""
        print(f"{Colors.BRIGHT_GREEN}[SUCCESS]{Colors.END} {message}")
        time.sleep(1)
    
    def show_error(self, message: str):
        """Affiche un message d'erreur"""
        print(f"{Colors.BRIGHT_RED}[ERROR]{Colors.END} {message}")
        time.sleep(2)
    
    def confirm_exit(self):
        """Demande confirmation avant de quitter"""
        print(f"\n{Colors.YELLOW}[?] Are you sure you want to exit?{Colors.END}")
        confirm = input(f"{Colors.BRIGHT_CYAN}[?] (yes/no): {Colors.END}").strip().lower()
        if confirm not in ['yes', 'y', 'oui', 'o']:
            return False
        
        print(f"\n{Colors.BRIGHT_CYAN}Thank you for using CyberSec Web Testing Tool!{Colors.END}")
        print(f"{Colors.BRIGHT_WHITE}Created by snaken18 - Use your knowledge ethically! {Colors.END}")
        return True


def main():
    """Point d'entrée principal du menu CLI professionnel"""
    try:
        interface = ProfessionalInterface()
        interface.main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Program interrupted by user.{Colors.END}")
    except (ImportError, AttributeError) as e:
        print(f"\n{Colors.BRIGHT_RED}[FATAL ERROR]{Colors.END} {str(e)}")


if __name__ == '__main__':
    main()