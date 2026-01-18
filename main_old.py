#!/usr/bin/env python3
"""
CyberSec Web Testing Tool - Point d'entrée principal
Outil de test de sécurité web pour les tests de pénétration éthiques

AVERTISSEMENT: Cet outil est destiné uniquement aux tests autorisés
"""

import click
import sys
import os
from typing import Optional
import time

# Ajouter le répertoire src au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from utils.logger import setup_logger
    from utils.report_generator import ReportGenerator
    from utils.cyberpunk_style import (
        console, get_cyber_banner, print_cyber_success, print_cyber_error, 
        print_cyber_warning, print_cyber_info, create_cyber_progress,
        cyber_loading_effect, show_scan_summary, display_cyber_footer,
        create_cyber_panel, create_status_table
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


@click.command()
@click.option('-u', '--url', required=True, help='URL cible à scanner')
@click.option('-m', '--modules', default='basic', 
              help='Modules à utiliser: all, basic, sql, xss, headers, ports, dirs (séparés par des virgules)')
@click.option('-o', '--output', help='Fichier de sortie pour le rapport')
@click.option('-v', '--verbose', is_flag=True, help='Mode verbeux')
@click.option('--threads', default=10, help='Nombre de threads (défaut: 10)')
@click.option('--timeout', default=10, help='Timeout des requêtes en secondes (défaut: 10)')
@click.option('--ports', default='80,443,8080,8443', help='Ports à scanner (ex: 80,443 ou 1-1000)')
def main(url: str, modules: str, output: Optional[str], verbose: bool, 
         threads: int, timeout: int, ports: str):
    """
    CyberSec Web Testing Tool - Scanner de sécurité web éthique
    
    Exemples d'utilisation:
    python main.py -u https://example.com
    python main.py -u https://example.com -m sql,xss -o rapport.html
    python main.py -u https://example.com -m all --threads 20
    """
    
    # Affichage de la bannière cyberpunk
    console.print(get_cyber_banner())
    
    # Configuration du logger
    logger = setup_logger(verbose)
    
    # Affichage de l'avertissement légal avec style cyberpunk
    display_legal_warning()
    
    # Validation de l'URL
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print_cyber_info(f"Initialisation du scan pour: {url}")
    print_cyber_info(f"Modules sélectionnés: {modules}")
    
    # Effet de chargement initial
    cyber_loading_effect("Initialisation des systèmes de scan...", 1.5)
    
    # Configuration des modules
    available_modules = {
        'sql': SQLInjectionScanner,
        'xss': XSSScanner,
        'headers': HeaderSecurityScanner,
        'ports': PortScanner,
        'dirs': DirectoryBuster
    }
    
    # Détermination des modules à exécuter
    if modules == 'all':
        selected_modules = list(available_modules.keys())
    elif modules == 'basic':
        selected_modules = ['headers', 'sql', 'xss']
    else:
        selected_modules = [m.strip() for m in modules.split(',')]
    
    # Validation des modules
    invalid_modules = [m for m in selected_modules if m not in available_modules]
    if invalid_modules:
        print_cyber_error(f"Modules invalides: {invalid_modules}")
        print_cyber_info(f"Modules disponibles: {list(available_modules.keys())}")
        sys.exit(1)
    
    # Affichage des paramètres de scan
    scan_params = {
        "URL Cible": url,
        "Modules": ", ".join(selected_modules),
        "Threads": threads,
        "Timeout": f"{timeout}s",
        "Mode Verbose": verbose
    }
    
    param_table = create_status_table(scan_params)
    console.print(create_cyber_panel(param_table, "PARAMÈTRES DE SCAN", "#ff0080"))
    
    # Initialisation du générateur de rapports
    report_gen = ReportGenerator()
    scan_results = {}
    
    try:
        # Exécution des scans avec barre de progression
        with create_cyber_progress() as progress:
            main_task = progress.add_task("Scan de sécurité en cours...", total=len(selected_modules))
            
            for i, module_name in enumerate(selected_modules):
                progress.update(main_task, description=f"Module: {module_name.upper()}")
                print_cyber_info(f"Lancement du module: {module_name}")
                
                scanner_class = available_modules[module_name]
                scanner = scanner_class(url, threads=threads, timeout=timeout)
                
                # Configuration spécifique pour le scanner de ports
                if module_name == 'ports':
                    scanner.set_ports(ports)
                
                # Exécution du scan
                results = scanner.scan()
                scan_results[module_name] = results
                
                # Affichage des résultats du module
                vuln_count = len(results.get('vulnerabilities', []))
                if vuln_count > 0:
                    print_cyber_warning(f"Module {module_name}: {vuln_count} vulnérabilité(s) détectée(s)")
                else:
                    print_cyber_success(f"Module {module_name}: Aucune vulnérabilité détectée")
                
                progress.advance(main_task)
                time.sleep(0.2)  # Petit délai pour l'effet visuel
        
        print_cyber_success("Scan terminé avec succès!")
        
        # Affichage du résumé des résultats
        show_scan_summary(scan_results, url)
    
    except KeyboardInterrupt:
        print_cyber_warning("Scan interrompu par l'utilisateur")
        sys.exit(1)
    except (ImportError, AttributeError, ValueError) as e:
        print_cyber_error(f"Erreur lors du scan: {str(e)}")
        sys.exit(1)
    
    # Génération du rapport avec style cyberpunk
    if output:
        try:
            cyber_loading_effect("Génération du rapport...", 1.0)
            report_path = report_gen.generate_report(scan_results, url, output)
            print_cyber_success(f"Rapport généré: {report_path}")
        except (IOError, PermissionError, ValueError) as e:
            print_cyber_error(f"Erreur lors de la génération du rapport: {str(e)}")
    
    # Footer cyberpunk
    display_cyber_footer()


def display_legal_warning():
    """Affiche l'avertissement légal avec style cyberpunk"""
    warning_content = """[bold #ff0040]⚠️  AVERTISSEMENT LÉGAL  ⚠️[/]

[#ffff00]Cet outil est destiné UNIQUEMENT aux tests de sécurité autorisés.
L'utilisation sur des systèmes sans autorisation explicite est ILLÉGALE.[/]

[bold #00ffff]En utilisant cet outil, vous acceptez:[/]
[#00ff41]• D'avoir l'autorisation écrite du propriétaire du système[/]
[#00ff41]• D'utiliser cet outil de manière éthique et responsable[/]
[#00ff41]• De respecter toutes les lois locales et internationales[/]

[bold #ff0080]USAGE RESPONSABLE UNIQUEMENT![/]"""
    
    warning_panel = create_cyber_panel(warning_content, "AVERTISSEMENT ÉTHIQUE", "#ff0040")
    console.print(warning_panel)
    
    # Pause pour laisser lire l'avertissement
    time.sleep(2)
    - D'assumer l'entière responsabilité de vos actions
    
    Les auteurs ne sont pas responsables de l'utilisation malveillante.
    """
    
    print(warning)
    
    response = input("Confirmez-vous avoir l'autorisation de tester cette cible? (oui/non): ")
    if response.lower() not in ['oui', 'o', 'yes', 'y']:
        print("❌ Test annulé - Autorisation requise")
        sys.exit(1)


def display_module_results(module_name: str, results: dict, logger):
    """Affiche les résultats d'un module"""
    logger.info(f"📊 Résultats du module {module_name}:")
    
    if 'vulnerabilities' in results:
        vuln_count = len(results['vulnerabilities'])
        if vuln_count > 0:
            logger.warning(f"🚨 {vuln_count} vulnérabilité(s) détectée(s)")
            for vuln in results['vulnerabilities'][:3]:  # Afficher les 3 premières
                logger.warning(f"  - {vuln.get('type', 'Inconnu')}: {vuln.get('description', 'N/A')}")
            if vuln_count > 3:
                logger.info(f"  ... et {vuln_count - 3} autre(s)")
        else:
            logger.info("✅ Aucune vulnérabilité détectée")
    
    if 'summary' in results:
        for key, value in results['summary'].items():
            logger.info(f"  {key}: {value}")


if __name__ == '__main__':
    main()