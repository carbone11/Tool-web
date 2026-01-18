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

# Ajouter le répertoire src au path pour exécution directe (préserve aussi les imports package)
SRC_PATH = os.path.join(os.path.dirname(__file__), 'src')
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

try:
    from src.utils.logger import setup_logger
    from src.utils.report_generator import ReportGenerator
    from src.utils.cyberpunk_style import (
        console, get_cyber_banner, print_cyber_success, print_cyber_error, 
        print_cyber_warning, print_cyber_info, create_cyber_progress,
        cyber_loading_effect, show_scan_summary, display_cyber_footer,
        create_cyber_panel, create_status_table
    )
    from src.scanners.sql_injection import SQLInjectionScanner
    from src.scanners.xss_scanner import XSSScanner
    from src.scanners.header_security import HeaderSecurityScanner
    from src.scanners.port_scanner import PortScanner
    from src.scanners.directory_buster import DirectoryBuster
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
def main(
    url: str = "",
    modules: str = "basic",
    output: Optional[str] = None,
    verbose: bool = False,
    threads: int = 10,
    timeout: int = 10,
    ports: str = "80,443,8080,8443",
):
    """
    CyberSec Web Testing Tool - Scanner de sécurité web éthique
    
    Exemples d'utilisation:
    python main.py -u https://example.com
    python main.py -u https://example.com -m sql,xss -o rapport.html
    python main.py -u https://example.com -m all --threads 20
    """
    
    # Vérification minimale si exécuté sans Click (appel direct sans args)
    if url == "":
        print_cyber_error("URL manquante. Utilisez -u/--url pour spécifier la cible.")
        return

    # Affichage de la bannière cyberpunk
    console.print(get_cyber_banner())
    
    # Configuration du logger
    setup_logger(verbose)
    
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
            
            for module_name in selected_modules:
                progress.update(main_task, description=f"Module: {module_name.upper()}")
                print_cyber_info(f"Lancement du module: {module_name}")
                
                # Initialisation du scanner avec paramètres adaptés
                scanner_class = available_modules[module_name]
                
                if module_name == 'headers':
                    scanner = scanner_class(url, timeout=timeout)
                else:
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
    
    # Footer cyberpunk - n'afficher qu'une seule fois
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
    
    # Demande de confirmation avec style cyberpunk
    console.print()
    response = console.input("[bold #00ffff]Confirmez-vous avoir l'autorisation de tester cette cible? [/]([bold #00ff41]oui[/]/[bold #ff0040]non[/]): ")
    if response.lower() not in ['oui', 'o', 'yes', 'y']:
        print_cyber_error("Test annulé - Autorisation requise")
        sys.exit(1)
    
    print_cyber_success("Autorisation confirmée - Démarrage du scan...")


if __name__ == '__main__':
    # Laisser Click gérer les options en ligne de commande
    main()