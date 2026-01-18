#!/usr/bin/env python3
"""
Cybersecurity Web Testing Tool - CLI (Cyberpunk Style)
Usage éthique uniquement • Rapports • Rejeu
"""

import sys
import time
import os
import glob
import json
import webbrowser
from pathlib import Path
import re
import requests
from typing import Dict, Optional, Tuple, List

try:
    from src.utils.logger import setup_logger
    from src.utils.report_generator import ReportGenerator
    from src.utils.cyberpunk_style import (
        console, print_cyber_success, print_cyber_error,
        print_cyber_warning, print_cyber_info, create_cyber_progress,
        show_scan_summary, display_cyber_footer,
        create_cyber_panel, clear_screen,
    )
    from src.scanners.sql_injection import SQLInjectionScanner
    from src.scanners.xss_scanner import XSSScanner
    from src.scanners.header_security import HeaderSecurityScanner
    from src.scanners.port_scanner import PortScanner
    from src.scanners.directory_buster import DirectoryBuster
    from src.scanners.redirect_traversal import RedirectTraversalScanner
    from src.scanners.ssrf import SSRFScanner
    from src.scanners.crlf_injection import CRLFInjectionScanner
    from src.scanners.command_injection import CommandInjectionScanner
    from src.scanners.nosql_injection import NoSQLInjectionScanner
    from src.scanners.xxe import XXEScanner
    from src.scanners.ssti import SSTIScanner
    from src.scanners.ldap_xpath_injection import LDAPXPathInjectionScanner
    from src.scanners.rce_safe import RCESafeScanner
except ImportError as e:
    print(f"Erreur d'importation: {e}")
    print("Veuillez vérifier la présence de tous les modules sous src/")
    sys.exit(1)


class CyberSecMenu:
    """Menu principal épuré et stable avec options essentielles"""

    def __init__(self) -> None:
        self.target_url: str = ""
        self.selected_modules: List[str] = []
        self.module_profile: str = 'custom'
        self.config: Dict[str, object] = {
            'threads': 10,
            'timeout': 10,
            'verbose': False,
            'output_format': 'html',
            'output_file': '',
            'aggressive_mode': False,
            'payload_mode': 'safe',  # safe | normal | aggressive | expert | expert-deep
            'bulk_filter': 'all',
            'proof_actions': False,
            'force_css_only': False,  # XSS: forcer preuves CSS-only
            'ascii_mode': False,      # CLI: désactiver emojis
            'verify_tls': True,       # HTTP: vérification certificat TLS
        }
        self.available_modules: Dict[str, str] = {
            'sql': 'SQL Injection Scanner',
            'xss': 'Cross-Site Scripting (XSS) Scanner',
            'headers': 'HTTP Security Headers Scanner',
            'ports': 'Port Scanner',
            'dirs': 'Directory Enumeration Scanner',
            'redirtrav': 'Open Redirect & Path Traversal Scanner',
            'ssrf': 'Server-Side Request Forgery (SSRF) Scanner',
            'crlf': 'CRLF Injection Scanner',
            'cmdi': 'Command Injection (safe) Scanner',
            'nosql': 'NoSQL Injection Scanner',
            'xxe': 'XXE (safe) Scanner',
            'ssti': 'SSTI (safe) Scanner',
            'ldapxpath': 'LDAP/XPath Injection Scanner',
            'rce': 'RCE (safe) Scanner',
        }
        self.logger = setup_logger("menu")
        self.last_scan_results: Dict = {}

    # --- Navigation principale ---
    def run(self) -> None:
        try:
            clear_screen()
            self.show_welcome()
            self.main_menu()
        except KeyboardInterrupt:
            print_cyber_warning("\nMenu interrompu par l'utilisateur")
        finally:
            self.show_goodbye()

    def show_welcome(self) -> None:
        clear_screen()
        # Basculer en mode ASCII si demandé via argument ou réglage
        ascii_mode = ('--no-emoji' in sys.argv) or bool(self.config.get('ascii_mode'))
        msg = (
            """
[bold #00ffff]Bienvenue dans CyberSec Web Testing Tool![/]
[dim #00ffff]Tests éthiques uniquement. Rapports HTML/JSON. Rejeu inclus.[/]
"""
        )
        if ascii_mode:
            msg += "[bold #ff0040]!!  UTILISATION AUTORISÉE UNIQUEMENT  !![/]\n"
        else:
            msg += "[bold #ff0040]⚠️  UTILISATION AUTORISÉE UNIQUEMENT  ⚠️[/]\n"
        console.print(create_cyber_panel(msg, "TOOL WEB BY SNAKEN18", "#00ff41"))

    def show_goodbye(self) -> None:
        display_cyber_footer()

    def main_menu(self) -> None:
        while True:
            self.render_main_menu()
            choice = console.input("\n[bold #00ff41]Votre choix (0-10): [/]" ).strip().lower()
            if choice == '1':
                self.configure_target_url()
            elif choice == '2':
                self.choose_modules_simple()
            elif choice == '3':
                self.run_scan()
            elif choice == '4':
                self.show_help()
            elif choice == '5':
                self.configure_advanced_settings()
            elif choice == '6':
                self.show_about()
            elif choice == '7':
                self.view_last_report()
            elif choice == '8':
                self.execute_vulnerability()
            elif choice == '9':
                self.execute_all_vulnerabilities()
            elif choice == '10':
                self.view_execution_reports()
            elif choice == '0':
                break
            else:
                print_cyber_error("Option invalide! Sélectionnez 0-10.")
                time.sleep(1.2)

    def render_main_menu(self) -> None:
        clear_screen()
        modules_count = len(self.selected_modules)
        modules_label = (
            ", ".join(self.selected_modules) if (modules_count and modules_count <= 3)
            else f"{modules_count} sélectionné(s)" if modules_count else "[Aucun]"
        )
        ready = bool(self.target_url and modules_count)
        profile_label = {
            'basic': 'BASIQUE', 'all': 'COMPLET', 'custom': 'PERSONNALISÉ'
        }.get(self.module_profile, 'NON DÉFINI')
        status_lines = [
            "[bold #00ffff]TOOL WEB BY SNAKEN18[/] [dim]• Web Security Testing •[/]",
            f"[bold #ff0080]URL:[/] [#ffff00]{self.target_url if self.target_url else '[Non configurée]'}[/]",
            (
                f"[bold #ff0080]Profil:[/] [#ffff00]{profile_label}[/]  "
                f"[bold #ff0080]Modules:[/] [#ffff00]{modules_label}[/]"
            ),
            (
                f"[bold #ff0080]Threads:[/] [#ffff00]{self.config['threads']}[/]  "
                f"[bold #ff0080]Timeout:[/] [#ffff00]{self.config['timeout']}s[/]  "
                f"[bold #ff0080]Format:[/] [#ffff00]{self.config['output_format'].upper()}[/]"
            ),
            f"[bold #ff0080]Payloads:[/] [#ffff00]{str(self.config.get('payload_mode', 'safe')).upper()}[/]",
            f"[bold #ff0080]Preuves visuelles:[/] [#ffff00]{'ON' if self.config.get('proof_actions') else 'OFF'}[/]",
            f"[bold #ff0080]XSS CSS-only:[/] [#ffff00]{'ON' if self.config.get('force_css_only') else 'OFF'}[/]",
            f"[bold #ff0080]ASCII mode:[/] [#ffff00]{'ON' if self.config.get('ascii_mode') else 'OFF'}[/]",
            f"[bold #ff0080]TLS verify:[/] [#ffff00]{'ON' if self.config.get('verify_tls') else 'OFF'}[/]",
            f"[bold #ff0080]Prêt:[/] {'[green]OUI[/]' if ready else '[red]NON[/]'}",
            "",
            "[dim #00ffff]Sélectionnez une option (0 pour quitter):[/]",
            "",
            "[bold #00ff41][[1]][/] [#ff0080]Définir l'URL cible[/]",
            "[bold #00ff41][[2]][/] [#ff0080]Choisir les modules (Basique/Complet/Personnalisé)[/]",
            "[bold #00ff41][[3]][/] [#ff0080]Lancer le scan[/]",
            "[bold #00ff41][[4]][/] [#ff0080]Aide[/]",
            "[bold #00ff41][[5]][/] [#ff0080]Paramètres avancés[/]",
            "[bold #00ff41][[6]][/] [#ff0080]À propos[/]",
            "[bold #00ff41][[7]][/] [#ff0080]Lire le dernier rapport (scan)[/]",
            "[bold #00ff41][[8]][/] [#ff0080]Exécuter une vulnérabilité détectée[/]",
            "[bold #00ff41][[9]][/] [#ff0080]Exécuter TOUTES les vulnérabilités[/]",
            "[bold #00ff41][[10]][/] [#ff0080]Lire les rapports d'exécution[/]",
            "",
            "[bold #00ff41][[0]][/] [#ff0040]Quitter[/]",
        ]
        console.print(create_cyber_panel("\n".join(status_lines), "MENU PRINCIPAL", "#00ff41"))

    # --- Configurations ---
    def configure_target_url(self) -> None:
        url = console.input("\n[bold #00ff41]Entrez l'URL cible: [/]" ).strip()
        if url:
            self.target_url = url
            print_cyber_success(f"URL configurée: {url}")
            time.sleep(1)

    def choose_modules_simple(self) -> None:
        lines = ["[bold #00ffff]Modules disponibles:[/]", ""]
        for i, (key, label) in enumerate(self.available_modules.items(), 1):
            lines.append(f"{i}. {label} [{key}]")
        lines.append("")
        lines.append("[dim]Astuce: tapez 'all' pour tout sélectionner[/]")
        console.print(create_cyber_panel("\n".join(lines), "CHOIX DES MODULES", "#00ffff"))
        sel = console.input("[bold #00ff41]Entrez des clés séparées par des espaces (ex: xss headers) ou 'all': [/]" ).strip().lower()
        if not sel:
            return
        if sel in ("all", "tous", "tout"):
            self.selected_modules = list(self.available_modules.keys())
            print_cyber_success("Tous les modules sélectionnés")
            time.sleep(1)
            return
        chosen = [s for s in sel.split() if s in self.available_modules]
        self.selected_modules = chosen
        print_cyber_success(f"Modules sélectionnés: {', '.join(chosen) if chosen else '[Aucun]'}")
        time.sleep(1)

    def configure_advanced_settings(self) -> None:
        clear_screen()
        settings_text = (
            f"""[bold #00ffff]Paramètres actuels:[/]

[bold #00ff41][1][/] [#ff0080]Threads:[/] [#ffff00]{self.config['threads']}[/]
[bold #00ff41][2][/] [#ff0080]Timeout:[/] [#ffff00]{self.config['timeout']}s[/]
[bold #00ff41][3][/] [#ff0080]Verbose:[/] [#ffff00]{'On' if self.config['verbose'] else 'Off'}[/]
[bold #00ff41][4][/] [#ff0080]Format sortie:[/]
[#ffff00]{str(self.config['output_format']).upper()}[/]
[bold #00ff41][5][/] [#ff0080]Fichier sortie:[/]
[#ffff00]{self.config['output_file'] or 'Auto-généré'}[/]
[bold #00ff41][6][/] [#ff0080]Mode agressif:[/] [#ffff00]{'On' if self.config['aggressive_mode'] else 'Off'}[/]
[bold #00ff41][7][/] [#ff0080]Filtre exécution lot:[/] [#ffff00]{self.config['bulk_filter']}[/]
[bold #00ff41][8][/] [#ff0080]Mode payloads (safe/normal/aggressive/expert/expert-deep):[/]
[#ffff00]{self.config.get('payload_mode', 'safe')}[/]
[bold #00ff41][9][/] [#ff0080]Preuves visuelles (XSS/CMDi):[/] [#ffff00]{'ON' if self.config.get('proof_actions') else 'OFF'}[/]
[bold #00ff41][10][/] [#ff0080]XSS CSS-only (forcer CSS sans JS):[/] [#ffff00]{'ON' if self.config.get('force_css_only') else 'OFF'}[/]
[bold #00ff41][11][/] [#ff0080]Mode ASCII (sans emojis):[/] [#ffff00]{'ON' if self.config.get('ascii_mode') else 'OFF'}[/]
[bold #00ff41][12][/] [#ff0080]Vérification TLS (certificat):[/] [#ffff00]{'ON' if self.config.get('verify_tls') else 'OFF'}[/]"""
        )
        console.print(create_cyber_panel(settings_text, "PARAMÈTRES AVANCÉS", "#ff0080"))
        choice = console.input("\n[bold #00ff41]Paramètre à modifier (1-12 ou 'back'): [/]" ).strip().lower()
        if choice == 'back':
            return
        elif choice == '1':
            val = console.input("Threads (1-100): ").strip()
            try:
                t = int(val)
                if 1 <= t <= 100:
                    self.config['threads'] = t
                    print_cyber_success(f"Threads: {t}")
            except ValueError:
                print_cyber_error("Nombre invalide")
            time.sleep(1)
        elif choice == '2':
            val = console.input("Timeout en secondes (1-300): ").strip()
            try:
                s = int(val)
                if 1 <= s <= 300:
                    self.config['timeout'] = s
                    print_cyber_success(f"Timeout: {s}s")
            except ValueError:
                print_cyber_error("Nombre invalide")
            time.sleep(1)
        elif choice == '3':
            self.config['verbose'] = not self.config['verbose']
            print_cyber_success(f"Verbose {'activé' if self.config['verbose'] else 'désactivé'}")
            time.sleep(1)
        elif choice == '4':
            cur = str(self.config['output_format']).lower()
            order = ['html', 'json']
            idx = (order.index(cur) + 1) % len(order) if cur in order else 0
            self.config['output_format'] = order[idx]
            print_cyber_success(f"Format: {order[idx].upper()}")
            time.sleep(1)
        elif choice == '5':
            path = console.input("Fichier de sortie (laisser vide pour auto): ").strip()
            self.config['output_file'] = path
            print_cyber_success("Fichier mis à jour")
            time.sleep(1)
        elif choice == '6':
            self.config['aggressive_mode'] = not self.config['aggressive_mode']
            print_cyber_success(f"Agressif {'activé' if self.config['aggressive_mode'] else 'désactivé'}")
            time.sleep(1)
        elif choice == '7':
            order = ['all', 'open redirect', 'path traversal']
            cur = str(self.config.get('bulk_filter', 'all')).lower()
            idx = (order.index(cur) + 1) % len(order) if cur in order else 0
            self.config['bulk_filter'] = order[idx]
            print_cyber_success(f"Filtre: {order[idx]}")
            time.sleep(1)
        elif choice == '8':
            order = ['safe', 'normal', 'aggressive', 'expert', 'expert-deep']
            cur = str(self.config.get('payload_mode', 'safe')).lower()
            idx = (order.index(cur) + 1) % len(order) if cur in order else 0
            new_val = order[idx]
            if new_val in ('expert', 'expert-deep'):
                warn = (
                    "[bold #ff0040]ATTENTION[/]\n\n"
                    f"Mode {new_val.upper()} réservé aux environnements autorisés."
                )
                console.print(create_cyber_panel(warn, "AVERTISSEMENT", "#ff0040"))
                ans = console.input("Confirmer (oui/non): ").strip().lower()
                if ans not in ("y", "yes", "oui"):
                    print_cyber_warning("Mode expert non activé")
                    time.sleep(1)
                    return
            self.config['payload_mode'] = new_val
            print_cyber_success(f"Payloads: {new_val}")
            time.sleep(1)
        elif choice == '9':
            if not self.config.get('proof_actions'):
                warn = (
                    "[bold #ff0040]CONFIRMATION LÉGALE[/]\n\n"
                    "Preuves visuelles exécutées uniquement sur périmètres autorisés."
                )
                console.print(create_cyber_panel(warn, "AVERTISSEMENT", "#ff0040"))
                ans = console.input("Confirmer (oui/non): ").strip().lower()
                if ans not in ("y", "yes", "oui"):
                    print_cyber_warning("Preuves visuelles non activées")
                    time.sleep(1)
                    return
            self.config['proof_actions'] = not self.config.get('proof_actions')
            print_cyber_success(f"Preuves {'activées' if self.config['proof_actions'] else 'désactivées'}")
            time.sleep(1)
        elif choice == '10':
            self.config['force_css_only'] = not self.config.get('force_css_only')
            print_cyber_success(f"XSS CSS-only {'activé' if self.config['force_css_only'] else 'désactivé'}")
            time.sleep(1)
        elif choice == '11':
            self.config['ascii_mode'] = not self.config.get('ascii_mode')
            state = 'activé' if self.config['ascii_mode'] else 'désactivé'
            print_cyber_success(f"Mode ASCII {state}")
            time.sleep(1)
        elif choice == '12':
            self.config['verify_tls'] = not self.config.get('verify_tls')
            state = 'activée' if self.config['verify_tls'] else 'désactivée'
            print_cyber_success(f"Vérification TLS {state}")
            time.sleep(1)

    # --- Exécution de scans ---
    def run_scan(self) -> None:
        if not self.target_url:
            print_cyber_error("URL cible non configurée")
            time.sleep(1.2)
            return
        if not self.selected_modules:
            print_cyber_error("Aucun module sélectionné")
            time.sleep(1.2)
            return
        # Propager la préférence TLS au client via variable d'environnement
        os.environ['CYBERSEC_VERIFY_TLS'] = '1' if bool(self.config.get('verify_tls', True)) else '0'
        report_gen = ReportGenerator()
        scan_results: Dict[str, Dict] = {}
        scanner_classes = {
            'sql': SQLInjectionScanner,
            'xss': XSSScanner,
            'headers': HeaderSecurityScanner,
            'ports': PortScanner,
            'dirs': DirectoryBuster,
            'redirtrav': RedirectTraversalScanner,
            'ssrf': SSRFScanner,
            'crlf': CRLFInjectionScanner,
            'cmdi': CommandInjectionScanner,
            'nosql': NoSQLInjectionScanner,
            'xxe': XXEScanner,
            'ssti': SSTIScanner,
            'ldapxpath': LDAPXPathInjectionScanner,
            'rce': RCESafeScanner,
        }
        with create_cyber_progress() as progress:
            main_task = progress.add_task("Scan en cours...", total=len(self.selected_modules))
            for module_name in self.selected_modules:
                progress.update(main_task, description=f"Module: {module_name.upper()}")
                print_cyber_info(f"Lancement du module: {module_name}")
                try:
                    scanner_class = scanner_classes[module_name]
                    kwargs = {
                        'threads': int(self.config['threads']),
                        'timeout': int(self.config['timeout']),
                        'payload_mode': str(self.config.get('payload_mode', 'safe')),
                        'proof_actions': bool(self.config.get('proof_actions', False)),
                    }
                    if module_name == 'headers':
                        scanner = scanner_class(self.target_url, timeout=int(self.config['timeout']))
                    elif module_name == 'xss':
                        scanner = scanner_class(
                            self.target_url,
                            threads=kwargs['threads'],
                            timeout=kwargs['timeout'],
                            payload_mode=kwargs['payload_mode'],
                            proof_actions=kwargs['proof_actions'],
                            force_css_only=bool(self.config.get('force_css_only', False)),
                        )
                    elif module_name in ('sql', 'ssrf', 'crlf', 'nosql', 'xxe', 'ssti', 'ldapxpath', 'redirtrav'):
                        scanner = scanner_class(
                            self.target_url,
                            threads=kwargs['threads'],
                            timeout=kwargs['timeout'],
                            payload_mode=kwargs['payload_mode'],
                            proof_actions=kwargs['proof_actions'],
                        )
                    elif module_name == 'cmdi':
                        scanner = scanner_class(
                            self.target_url,
                            threads=kwargs['threads'],
                            timeout=kwargs['timeout'],
                            aggressive=bool(self.config.get('aggressive_mode', False)),
                            payload_mode=kwargs['payload_mode'],
                            proof_actions=kwargs['proof_actions'],
                        )
                    elif module_name == 'rce':
                        scanner = scanner_class(
                            self.target_url,
                            threads=kwargs['threads'],
                            timeout=kwargs['timeout'],
                            aggressive=bool(self.config.get('aggressive_mode', False)),
                            payload_mode=kwargs['payload_mode'],
                        )
                    else:
                        scanner = scanner_class(self.target_url, timeout=kwargs['timeout'])
                    results = scanner.scan()
                    scan_results[module_name] = results
                    vuln_count = len(results.get('vulnerabilities', []))
                    if vuln_count > 0:
                        print_cyber_warning(f"Module {module_name}: {vuln_count} vulnérabilité(s)")
                    else:
                        print_cyber_success(f"Module {module_name}: Aucune vulnérabilité")
                except Exception as e:
                    print_cyber_error(f"Erreur module {module_name}: {e}")
                    scan_results[module_name] = {"error": str(e), "vulnerabilities": []}
                finally:
                    progress.advance(main_task)
                    time.sleep(0.2)
        show_scan_summary(scan_results, self.target_url)
        # Générer rapport
        ts = time.strftime('%Y%m%d_%H%M%S')
        base = f"reports/scans/cybersec_report_{ts}." + str(self.config['output_format']).lower()
        report_gen.generate_report(scan_results, self.target_url, base)
        self.last_scan_results = scan_results
        print_cyber_success("Scan terminé et rapport généré")
        time.sleep(1.5)

    # --- Rapports ---
    def _open_in_browser(self, path: str) -> None:
        try:
            webbrowser.open_new_tab(path)
        except Exception:
            pass

    # --- Helpers pour rejeu ---
    def _collect_vulnerabilities(self) -> List[Dict]:
        vulns: List[Dict] = []
        for module, res in (self.last_scan_results or {}).items():
            for v in res.get('vulnerabilities', []) or []:
                # Ne garder que les vulnérabilités rejouables (avec URL ou lien de preuve)
                if not (v.get('proof_url') or v.get('url')):
                    continue
                copy = dict(v)
                copy['module'] = module
                vulns.append(copy)
        return vulns

    def _fallback_vulns_from_latest_html(self) -> List[Dict]:
        # Cherche les liens "Preuve visuelle" dans le dernier rapport HTML pour permettre un rejeu minimal
        latest = None
        scans_dir = os.path.join(os.getcwd(), 'reports', 'scans')
        if os.path.isdir(scans_dir):
            candidates = []
            for p in glob.glob(os.path.join(scans_dir, '*.html')):
                try:
                    candidates.append((os.path.getmtime(p), p))
                except OSError:
                    continue
            if candidates:
                candidates.sort(key=lambda t: t[0], reverse=True)
                latest = candidates[0][1]
        if not latest:
            return []
        try:
            with open(latest, 'r', encoding='utf-8') as f:
                html_src = f.read()
        except OSError:
            return []
        vulns: List[Dict] = []
        # Capture les blocs de vulnérabilité et extrait le type et le lien de preuve
        for block in re.findall(r"<div class=\"vulnerability[\s\S]*?<div class=\\\"vuln-details\\\">([\s\S]*?)</div></div>", html_src):
            # Type
            mtype = re.search(r"<span class=\\\"vuln-type\\\">([^<]+)</span>", block)
            vtype = mtype.group(1) if mtype else 'Unknown'
            # Paramètre
            mparam = re.search(r"<strong>Paramètre:</strong>\s*([^<\n]+)", block)
            param = mparam.group(1) if mparam else ''
            # Méthode
            mmeth = re.search(r"<strong>Méthode:</strong>\s*([^<\n]+)", block)
            method = mmeth.group(1) if mmeth else 'GET'
            # Preuve visuelle
            mproof = re.search(r"<strong>Preuve visuelle:</strong>\s*<a href=\"([^\"]+)\"", block)
            proof = mproof.group(1) if mproof else ''
            # URL
            murl = re.search(r"<strong>URL:</strong>\s*([^<\n]+)", block)
            url = murl.group(1) if murl else ''
            if proof or url:
                vulns.append({
                    'type': vtype,
                    'parameter': param,
                    'method': method,
                    'proof_url': proof,
                    'url': url,
                    'module': 'unknown',
                })
        return vulns

    def _replay_vulnerabilities(self, vulns: List[Dict]) -> Optional[str]:
        if not vulns:
            print_cyber_warning("Aucune vulnérabilité à rejouer")
            time.sleep(1.2)
            return None
        results: List[Dict] = []
        raw_dir = Path(os.getcwd()) / 'reports' / 'executions' / 'raw'
        raw_dir.mkdir(parents=True, exist_ok=True)
        for v in vulns:
            # Ignorer les constats d'en-têtes non rejouables
            vtype = (v.get('type') or '').lower()
            if (v.get('module') == 'headers') and not v.get('proof_url'):
                continue
            url = v.get('proof_url') or v.get('url')
            method = (v.get('method') or 'GET').upper()
            ok = False
            status = None
            final_url = None
            raw_path = None
            try:
                if method == 'POST' and v.get('post_data'):
                    r = requests.post(url, data=v.get('post_data'), timeout=int(self.config['timeout']), allow_redirects=True)
                else:
                    r = requests.get(url, timeout=int(self.config['timeout']), allow_redirects=True)
                status = r.status_code
                final_url = r.url
                raw_path = str(raw_dir / f"body_{int(time.time()*1000)}.html")
                with open(raw_path, 'w', encoding='utf-8') as f:
                    f.write(r.text)
                # Critère générique
                ok200 = (200 <= r.status_code < 400)
                ok = ok200
                manual_check = False
                # Validation visuelle pour XSS CSS-only: vérifier la présence du style appliqué
                # On considère le succès si le HTML de réponse contient un style appliquant la couleur #ff0044
                if v.get('proof_url'):
                    # Détection CSS plus robuste (espaces variables, inline ou balise <style>)
                    try:
                        import re as _re
                        body_has_red = _re.search(r"background\s*:\s*#ff0044", r.text, flags=_re.IGNORECASE) is not None
                    except Exception:
                        body_has_red = ('background:#ff0044' in r.text.lower()) or ('background: #ff0044' in r.text.lower())
                    if 'style' in str(v.get('proof_url')).lower():
                        # Si réponse OK mais pas de style détecté, marquer comme vérification manuelle
                        if ok200 and not body_has_red:
                            manual_check = True
                        ok = ok200 and body_has_red
                # Validateurs spécifiques par type de vulnérabilité
                vtype_l = (v.get('type') or '').lower()
                try:
                    # Open Redirect: vérifier bascule vers domaine externe connu
                    if 'open redirect' in vtype_l:
                        ext_domains = ('httpbin.org', 'postman-echo.com', 'example.com')
                        ok = ok200 and any(d in (final_url or '').lower() for d in ext_domains)
                    # Path Traversal: marqueurs de fichiers système (hosts/passwd/win.ini)
                    elif 'path traversal' in vtype_l:
                        txt = r.text or ''
                        markers = ('root:', '[fonts]', 'extensions', 'mci', '127.0.0.1', 'localhost', '::1')
                        ok = ok200 and any(m.lower() in txt.lower() for m in markers)
                    # SSRF: marqueurs d'écho externe ou metadata
                    elif 'ssrf' in vtype_l:
                        txt = r.text or ''
                        markers = (
                            'httpbin.org', 'postman-echo.com', 'meta-data', 'iam', 'security-credentials',
                            '169.254.169.254'
                        )
                        ok = ok200 and any(m.lower() in txt.lower() for m in markers)
                    # SSTI (safe): trace d'erreur ou calcul 7*7 == 49
                    elif 'ssti' in vtype_l:
                        txt = r.text or ''
                        err_markers = (
                            'TemplateSyntaxError', 'UndefinedError', 'Jinja2', 'Twig_Error', 'VelocityException',
                            'freemarker.core', 'Handlebars', 'erb', 'liquid', 'mustache'
                        )
                        ok = ok200 and (('49' in txt) or any(m.lower() in txt.lower() for m in err_markers))
                    # XXE (safe): erreurs parser DOCTYPE/ENTITY
                    elif 'xxe' in vtype_l:
                        txt = r.text or ''
                        xxe_markers = (
                            'DOCTYPE is disallowed', 'External entity', 'XXE', 'XML parser error', 'ENTITY is not allowed'
                        )
                        ok = ok200 and any(m.lower() in txt.lower() for m in xxe_markers)
                    # CRLF Injection: refaire une requête sans redirections et inspecter les en-têtes
                    elif 'crlf injection' in vtype_l:
                        r2 = requests.get(url, timeout=int(self.config['timeout']), allow_redirects=False)
                        headers_blob = "\n".join([f"{k}: {v}" for k, v in r2.headers.items()])
                        ok = (r2.status_code in {400, 500, 502, 503, 504}) or any(
                            m in headers_blob for m in ('Injected:', 'X-Test:', 'crlf=1', 'X-Proof:')
                        )
                except Exception:
                    # Ne pas casser le rejeu sur erreur de validation
                    ok = ok
            except Exception as e:
                status = str(e)
                ok = False
            results.append({
                'type': v.get('type') or v.get('module') or 'Unknown',
                'method': method,
                'parameter': v.get('parameter', ''),
                'payloads_tried': [v.get('payload')] if v.get('payload') else [],
                'status_code': status,
                'final_url': final_url or url,
                'proof_url': v.get('proof_url'),
                'proof_used': bool(v.get('proof_url')),
                'raw_body_path': raw_path,
                'success': ok,
                'manual_check': manual_check,
            })
        ts = time.strftime('%Y%m%d_%H%M%S')
        out_html = os.path.join('reports', 'executions', f"cybersec_exec_{ts}.html")
        ReportGenerator().generate_execution_report(results, self.target_url or 'N/A', out_html)
        print_cyber_success(f"Rapport d'exécution généré: {out_html}")
        return out_html

    def view_execution_reports(self) -> None:
        clear_screen()
        exec_dir = os.path.join(os.getcwd(), 'reports', 'executions')
        if not os.path.isdir(exec_dir):
            console.print(create_cyber_panel("Aucun dossier reports/executions", "RAPPORTS D'EXÉCUTION", "#ff0040"))
            time.sleep(2)
            return
        files: List[Tuple[float, str]] = []
        for pattern in ('*.html', '*.json'):
            for path in glob.glob(os.path.join(exec_dir, pattern)):
                try:
                    files.append((os.path.getmtime(path), path))
                except OSError:
                    continue
        if not files:
            console.print(create_cyber_panel("Aucun rapport d'exécution", "RAPPORTS D'EXÉCUTION", "#ff0040"))
            time.sleep(2)
            return
        files.sort(key=lambda t: t[0], reverse=True)
        lines: List[str] = ["[bold #00ffff]Rapports disponibles (récents d'abord):[/]", ""]
        for idx, (_, path) in enumerate(files[:30], 1):
            name = os.path.basename(path)
            lines.append(f"[bold #00ff41]{idx}[/] [#ff0080]{name}[/] [dim]{path}[/]")
        lines.append("")
        lines.append("[dim #00ffff]Entrez un numéro (ou 'back').[/]")
        console.print(create_cyber_panel("\n".join(lines), "RAPPORTS D'EXÉCUTION", "#00ffff"))
        choice = console.input("\n[bold #00ff41]Votre choix: [/]" ).strip().lower()
        if choice == 'back' or not choice:
            return
        if not choice.isdigit():
            print_cyber_error("Entrée invalide")
            time.sleep(1.2)
            return
        n = int(choice)
        if not (1 <= n <= min(30, len(files))):
            print_cyber_error("Numéro hors plage")
            time.sleep(1.2)
            return
        selected_path = files[n - 1][1]
        ext = os.path.splitext(selected_path)[1].lower()
        if ext == '.html':
            msg = f"Ouverture du rapport HTML:\n[#ffff00]{selected_path}[/]"
            console.print(create_cyber_panel(msg, "OUVERTURE", "#00ff41"))
            self._open_in_browser(selected_path)
            time.sleep(1.5)
            return
        # JSON bref
        try:
            with open(selected_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print_cyber_error(f"Impossible de lire le JSON: {e}")
            time.sleep(2)
            return
        scan_info = data.get('scan_info', {})
        summary = data.get('summary', {})
        tgt = scan_info.get('target', 'N/A')
        ts = scan_info.get('timestamp', 'N/A')
        success = summary.get('success', 0)
        fail = summary.get('fail', 0)
        total = summary.get('total', success + fail)
        content = (
            f"[bold #00ffff]Cible:[/] [#ffff00]{tgt}[/]\n"
            f"[bold #00ffff]Date:[/] [#ffff00]{ts}[/]\n"
            f"[bold #00ffff]Exécutions:[/] [#ffff00]{total}[/] • "
            f"[green]Succès {success}[/] / [red]Échecs {fail}[/]"
        )
        console.print(create_cyber_panel(content, "RAPPORT D'EXÉCUTION (JSON)", "#00ff41"))
        time.sleep(2)

    # --- Placeholders épurés ---
    def show_help(self) -> None:
        console.print(create_cyber_panel("Consultez README.md pour l'aide.", "AIDE", "#00ffff"))
        time.sleep(1.5)

    def show_about(self) -> None:
        console.print(create_cyber_panel("CyberSec Web Testing Tool • Pro", "À PROPOS", "#00ff41"))
        time.sleep(1.5)

    def view_last_report(self) -> None:
        console.print(create_cyber_panel("Lecture de rapport simplifiée.", "RAPPORT", "#00ffff"))
        time.sleep(1.5)

    def execute_vulnerability(self) -> None:
        # Rejeu ciblé d'une vulnérabilité depuis les résultats en mémoire, sinon fallback dernier HTML
        vulns = self._collect_vulnerabilities()
        if not vulns:
            vulns = self._fallback_vulns_from_latest_html()
        if not vulns:
            console.print(create_cyber_panel("Aucune vulnérabilité disponible pour rejeu.", "REJEU", "#ff0040"))
            time.sleep(1.5)
            return
        # Afficher la liste
        lines = ["[bold #00ffff]Vulnérabilités détectées:[/]", ""]
        for i, v in enumerate(vulns, 1):
            label = f"{v.get('type','Unknown')} • {v.get('method','GET')} • {v.get('parameter','')}"
            lines.append(f"[bold #00ff41]{i}[/] [#ff0080]{label}[/]")
        lines.append("")
        lines.append("[dim]Choisissez un numéro pour rejouer (ou 'back').[/]")
        console.print(create_cyber_panel("\n".join(lines), "REJEU CIBLÉ", "#00ffff"))
        choice = console.input("\n[bold #00ff41]Votre choix: [/]" ).strip().lower()
        if choice == 'back' or not choice:
            return
        if not choice.isdigit():
            print_cyber_error("Entrée invalide")
            time.sleep(1.2)
            return
        n = int(choice)
        if not (1 <= n <= len(vulns)):
            print_cyber_error("Numéro hors plage")
            time.sleep(1.2)
            return
        sel = [vulns[n - 1]]
        out = self._replay_vulnerabilities(sel)
        if out:
            # Ouvrir rapport
            self._open_in_browser(out)
        time.sleep(1.0)

    def execute_all_vulnerabilities(self) -> None:
        # Rejeu de toutes les vulnérabilités disponibles
        vulns = self._collect_vulnerabilities()
        if not vulns:
            vulns = self._fallback_vulns_from_latest_html()
        if not vulns:
            console.print(create_cyber_panel("Aucune vulnérabilité disponible pour rejeu.", "REJEU LOT", "#ff0040"))
            time.sleep(1.5)
            return
        out = self._replay_vulnerabilities(vulns)
        if out:
            self._open_in_browser(out)
        time.sleep(1.0)


def main() -> None:
    app = CyberSecMenu()
    app.run()


if __name__ == "__main__":
    main()
