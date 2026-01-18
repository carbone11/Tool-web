"""
Générateur de rapports
Crée des rapports HTML et JSON des résultats de scan
"""

import json
import html
from datetime import datetime
from typing import Dict, List
import logging


class ReportGenerator:
    """Générateur de rapports pour les résultats de scan de sécurité"""
    
    def __init__(self):
        """Initialise le générateur de rapports"""
        self.logger = logging.getLogger('cybersec_tool.report_generator')
    
    def generate_report(self, scan_results: Dict, target_url: str, output_path: str) -> str:
        """
        Génère un rapport à partir des résultats de scan
        
        Args:
            scan_results: Résultats des différents modules de scan
            target_url: URL de la cible scannée
            output_path: Chemin de sortie du rapport
            
        Returns:
            Chemin du fichier de rapport généré
        """
        # Déterminer le format basé sur l'extension
        if output_path.endswith('.json'):
            return self._generate_json_report(scan_results, target_url, output_path)
        else:
            return self._generate_html_report(scan_results, target_url, output_path)

    # === Nouveaux rapports: exécutions (replay) ===
    def generate_execution_report(self, replay_results: List[Dict], target_url: str, output_path: str) -> str:
        """
        Génère un rapport d'exécution (replay) après reproduction des vulnérabilités

        Args:
            replay_results: Liste de résultats de rejeu (dicts avec succès/échec et détails)
            target_url: URL cible
            output_path: Chemin du rapport (html ou json)

        Returns:
            Chemin du fichier généré
        """
        if output_path.endswith('.json'):
            return self._generate_json_exec_report(replay_results, target_url, output_path)
        else:
            return self._generate_html_exec_report(replay_results, target_url, output_path)
    
    def _generate_json_report(self, scan_results: Dict, target_url: str, output_path: str) -> str:
        """
        Génère un rapport JSON
        
        Args:
            scan_results: Résultats des scans
            target_url: URL cible
            output_path: Chemin de sortie
            
        Returns:
            Chemin du fichier généré
        """
        report_data = {
            'scan_info': {
                'target': target_url,
                'timestamp': datetime.now().isoformat(),
                'tool': 'CyberSec Web Testing Tool',
                'version': '1.0.0'
            },
            'summary': self._generate_summary(scan_results),
            'results': scan_results
        }
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info("📄 Rapport JSON généré: %s", output_path)
            return output_path
            
        except Exception as e:
            self.logger.error("Erreur génération rapport JSON: %s", str(e))
            raise
    
    def _generate_html_report(self, scan_results: Dict, target_url: str, output_path: str) -> str:
        """
        Génère un rapport HTML
        
        Args:
            scan_results: Résultats des scans
            target_url: URL cible
            output_path: Chemin de sortie
            
        Returns:
            Chemin du fichier généré
        """
        try:
            html_content = self._build_html_report(scan_results, target_url)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info("📄 Rapport HTML généré: %s", output_path)
            return output_path
            
        except Exception as e:
            self.logger.error("Erreur génération rapport HTML: %s", str(e))
            raise

    def _generate_json_exec_report(self, replay_results: List[Dict], target_url: str, output_path: str) -> str:
        summary = self._generate_exec_summary(replay_results)
        report_data = {
            'scan_info': {
                'target': target_url,
                'timestamp': datetime.now().isoformat(),
                'tool': 'CyberSec Web Testing Tool',
                'version': '1.0.0',
            },
            'summary': summary,
            'replay_results': replay_results,
        }
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            self.logger.info("📄 Rapport d'exécution JSON généré: %s", output_path)
            return output_path
        except Exception as e:
            self.logger.error("Erreur génération rapport exécution JSON: %s", str(e))
            raise

    def _generate_html_exec_report(self, replay_results: List[Dict], target_url: str, output_path: str) -> str:
        summary = self._generate_exec_summary(replay_results)
        # Construire sections
        rows = []
        for i, r in enumerate(replay_results, 1):
            # Affichage de l'état: succès, échec ou vérification manuelle
            if r.get('manual_check'):
                success = '⚠️ manuel'
            else:
                success = '✅' if r.get('success') else '❌'
            raw_link = ''
            rpath = r.get('raw_body_path')
            if rpath:
                raw_link = f"<br><small>Raw: <a href='{html.escape(str(rpath))}' target='_blank'>{html.escape(str(rpath))}</a></small>"
            post_replay_link = ''
            if r.get('open_replay_path'):
                post_replay_link = f"<br><small>Rejouer POST: <a href='{html.escape(str(r.get('open_replay_path')))}' target='_blank'>ouvrir</a></small>"
            bypass_info = ''
            attempts = r.get('bypass_403_attempts') or []
            if attempts:
                ok = [a for a in attempts if a.get('success')]
                bypass_info = f"<br><small>403-bypass: {len(ok)}/{len(attempts)} succès</small>"
            proof_cell = ''
            # Utiliser l'URL de preuve si disponible, sinon retomber sur l'URL finale
            proof_link = r.get('proof_url') or r.get('final_url')
            if r.get('proof_used') and proof_link:
                manual_note = ''
                if r.get('manual_check'):
                    manual_note = "<br><small>Note: paramètre non reflété — preuve visuelle non applicable</small>"
                proof_cell = f"<a href='{html.escape(str(proof_link))}' target='_blank'>ouvrir</a>{manual_note}"
            rows.append(f"""
                <tr>
                    <td>#{i}</td>
                    <td>{html.escape(str(r.get('type', '')))}</td>
                    <td>{html.escape(str(r.get('method', '')))}</td>
                    <td>{html.escape(str(r.get('parameter', '') or ''))}</td>
                    <td><code>{html.escape(str(r.get('payloads_tried', []))[:120])}</code></td>
                    <td>{html.escape(str(r.get('status_code', '')))}</td>
                    <td><a href="{html.escape(str(r.get('final_url', '')))}" target="_blank">link</a>{raw_link}{post_replay_link}{bypass_info}</td>
                    <td>{proof_cell or '-'}</td>
                    <td>{success}</td>
                </tr>
            """)
        rows_html = "\n".join(rows)
        html_content = f'''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Exécution - {html.escape(target_url)}</title>
    <style>
        {self._get_css_styles()}
        table.replay {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
        table.replay th, table.replay td {{ border: 1px solid #ddd; padding: 8px; font-size: 14px; }}
        table.replay th {{ background: #eee; text-align: left; }}
        .ok {{ color: #2e7d32; }}
        .fail {{ color: #c62828; }}
        code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }}
    </style>
    </head>
    <body>
        <div class="container">
            <header class="header">
                <h1>🚀 Rapport d'Exécution (Rejeu)</h1>
                <div class="target-info">
                    <strong>Cible:</strong> {html.escape(target_url)}<br>
                    <strong>Date:</strong> {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}<br>
                    <strong>Bilan:</strong> {summary['success']} succès / {summary['fail']} échecs
                </div>
            </header>
            <section>
                <h2>Résultats</h2>
                <table class="replay">
                    <thead>
                        <tr>
                            <th>#</th><th>Type</th><th>Méthode</th><th>Paramètre</th><th>Payload(s)</th><th>Status</th><th>URL finale</th><th>Preuve visuelle</th><th>OK?</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </section>
            <footer class="footer">
                <p>Rapport généré par CyberSec Web Testing Tool</p>
                <p><strong>⚠️ Tests autorisés uniquement</strong></p>
            </footer>
        </div>
    </body>
    </html>
        '''
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.logger.info("📄 Rapport d'exécution HTML généré: %s", output_path)
            return output_path
        except Exception as e:
            self.logger.error("Erreur génération rapport exécution HTML: %s", str(e))
            raise

    def _generate_exec_summary(self, replay_results: List[Dict]) -> Dict:
        total = len(replay_results)
        success = sum(1 for r in replay_results if r.get('success'))
        fail = total - success
        return {
            'total': total,
            'success': success,
            'fail': fail,
        }
    
    def _generate_summary(self, scan_results: Dict) -> Dict:
        """
        Génère un résumé global des résultats
        
        Args:
            scan_results: Résultats des scans
            
        Returns:
            Dictionnaire de résumé
        """
        total_vulnerabilities = 0
        vulnerabilities_by_severity = {'High': 0, 'Medium': 0, 'Low': 0}
        modules_executed = []
        
        for module_name, results in scan_results.items():
            modules_executed.append(module_name)
            
            if 'vulnerabilities' in results:
                vulns = results['vulnerabilities']
                total_vulnerabilities += len(vulns)
                
                for vuln in vulns:
                    severity = vuln.get('severity', 'Low')
                    if severity in vulnerabilities_by_severity:
                        vulnerabilities_by_severity[severity] += 1
        
        return {
            'total_vulnerabilities': total_vulnerabilities,
            'vulnerabilities_by_severity': vulnerabilities_by_severity,
            'modules_executed': modules_executed,
            'risk_level': self._calculate_risk_level(vulnerabilities_by_severity)
        }
    
    def _calculate_risk_level(self, vulns_by_severity: Dict) -> str:
        """
        Calcule le niveau de risque global
        
        Args:
            vulns_by_severity: Vulnérabilités par niveau de sévérité
            
        Returns:
            Niveau de risque
        """
        if vulns_by_severity['High'] > 0:
            return 'Critique'
        elif vulns_by_severity['Medium'] > 3:
            return 'Élevé'
        elif vulns_by_severity['Medium'] > 0 or vulns_by_severity['Low'] > 5:
            return 'Moyen'
        elif vulns_by_severity['Low'] > 0:
            return 'Faible'
        else:
            return 'Minimal'
    
    def _build_html_report(self, scan_results: Dict, target_url: str) -> str:
        """
        Construit le contenu HTML du rapport
        
        Args:
            scan_results: Résultats des scans
            target_url: URL cible
            
        Returns:
            Contenu HTML
        """
        summary = self._generate_summary(scan_results)
        
        html_content = f'''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Sécurité Web - {html.escape(target_url)}</title>
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ Rapport de Sécurité Web</h1>
            <div class="target-info">
                <strong>Cible:</strong> {html.escape(target_url)}<br>
                <strong>Date:</strong> {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}<br>
                <strong>Niveau de risque:</strong> <span class="risk-{summary['risk_level'].lower()}">{summary['risk_level']}</span>
            </div>
        </header>
        
        <section class="summary">
            <h2>📊 Résumé Exécutif</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Vulnérabilités Totales</h3>
                    <div class="big-number">{summary['total_vulnerabilities']}</div>
                </div>
                <div class="summary-card critical">
                    <h3>Critiques</h3>
                    <div class="big-number">{summary['vulnerabilities_by_severity']['High']}</div>
                </div>
                <div class="summary-card warning">
                    <h3>Moyennes</h3>
                    <div class="big-number">{summary['vulnerabilities_by_severity']['Medium']}</div>
                </div>
                <div class="summary-card info">
                    <h3>Faibles</h3>
                    <div class="big-number">{summary['vulnerabilities_by_severity']['Low']}</div>
                </div>
            </div>
        </section>
        
        {self._build_modules_sections(scan_results)}
        
        <footer class="footer">
            <p>Rapport généré par CyberSec Web Testing Tool v1.0.0</p>
            <p><strong>⚠️ Ce rapport est destiné uniquement aux tests autorisés</strong></p>
        </footer>
    </div>
</body>
</html>
'''
        return html_content
    
    def _build_modules_sections(self, scan_results: Dict) -> str:
        """
        Construit les sections pour chaque module de scan
        
        Args:
            scan_results: Résultats des scans
            
        Returns:
            HTML des sections de modules
        """
        sections_html = ""
        
        module_names = {
            'sql': '💉 Test d\'Injection SQL',
            'xss': '🔗 Test de Cross-Site Scripting (XSS)',
            'headers': '🔒 Analyse des En-têtes de Sécurité',
            'ports': '🔍 Scan de Ports',
            'dirs': '📁 Découverte de Répertoires',
            'redirtrav': '↪️ Open Redirect & Path Traversal',
            'ssrf': '🌐 Server-Side Request Forgery (SSRF)',
            'crlf': '📨 Injection CRLF (Header Splitting)',
                'cmdi': '🧰 Injection de Commandes (safe)',
                'nosql': '🗄️ Injection NoSQL',
                'xxe': '📦 XXE (safe)',
                'ssti': '🧩 SSTI (safe)',
                'ldapxpath': '📚 LDAP/XPath Injection',
                'rce': '🚀 RCE (safe)',
        }
        
        for module_key, results in scan_results.items():
            module_name = module_names.get(module_key, module_key.title())
            
            sections_html += f'''
        <section class="module-section">
            <h2>{module_name}</h2>
            {self._build_module_content(module_key, results)}
        </section>
            '''
        
        return sections_html
    
    def _build_module_content(self, module_key: str, results: Dict) -> str:
        """
        Construit le contenu d'un module spécifique
        
        Args:
            module_key: Clé du module
            results: Résultats du module
            
        Returns:
            HTML du contenu du module
        """
        content = ""
        
        # Résumé du module
        if 'summary' in results:
            content += "<div class='module-summary'>"
            content += "<h3>📈 Résumé</h3>"
            content += "<ul>"
            for key, value in results['summary'].items():
                content += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
            content += "</ul>"
            content += "</div>"
        
        # Vulnérabilités trouvées
        if 'vulnerabilities' in results and results['vulnerabilities']:
            content += "<div class='vulnerabilities'>"
            content += f"<h3>🚨 Vulnérabilités Détectées ({len(results['vulnerabilities'])})</h3>"
            
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                severity_class = vuln.get('severity', 'Low').lower()
                content += f'''
                <div class="vulnerability {severity_class}">
                    <div class="vuln-header">
                        <span class="vuln-number">#{i}</span>
                        <span class="vuln-type">{html.escape(vuln.get('type', 'Unknown'))}</span>
                        <span class="severity-badge {severity_class}">{vuln.get('severity', 'Low')}</span>
                    </div>
                    <div class="vuln-details">
                        <p><strong>Description:</strong> {html.escape(vuln.get('description', 'N/A'))}</p>
                '''
                
                # Détails spécifiques selon le type de vulnérabilité
                if 'parameter' in vuln:
                    content += f"<p><strong>Paramètre:</strong> {html.escape(vuln['parameter'])}</p>"
                if 'payload' in vuln:
                    content += f"<p><strong>Payload:</strong> <code>{html.escape(vuln['payload'])}</code></p>"
                if 'url' in vuln:
                    content += f"<p><strong>URL:</strong> {html.escape(vuln['url'])}</p>"
                # Lien vers une preuve visuelle, si disponible
                if 'proof_url' in vuln and vuln.get('proof_url'):
                    content += (
                        f"<p><strong>Preuve visuelle:</strong> "
                        f"<a href=\"{html.escape(str(vuln.get('proof_url')))}\" target=\"_blank\">ouvrir</a></p>"
                    )
                if 'method' in vuln:
                    content += f"<p><strong>Méthode:</strong> {vuln['method']}</p>"
                if 'header' in vuln:
                    content += f"<p><strong>En-tête:</strong> {html.escape(vuln['header'])}</p>"
                if 'port' in vuln:
                    content += f"<p><strong>Port:</strong> {vuln['port']}</p>"
                if 'path' in vuln:
                    content += f"<p><strong>Chemin:</strong> {html.escape(vuln['path'])}</p>"
                
                if 'recommendation' in vuln:
                    content += f"<p><strong>Recommandation:</strong> {html.escape(vuln['recommendation'])}</p>"
                
                if 'evidence' in vuln:
                    content += f"<details><summary>Évidence</summary><pre>{html.escape(vuln['evidence'])}</pre></details>"
                
                content += "</div></div>"
            
            content += "</div>"
        
        # Éléments trouvés (pour le directory buster)
        if module_key == 'dirs' and 'found_paths' in results and results['found_paths']:
            content += "<div class='found-paths'>"
            content += f"<h3>📂 Chemins Découverts ({len(results['found_paths'])})</h3>"
            content += "<table>"
            content += "<tr><th>Chemin</th><th>Type</th><th>Status</th><th>Taille</th></tr>"
            
            for path_info in results['found_paths'][:20]:  # Limiter l'affichage
                content += f'''
                <tr>
                    <td><a href="{html.escape(path_info['url'])}" target="_blank">{html.escape(path_info['path'])}</a></td>
                    <td>{path_info['type']}</td>
                    <td>{path_info['status_code']}</td>
                    <td>{path_info.get('size', 0)} bytes</td>
                </tr>
                '''
            
            if len(results['found_paths']) > 20:
                content += f"<tr><td colspan='4'>... et {len(results['found_paths']) - 20} autres</td></tr>"
            
            content += "</table></div>"
        
        # Ports ouverts (pour le port scanner)
        if module_key == 'ports' and 'open_ports' in results and results['open_ports']:
            content += "<div class='open-ports'>"
            content += f"<h3>🔓 Ports Ouverts ({len(results['open_ports'])})</h3>"
            content += "<table>"
            content += "<tr><th>Port</th><th>Service</th><th>Temps de réponse</th><th>Banner</th></tr>"
            
            for port_info in results['open_ports']:
                content += f'''
                <tr>
                    <td>{port_info['port']}</td>
                    <td>{html.escape(port_info['service'])}</td>
                    <td>{port_info.get('response_time', 0):.1f}ms</td>
                    <td><code>{html.escape(port_info.get('banner', '')[:50])}</code></td>
                </tr>
                '''
            
            content += "</table></div>"
        
        if not content:
            content = "<p>✅ Aucun problème détecté dans ce module.</p>"
        
        return content
    
    def _get_css_styles(self) -> str:
        """
        Retourne les styles CSS pour le rapport HTML
        
        Returns:
            Styles CSS
        """
        return '''
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 15px;
        }
        
        .target-info {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 5px;
            display: inline-block;
            text-align: left;
        }
        
        .risk-critique { color: #dc3545; font-weight: bold; }
        .risk-élevé { color: #fd7e14; font-weight: bold; }
        .risk-moyen { color: #ffc107; font-weight: bold; }
        .risk-faible { color: #28a745; font-weight: bold; }
        .risk-minimal { color: #6c757d; font-weight: bold; }
        
        .summary {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #007bff;
        }
        
        .summary-card.critical { border-left-color: #dc3545; }
        .summary-card.warning { border-left-color: #ffc107; }
        .summary-card.info { border-left-color: #17a2b8; }
        
        .big-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #333;
            margin-top: 10px;
        }
        
        .module-section {
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .module-section h2 {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            padding: 20px;
            margin: 0;
            font-size: 1.5em;
        }
        
        .module-summary {
            padding: 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        
        .module-summary ul {
            list-style: none;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 10px;
        }
        
        .module-summary li {
            background: white;
            padding: 10px;
            border-radius: 5px;
            border-left: 3px solid #007bff;
        }
        
        .vulnerabilities {
            padding: 20px;
        }
        
        .vulnerability {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .vulnerability.high {
            border-left: 5px solid #dc3545;
        }
        
        .vulnerability.medium {
            border-left: 5px solid #ffc107;
        }
        
        .vulnerability.low {
            border-left: 5px solid #17a2b8;
        }
        
        .vuln-header {
            background: #f8f9fa;
            padding: 15px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .vuln-number {
            background: #007bff;
            color: white;
            padding: 5px 10px;
            border-radius: 20px;
            font-weight: bold;
            min-width: 35px;
            text-align: center;
        }
        
        .vuln-type {
            flex: 1;
            font-weight: bold;
            font-size: 1.1em;
        }
        
        .severity-badge {
            padding: 5px 12px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.8em;
        }
        
        .severity-badge.high { background: #dc3545; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #17a2b8; }
        
        .vuln-details {
            padding: 20px;
        }
        
        .vuln-details p {
            margin-bottom: 10px;
        }
        
        code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            color: #e83e8c;
        }
        
        pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            max-height: 200px;
            overflow-y: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        th {
            background: #f8f9fa;
            font-weight: bold;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        .found-paths, .open-ports {
            padding: 20px;
        }
        
        details {
            margin-top: 10px;
        }
        
        summary {
            cursor: pointer;
            color: #007bff;
            font-weight: bold;
        }
        
        summary:hover {
            text-decoration: underline;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
            margin-top: 30px;
        }
        
        a {
            color: #007bff;
            text-decoration: none;
        }
        
        a:hover {
            text-decoration: underline;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .vuln-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
        }
        '''