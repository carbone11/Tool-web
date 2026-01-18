# 🛡️ CyberSec Web Testing Tool v2.1

**Professional Security Scanner for Authorized Penetration Testing**  
*Created by snaken18*

## ⚠️ LEGAL DISCLAIMER

**THIS TOOL IS FOR AUTHORIZED TESTING ONLY**

This cybersecurity testing tool is designed exclusively for legitimate security professionals, researchers, and system administrators conducting authorized security assessments. 

### Legal Requirements:
- ✅ Written authorization from system owner required
- ✅ Compliance with local and international cybersecurity laws
- ✅ Use only for defensive security purposes
- ✅ Follow responsible disclosure practices

**Unauthorized use is strictly prohibited and may violate laws.**

---

## 🌟 Fonctionnalités

### Modules de Test Disponibles

- **💉 Injection SQL** : Détection des vulnérabilités d'injection SQL avec plus de 10 payloads
- **🔗 Cross-Site Scripting (XSS)** : Test des failles XSS réfléchies
- **🔒 Sécurité des En-têtes** : Analyse des en-têtes de sécurité HTTP manquants ou mal configurés  
- **🔍 Scanner de Ports** : Découverte des ports ouverts et identification des services
- **📁 Découverte de Répertoires** : Énumération des fichiers et dossiers cachés
- **↪️ Open Redirect & Path Traversal** : Détection des redirections ouvertes (GET) et traversal (GET/POST)

### Interfaces Utilisateur

- **🖥️ Menu CLI Interactif** : Interface conviviale avec navigation par menus (recommandé)
- **⌨️ Ligne de Commande** : Interface classique pour l'automatisation et les scripts

### Fonctionnalités Avancées

- 📉 Rapports Détaillés : Génération de rapports HTML et JSON avec graphiques et analyses
- ⚡ Multi-threading : Scans rapides avec support du traitement parallèle
- 🛡️ Rate Limiting : Protection contre la détection avec limitation de débit
- 🧾 Logging Complet : Journalisation détaillée pour le débogage et l'audit
- 🔧 Configuration Flexible : Paramètres personnalisables via fichiers YAML
- 🎛️ Modes d'exécution & rejoue :
  - Rejoue ciblée d'une vulnérabilité détectée ou rejoue de toutes les failles collectées
  - Tentatives automatiques de bypass 403 pendant la rejoue (encodages de chemin, GET/HEAD, en-têtes X-Original-URL/X-Rewrite-URL)
  - Sauvegarde de la réponse brute (HTTP 200) en modes expert/expert-deep dans `reports/executions/raw/` (lien ajouté au rapport)
- 🗂️ Rapports organisés :
  - Scans: `reports/scans/`
  - Rejoues (exécutions): `reports/executions/`
  - Menu « Lire le dernier rapport » détecte automatiquement le type et l'ouvre

### Modes de Payloads (Professionnels)

- Safe: payloads non destructifs, détection prudente
- Normal: safe + variantes supplémentaires (modérées)
- Aggressive: normal + payloads plus intrusifs (toujours sans écriture)
- Expert: ajoute des payloads avancés (extraction de versions, schémas, metadata cloud). Réservé aux périmètres autorisés.
- Expert-deep: inclut des preuves contrôlées (écritures temporaires de marqueurs, lecture étendue). Nécessite autorisation explicite et supervision.

Tous les scanners consomment un catalogue central de payloads par type avec ces niveaux. Les charges lourdes et sensibles sont strictement limitées aux modes Expert/Expert-deep.

## 🚀 Installation et Utilisation

### Prérequis

- Python 3.8 ou supérieur
- pip (gestionnaire de paquets Python)
- Connexion Internet pour l'installation des dépendances

### Installation Rapide

#### Windows (PowerShell)
```powershell
# Cloner ou télécharger le projet
git clone <url-du-repo>
cd cybersec-web-tool

# Lancer l'installation et le menu
.\launch_menu.ps1 -InstallDeps
.\launch_menu.ps1
```

#### Windows (Batch)
```cmd
# Double-cliquer sur launch_menu.bat
# OU en ligne de commande:
launch_menu.bat
```

#### Linux/macOS
```bash
# Cloner ou télécharger le projet
git clone <url-du-repo>
cd cybersec-web-tool

# Rendre le script exécutable et installer
chmod +x launch_menu.sh
./launch_menu.sh --install
./launch_menu.sh
```

### Installation Manuelle

```bash
# Installer les dépendances
pip install -r requirements.txt

# Lancer le menu interactif
python menu_cli.py

# OU utiliser la ligne de commande classique
python main.py --help
```

## 📖 Guide d'Utilisation

### Menu CLI Interactif (Recommandé)

Le menu CLI offre une interface conviviale avec navigation par menus :

1. **🎯 Configurer la cible** : Définir l'URL à tester avec vérification d'autorisation
2. **📦 Sélectionner les modules** : Choisir les tests à effectuer
3. **⚙️ Configurer les paramètres** : Ajuster threads, timeout, mode verbeux
4. **📄 Configurer le rapport** : Choisir le format et l'emplacement du rapport
5. **🚀 Lancer le scan** : Exécuter les tests sélectionnés
6. **ℹ️ Aide et informations** : Documentation et conseils

### Ligne de Commande Classique

```bash
# Scan complet avec tous les modules
python main.py -u https://example.com -m all -o rapport.html

# Test spécifique d'injection SQL
python main.py -u https://example.com -m sql -t 20

# Scan avec paramètres personnalisés
python main.py -u https://example.com -m sql,xss,headers --threads 15 --timeout 30 -o results.json

# Mode verbeux pour le débogage
python main.py -u https://example.com -m all -v
```

### Options de Ligne de Commande

```
Usage: main.py [OPTIONS]

Options:
  -u, --url TEXT           URL cible à scanner (requis)
  -m, --modules TEXT       Modules à utiliser: sql,xss,headers,ports,dirs ou 'all'
  -t, --threads INTEGER    Nombre de threads (défaut: 10)
  --timeout INTEGER        Timeout des requêtes en secondes (défaut: 10)
  -o, --output TEXT        Fichier de sortie (.html ou .json)
  -v, --verbose            Mode verbeux
  --ports TEXT             Ports à scanner (ex: "80,443,8080")
  --config TEXT            Fichier de configuration YAML
  --help                   Afficher cette aide
```

### Exemples

```bash
# Test complet d'une application web
python main.py -u https://testsite.com -m all -o rapport_complet.html

# Test spécifique d'injection SQL
python main.py -u https://testsite.com/login -m sql --threads 10

# Scan de ports avec découverte de services
python main.py -u https://testsite.com -m portscan --ports 1-1000
```

## Structure du projet

```
├── src/
│   ├── scanners/           # Modules de scanning
│   │   ├── sql_injection.py
│   │   ├── xss_scanner.py
│   │   ├── header_security.py
│   │   ├── port_scanner.py
│   │   ├── directory_buster.py
│   │   └── redirect_traversal.py
│   ├── utils/             # Utilitaires
│   │   ├── http_client.py
│   │   ├── logger.py
│   │   └── report_generator.py
│   └── main.py           # Point d'entrée principal
├── config/               # Fichiers de configuration
├── reports/             # Rapports générés
├── tests/              # Tests unitaires
└── requirements.txt    # Dépendances Python
```

## Configuration

Le fichier `config/settings.yml` permet de personnaliser :
- Timeouts et délais
- User-agents et headers
- Dictionnaires d'attaque
- Seuils de détection
- Niveau de payloads (`payload_mode`: safe | normal | aggressive | expert | expert-deep)

## Tests

```bash
# Exécuter tous les tests
python -m pytest tests/

## Bonnes Pratiques et Éthique

- Tests autorisés uniquement; conserver les preuves et rapports pour l’audit
- Limiter la fréquence des requêtes (rate limiting intégré)
- Utiliser les modes Expert/Expert-deep uniquement avec autorisation écrite
- Respecter la divulgation responsable et prévenir l’exploit en production

# Tests avec couverture
python -m pytest tests/ --cov=src
```

Tests rapides du scanner Redirect/Traversal uniquement:

```bash
python -m pytest tests/test_redirect_traversal.py -q
```

Note: Assurez-vous que les dépendances de test (pytest, pytest-cov) sont installées (voir `requirements.txt`).

## Modes de payloads

 - safe: le plus prudent
 - normal: élargi mais non destructif
 - aggressive: ajoute des payloads plus intrusifs (sans expert)
 - expert: catalogue très intrusif (non destructif) pour environnements professionnels autorisés (confirmation requise)
 - expert-deep: extraction exhaustive non destructive, ajoute un catalogue plus profond (voir `docs/EXPERT_MODE.md`)

## Payloads contextuels et preuves visuelles

Vous pouvez cibler des contextes précis et produire des preuves **visuelles et non destructives** sur des environnements autorisés.

Exemples d'utilisation:

```python
from src.utils.payloads import get_contextual_payloads

# XSS: changer la couleur de fond en rouge (preuve visuelle)
payloads = get_contextual_payloads('xss', 'proof-bg-red', mode='safe')

# XSS: afficher une bannière de contrôle
banner_payloads = get_contextual_payloads('xss', 'proof-banner', mode='safe')

# Command Injection: écrire un marqueur inoffensif dans le dossier temp (autorisé uniquement)
cmd_marker = get_contextual_payloads('command injection', 'proof-marker-file', mode='expert-deep')
```

Important:
- Toujours obtenir une autorisation explicite avant d'exécuter des payloads.
- Les preuves visuelles sont conçues pour être **réversibles et non destructives**, mais doivent être utilisées de manière responsable.

## Contribution

1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commiter vos changements
4. Créer une Pull Request

## Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

## Responsabilité légale

L'utilisation de cet outil doit respecter toutes les lois applicables. Les utilisateurs sont entièrement responsables de s'assurer qu'ils ont l'autorisation appropriée avant de tester tout système.