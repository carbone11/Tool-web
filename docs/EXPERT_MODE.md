# Modes EXPERT et EXPERT-DEEP — Payloads très intrusifs (non destructifs)

Attention: usage strictement réservé aux environnements autorisés et contrôlés (contrat écrit, périmètre défini, fenêtre de tir validée). Les payloads EXPERT/EXPERT-DEEP peuvent divulguer des informations sensibles (versions système/DB, chemins, cookies) et contacter des services internes (métadonnées cloud). L'objectif reste la preuve de contrôle sans action destructive.

## Ce que fait le mode EXPERT

## Ce que fait le mode EXPERT-DEEP

## Payloads contextuels (nouveaux)

Les payloads contextuels permettent d'aligner les injections sur des sinks spécifiques et de produire des **preuves visuelles non destructives**.

### XSS (preuves visuelles)
- `proof-bg-red`: change le fond de la page en rouge
- `proof-banner`: ajoute une bannière fixe « XSS CONTROL » en haut de page
- `proof-title`: remplace le titre de l'onglet

Usage:
```python
from src.utils.payloads import get_contextual_payloads
get_contextual_payloads('xss', 'proof-bg-red', mode='safe')
get_contextual_payloads('xss', 'proof-banner', mode='safe')
get_contextual_payloads('xss', 'proof-title', mode='safe')
```

### Command Injection (marqueur temporaire)
- `proof-marker-file`: écrit un fichier marqueur inoffensif dans le répertoire temporaire

Usage (environnements autorisés):
```python
get_contextual_payloads('command injection', 'proof-marker-file', mode='expert-deep')
```

> Note: Les preuves doivent être utilisées uniquement avec autorisation explicite. Éviter toute action irréversible.
## Déclenchement dans l'outil

## Rejoue: Bypass 403 et capture brute (expert/expert-deep)
- Lors de la rejoue d'une vulnérabilité en mode EXPERT/EXPERT-DEEP, l'outil:
	- Tente des variantes de contournement 403 (chemins encodés, méthodes GET/HEAD, en-têtes X-Original-URL/X-Rewrite-URL, etc.) et indique le nombre de succès dans le rapport.
	- Sauvegarde la réponse brute (body) pour toute réponse HTTP 200 dans: `reports/executions/raw/` (fichier binaire `raw_<type>_<timestamp>_<hash>.bin`). Le rapport HTML ajoute un lien vers cet artefact.
- La prévisualisation de réponse est allongée (extrait plus grand) en modes EXPERT/EXPERT-DEEP pour faciliter l'analyse.

## Bonnes pratiques
- Obtenir l'autorisation écrite et préciser l'impact attendu.
- Limiter la fenêtre de tir et le périmètre réseau.
- Activer un rate limiting et une journalisation fine.
- Préférer des heures creuses pour limiter l'impact.
- Conserver les artefacts bruts uniquement dans un environnement sécurisé (contient potentiellement des données sensibles).

## Sortie et traces
- Les rapports HTML/JSON incluent l'information du mode de payloads employé.
- Le rapport d'exécution (rejoue) affiche: résumé des tentatives de contournement 403 et lien vers l'artefact brut si présent.
- Certains payloads (p. ex. SSRF metadata) peuvent ne rien retourner si l'environnement n'est pas concerné — c'est attendu.

## Désactivation ciblée
- Si nécessaire, restez en `normal`/`aggressive` pour un type particulier et passez en `expert`/`expert-deep` ponctuellement pour la rejoue.

