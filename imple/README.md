# Scanner de Vulnérabilités Web — OWASP Top 10

Projet de Fin d'Année (PFA) — Salma El Kamili & Fatima Ezzahrae Nouama.

Outil Python en ligne de commande qui scanne une application web à la
recherche des vulnérabilités les plus courantes du **OWASP Top 10 2021** :
**SQLi, XSS, SSRF, IDOR, Path Traversal, XXE**. Chaque faille détectée est
notée selon **CVSS v3.1** et un **rapport HTML** autonome est généré.

## Avertissement

Cet outil effectue des tests **actifs** (envoi de payloads). Il ne doit être
utilisé **que** sur des applications dont vous avez l'autorisation explicite
de tester la sécurité (votre propre environnement, une instance DVWA/WebGoat,
un programme de bug bounty autorisant les scans automatisés, etc.).

## Installation

```bash
cd imple
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

Python 3.10+ requis.

## Utilisation

```bash
# Scan complet
python main.py --url http://127.0.0.1:5000

# Scan ciblé (uniquement SQLi et XSS)
python main.py --url http://127.0.0.1:5000 --only sqli,xss

# Réglages avancés
python main.py --url http://cible --depth 3 --timeout 15 --output mon_rapport.html -v
```

### Options

| Option | Défaut | Description |
|---|---|---|
| `--url` | *(requis)* | URL cible |
| `--output` | `rapport.html` | Chemin du rapport HTML |
| `--depth` | `2` | Profondeur maximale du crawl |
| `--timeout` | `10` | Timeout HTTP (secondes) |
| `--max-pages` | `100` | Nombre maximum de pages crawlées |
| `--only` | *(tous)* | Liste de détecteurs : `sqli,xss,ssrf,idor,path_traversal,xxe` |
| `-v`, `--verbose` | `false` | Logs détaillés |

## Architecture

```
imple/
├── main.py              # CLI (argparse)
├── scanner/             # Orchestrateur + modèle Vulnerability
├── crawler/             # BFS, découverte d'endpoints et de formulaires
├── detectors/           # 6 détecteurs spécialisés
├── evaluator/           # Scoring CVSS v3.1
├── reporter/            # Génération HTML
├── payloads/            # Listes de payloads (SQLi, XSS, SSRF, Path, XXE)
└── tests/               # pytest + app Flask volontairement vulnérable
```

Pipeline : `Crawler` → `Detectors` → `CVSSEvaluator` → `HTMLReporter`.

## Tests

Tous les tests utilisent une application Flask **volontairement vulnérable**
lancée en mémoire par la fixture `vulnerable_app` :

```bash
cd imple
pytest -v
```

## Environnements de test recommandés

- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application
- [WebGoat](https://owasp.org/www-project-webgoat/) — OWASP WebGoat
- L'app Flask de test locale (fixture `vulnerable_app`)

## Références

- OWASP Top 10 — <https://owasp.org/Top10/>
- CVSS v3.1 — <https://www.first.org/cvss/v3.1/specification-document>
