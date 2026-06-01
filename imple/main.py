"""Scanner de Vulnérabilités Web - OWASP Top 10

Point d'entrée CLI.

Usage :
    python main.py --url http://exemple.com
    python main.py --url http://exemple.com --output rapport.html --depth 3
    python main.py --url http://exemple.com --only sqli,xss -v
"""
from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from pathlib import Path

# Permet d'exécuter le script directement : python main.py
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner import Scanner
from scanner.core import ScanOptions
from detectors import ALL_DETECTORS


BANNER = r"""
 ____   __        __    _    ____  ____   _____            _     _  ___
/ __ \  \ \      / /   / \  / ___||  _ \ |_   _|___  _ __ / |   / |/ _ \
| |  | |  \ \ /\ / /   / _ \ \___ \| |_) |  | | / _ \| '_ \| |   | | | | |
| |  | |   \ V  V /   / ___ \ ___) |  __/   | || (_) | |_) | |   | | |_| |
 \____/     \_/\_/   /_/   \_\____/|_|      |_| \___/| .__/|_|___|_|\___/
                                                     |_|    |___|
         Scanner de Vulnerabilites Web -- PFA EMSI 2024-2025
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scanner de vulnérabilités web basé sur OWASP Top 10",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Détecteurs disponibles : "
            + ", ".join(ALL_DETECTORS.keys())
            + "\n\nExemples :\n"
            "  python main.py --url http://127.0.0.1:5000\n"
            "  python main.py --url http://cible --only sqli,xss --depth 1 -v\n\n"
            "ATTENTION : cet outil ne doit être utilisé que sur des applications "
            "dont vous avez l'autorisation explicite de tester la sécurité."
        ),
    )
    parser.add_argument("--url", required=True, help="URL cible du scan")
    parser.add_argument(
        "--output", default="rapport.html", help="Chemin du rapport HTML (défaut : rapport.html)"
    )
    parser.add_argument(
        "--depth", type=int, default=2, help="Profondeur de crawl (défaut : 2)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="Timeout HTTP en secondes (défaut : 10)"
    )
    parser.add_argument(
        "--max-pages", type=int, default=100,
        help="Nombre maximal de pages à crawler (défaut : 100)"
    )
    parser.add_argument(
        "--only", default="",
        help="Liste de détecteurs à activer, séparés par des virgules (ex: sqli,xss)"
    )
    parser.add_argument(
        "--cookie", default="",
        help=(
            "Cookies à envoyer avec chaque requête (utile pour scanner une app "
            "authentifiée). Ex: 'PHPSESSID=abc; security=low'"
        ),
    )
    # ── Auto-login ─────────────────────────────────────────────────────
    parser.add_argument(
        "--dvwa", action="store_true",
        help=(
            "Raccourci DVWA : auto-login (admin/password par défaut) + "
            "bascule sur security=low. Plus besoin de --cookie."
        ),
    )
    parser.add_argument(
        "--login-url", default="",
        help="URL du formulaire de login (mode générique, à utiliser avec --username/--password)",
    )
    parser.add_argument(
        "--username", default="",
        help="Nom d'utilisateur pour l'auto-login (défaut DVWA : admin)",
    )
    parser.add_argument(
        "--password", default="",
        help="Mot de passe pour l'auto-login (défaut DVWA : password)",
    )
    parser.add_argument(
        "--dvwa-security", default="low", choices=["low", "medium", "high", "impossible"],
        help="Niveau de sécurité DVWA à activer (défaut : low)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Logs détaillés"
    )
    return parser.parse_args()


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="[%(asctime)s] %(levelname)-7s %(name)-20s %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )


def print_summary(vulns: list, report_path: Path, duration: float) -> None:
    counts = Counter(v.severity for v in vulns)
    print("\n" + "=" * 60)
    print(f"  Scan terminé en {duration:.2f}s")
    print("=" * 60)
    print(f"  Total vulnérabilités : {len(vulns)}")
    for sev in ("Critique", "Élevé", "Moyen", "Faible"):
        if counts.get(sev):
            print(f"    - {sev:<10} : {counts[sev]}")
    print(f"\n  Rapport HTML : {report_path}")
    print("=" * 60 + "\n")


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    print(BANNER)

    only = [d.strip() for d in args.only.split(",") if d.strip()]
    options = ScanOptions(
        output=args.output,
        depth=args.depth,
        timeout=args.timeout,
        max_pages=args.max_pages,
        only=only,
        verbose=args.verbose,
        cookie=args.cookie,
        login_url=args.login_url,
        username=args.username,
        password=args.password,
        dvwa=args.dvwa,
        dvwa_security=args.dvwa_security,
    )

    scanner = Scanner(args.url, options)
    try:
        vulns = scanner.run()
    except KeyboardInterrupt:
        print("\nScan interrompu par l'utilisateur.")
        return 130
    except Exception as exc:
        logging.error("Erreur fatale : %s", exc, exc_info=args.verbose)
        return 1

    print_summary(vulns, scanner.get_report(), scanner.duration)
    return 0


if __name__ == "__main__":
    sys.exit(main())
