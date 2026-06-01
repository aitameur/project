"""Module d'évaluation CVSS v3.1.

Chaque type de vulnérabilité est associé à un vecteur CVSS v3.1 et à un score
de base standard (aligné sur les fiches CWE/OWASP). La sévérité est déterminée
selon les seuils officiels CVSS v3.1 :

    Critique : 9.0 - 10.0
    Élevé    : 7.0 -  8.9
    Moyen    : 4.0 -  6.9
    Faible   : 0.1 -  3.9
"""
from __future__ import annotations

from dataclasses import dataclass

from scanner.vulnerability import Vulnerability


@dataclass(frozen=True)
class CVSSProfile:
    vector: str
    score: float
    recommendation: str


CVSS_PROFILES: dict[str, CVSSProfile] = {
    "SQL Injection": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        score=9.8,
        recommendation=(
            "Utiliser des requêtes paramétrées (prepared statements) ou un ORM. "
            "Valider et échapper toutes les entrées utilisateur. Appliquer le "
            "principe du moindre privilège sur le compte de base de données."
        ),
    ),
    "Cross-Site Scripting": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        score=6.1,
        recommendation=(
            "Échapper systématiquement les sorties HTML (encodage contextuel). "
            "Utiliser une Content-Security-Policy (CSP) stricte. Valider les "
            "entrées côté serveur et utiliser des frameworks qui échappent "
            "automatiquement le HTML."
        ),
    ),
    "SSRF": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
        score=8.5,
        recommendation=(
            "Mettre en place une liste blanche (allowlist) des domaines et IPs "
            "autorisés. Interdire les accès à 127.0.0.1, 169.254.169.254 "
            "(métadonnées cloud), et aux plages privées. Désactiver les "
            "schémas dangereux (file://, gopher://, dict://)."
        ),
    ),
    "IDOR": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        score=6.5,
        recommendation=(
            "Vérifier systématiquement les autorisations côté serveur pour chaque "
            "accès à une ressource. Utiliser des identifiants opaques (UUID) "
            "plutôt que des ID incrémentaux. Implémenter un contrôle d'accès "
            "basé sur les rôles (RBAC)."
        ),
    ),
    "Path Traversal": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        score=7.5,
        recommendation=(
            "Normaliser et valider les chemins de fichiers reçus. Interdire les "
            "séquences '../'. Utiliser une liste blanche de fichiers/répertoires "
            "autorisés. Chroot/sandbox le processus servant les fichiers."
        ),
    ),
    "XXE": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
        score=8.2,
        recommendation=(
            "Désactiver le traitement des entités externes (DTD) dans le parser "
            "XML. Préférer des formats plus simples (JSON) quand possible. "
            "Utiliser defusedxml en Python pour éviter les XXE."
        ),
    ),
    "Unrestricted File Upload": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        score=8.8,
        recommendation=(
            "Valider rigoureusement le type de fichier côté serveur (extension ET "
            "magic bytes). Utiliser une liste blanche d'extensions. Stocker les "
            "fichiers en dehors du webroot ou sur un domaine différent. Renommer "
            "les fichiers uploadés avec des noms aléatoires. Désactiver "
            "l'exécution des scripts dans le répertoire d'upload."
        ),
    ),
    "Cryptographic Failures": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        score=7.5,
        recommendation=(
            "Servir toutes les pages sensibles exclusivement en HTTPS. Activer "
            "HSTS (Strict-Transport-Security). Marquer les cookies de session "
            "avec les flags Secure + HttpOnly + SameSite. Ne jamais transmettre "
            "d'identifiants ou de tokens en paramètre GET."
        ),
    ),
    "Security Misconfiguration": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        score=5.3,
        recommendation=(
            "Renforcer les headers HTTP de sécurité (X-Content-Type-Options, "
            "X-Frame-Options, Content-Security-Policy, Referrer-Policy). "
            "Désactiver le listing de répertoires. Masquer les traces d'erreurs "
            "en production. Refuser l'accès HTTP aux fichiers sensibles "
            "(.git, .env, phpinfo.php, backup.*)."
        ),
    ),
    "Vulnerable Components": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        score=5.3,
        recommendation=(
            "Masquer les bannières de version (directives ServerTokens Prod, "
            "expose_php=Off). Maintenir un inventaire des composants et "
            "vérifier régulièrement les CVE sur NVD / snyk.io. Appliquer les "
            "correctifs de sécurité dès leur publication."
        ),
    ),
    "Authentication Failures": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        score=9.8,
        recommendation=(
            "Interdire les mots de passe par défaut et imposer une politique "
            "forte dès le premier login. Implémenter un rate limiting et un "
            "blocage après N tentatives. Utiliser POST (jamais GET) pour les "
            "formulaires de login. Activer l'authentification multi-facteurs."
        ),
    ),
    "Software & Data Integrity": CVSSProfile(
        vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        score=4.8,
        recommendation=(
            "Ajouter l'attribut 'integrity' (Subresource Integrity, SRI) sur "
            "toutes les ressources <script> et <link rel=\"stylesheet\"> chargées "
            "depuis une origine externe. Vérifier la signature des dépendances "
            "et des mises à jour (chaîne d'approvisionnement)."
        ),
    ),
}


def get_severity(score: float) -> str:
    """Retourne le niveau de sévérité selon les seuils CVSS v3.1."""
    if score >= 9.0:
        return "Critique"
    if score >= 7.0:
        return "Élevé"
    if score >= 4.0:
        return "Moyen"
    if score > 0.0:
        return "Faible"
    return "Aucun"


class CVSSEvaluator:
    """Attribue à chaque vulnérabilité un score CVSS, un vecteur et une recommandation."""

    def evaluate(self, vuln: Vulnerability) -> Vulnerability:
        profile = CVSS_PROFILES.get(vuln.name)
        if profile is None:
            vuln.cvss_score = 5.0
            vuln.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
            vuln.recommendation = (
                "Vulnérabilité générique détectée. Consulter la documentation "
                "OWASP Top 10 pour les contre-mesures adaptées."
            )
        else:
            vuln.cvss_score = profile.score
            vuln.cvss_vector = profile.vector
            if not vuln.recommendation:
                vuln.recommendation = profile.recommendation
        vuln.severity = get_severity(vuln.cvss_score)
        return vuln

    def evaluate_all(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        return [self.evaluate(v) for v in vulns]
