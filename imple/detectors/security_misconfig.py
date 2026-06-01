"""Détecteur A05 - Security Misconfiguration.

Vérifications :
  - Headers de sécurité manquants (X-Content-Type-Options, X-Frame-Options, CSP)
  - Listing de répertoires activé
  - Stack traces / erreurs verbeuses exposées
  - Fichiers sensibles accessibles : /.git/config, /.env, /phpinfo.php,
    /server-status, /config.bak, etc.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from crawler import Endpoint
from scanner.vulnerability import Vulnerability
from .base import BaseDetector, PassiveDetector

SECURITY_HEADERS = {
    "x-content-type-options": "Empêche le MIME-sniffing (doit valoir 'nosniff').",
    "x-frame-options": "Protège contre le clickjacking (DENY/SAMEORIGIN).",
    "content-security-policy": "Limite les sources de scripts et ressources.",
    "referrer-policy": "Contrôle ce qui est envoyé dans le Referer.",
}

DIR_LISTING_MARKERS = ("index of /", "<title>directory listing", "parent directory")

STACK_TRACE_MARKERS = (
    "traceback (most recent call last)",
    "at java.lang.",
    "at org.springframework.",
    "fatal error: uncaught",
    "stack trace:",
    "<h1>server error",
    "nullpointerexception",
)

SENSITIVE_PATHS = [
    (".git/config",           re.compile(r"\[core\]|repositoryformatversion", re.I)),
    (".env",                  re.compile(r"(^|\n)\w+\s*=", re.M)),
    ("phpinfo.php",           re.compile(r"phpinfo\(\)|PHP Version \d", re.I)),
    ("server-status",         re.compile(r"Server Status|Apache Server", re.I)),
    ("config.php.bak",        re.compile(r"<\?php|define\(", re.I)),
    ("backup.zip",            None),  # 200 = présent
    (".DS_Store",             None),
    ("web.config",            re.compile(r"<configuration>", re.I)),
]


class SecurityMisconfigDetector(PassiveDetector):
    name = "Security Misconfiguration"
    owasp_id = "A05"
    payloads_file = None

    _tested_base: set[str] = set()  # cache : on teste les fichiers sensibles une fois par domaine

    def analyze(self, url: str, response) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        # 1) Headers de sécurité manquants (uniquement sur les pages HTML)
        ctype = response.headers.get("Content-Type", "").lower()
        headers_low = {h.lower() for h in response.headers}
        if "html" in ctype:
            for h, reason in SECURITY_HEADERS.items():
                if h not in headers_low:
                    vulns.append(Vulnerability(
                        name=self.name, owasp_id=self.owasp_id, url=url,
                        parameter=f"Header: {h}", payload="(manquant)",
                        evidence=f"Header '{h}' absent. {reason}",
                    ))

        # 2) Listing de répertoires
        body_low = response.text[:2000].lower() if response.text else ""
        for marker in DIR_LISTING_MARKERS:
            if marker in body_low:
                vulns.append(Vulnerability(
                    name=self.name, owasp_id=self.owasp_id, url=url,
                    parameter="(page)", payload="Directory listing",
                    evidence="Listing de répertoire activé : "
                             "exposition de la structure des fichiers.",
                ))
                break

        # 3) Stack traces exposées
        for marker in STACK_TRACE_MARKERS:
            if marker in body_low:
                vulns.append(Vulnerability(
                    name=self.name, owasp_id=self.owasp_id, url=url,
                    parameter="(page)", payload="Stack trace exposée",
                    evidence=f"Trace d'erreur verbeuse divulguée : '{marker}'.",
                ))
                break

        # 4) Fichiers sensibles (testés une seule fois par domaine)
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self._tested_base:
            self._tested_base.add(origin)
            vulns.extend(self._check_sensitive_files(origin))

        return vulns

    def _check_sensitive_files(self, origin: str) -> list[Vulnerability]:
        found: list[Vulnerability] = []
        for path, pattern in SENSITIVE_PATHS:
            full_url = f"{origin}/{path}"
            resp = self._send(full_url, method="GET")
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            # Distinguer une vraie divulgation d'une page d'erreur custom 200
            if pattern is None:
                # 200 suffit
                if len(body) > 0 and "404" not in body.lower()[:200]:
                    found.append(Vulnerability(
                        name=self.name, owasp_id=self.owasp_id, url=full_url,
                        parameter=path, payload="Fichier sensible accessible",
                        evidence=f"Le fichier /{path} est accessible publiquement "
                                 f"(HTTP 200, {len(body)} octets).",
                    ))
            else:
                if pattern.search(body):
                    found.append(Vulnerability(
                        name=self.name, owasp_id=self.owasp_id, url=full_url,
                        parameter=path, payload="Fichier sensible accessible",
                        evidence=f"Le fichier /{path} est exposé et contient "
                                 "des informations sensibles.",
                    ))
        return found
