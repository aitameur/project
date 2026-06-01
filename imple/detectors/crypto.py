"""Détecteur A02 - Cryptographic Failures.

Vérifications passives :
  - Page avec formulaire de mot de passe servie en HTTP (pas HTTPS)
  - Absence du header Strict-Transport-Security (HSTS) sur HTTPS
  - Cookies sans flag Secure ou HttpOnly
  - Identifiants/tokens passés en paramètre GET de l'URL
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup

from scanner.vulnerability import Vulnerability
from .base import PassiveDetector

SENSITIVE_PARAMS = ("password", "pwd", "pass", "token", "apikey",
                    "api_key", "secret", "auth", "session")


class CryptographicFailuresDetector(PassiveDetector):
    name = "Cryptographic Failures"
    owasp_id = "A02"
    payloads_file = None

    def analyze(self, url: str, response) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        parsed = urlparse(url)
        is_https = parsed.scheme == "https"

        # 1) Formulaire de login en HTTP clair
        if not is_https:
            try:
                soup = BeautifulSoup(response.text, "html.parser")
            except Exception:
                soup = None
            if soup and soup.find("input", {"type": "password"}):
                vulns.append(Vulnerability(
                    name=self.name, owasp_id=self.owasp_id, url=url,
                    parameter="(page)", payload="HTTP en clair",
                    evidence="Formulaire contenant un champ <input type=\"password\"> "
                             "servi en HTTP (non chiffré) : les identifiants "
                             "transitent en clair sur le réseau.",
                ))

        # 2) HSTS manquant sur HTTPS
        if is_https and "strict-transport-security" not in {h.lower() for h in response.headers}:
            vulns.append(Vulnerability(
                name=self.name, owasp_id=self.owasp_id, url=url,
                parameter="HSTS", payload="(header manquant)",
                evidence="Header Strict-Transport-Security absent : le navigateur "
                         "ne force pas HTTPS sur les visites suivantes.",
            ))

        # 3) Cookies sans Secure / HttpOnly
        set_cookies = response.headers.get_list("Set-Cookie") \
            if hasattr(response.headers, "get_list") else []
        if not set_cookies:
            # fallback pour certaines versions de requests
            raw = response.headers.get("Set-Cookie")
            set_cookies = [raw] if raw else []
        for c in set_cookies:
            low = c.lower()
            if "session" in low or "phpsessid" in low or "auth" in low:
                missing = []
                if "secure" not in low and is_https:
                    missing.append("Secure")
                if "httponly" not in low:
                    missing.append("HttpOnly")
                if missing:
                    vulns.append(Vulnerability(
                        name=self.name, owasp_id=self.owasp_id, url=url,
                        parameter="Set-Cookie",
                        payload=c.split(";")[0],
                        evidence=f"Cookie de session sans flag(s) : {', '.join(missing)}",
                    ))

        # 4) Identifiants en paramètre d'URL
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for param in qs:
            if param.lower() in SENSITIVE_PARAMS:
                vulns.append(Vulnerability(
                    name=self.name, owasp_id=self.owasp_id, url=url,
                    parameter=param, payload="(paramètre GET)",
                    evidence=f"Donnée sensible '{param}' passée en paramètre GET : "
                             "apparaît dans les logs serveur, l'historique du "
                             "navigateur et le Referer.",
                ))

        # Déduplication locale (même type de check peut matcher plusieurs fois)
        return _dedupe(vulns)


def _dedupe(vulns: list[Vulnerability]) -> list[Vulnerability]:
    seen = set()
    out = []
    for v in vulns:
        key = (v.parameter, v.evidence[:50])
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out
