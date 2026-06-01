"""Détecteur A06 - Vulnerable and Outdated Components.

On fingerprinte les versions divulguées par :
  - Server: (Apache/2.4.25, nginx/1.14.0, ...)
  - X-Powered-By: (PHP/7.0.30, Express, ...)
  - <meta name="generator" content="WordPress 5.2">
  - Scripts JS avec version dans l'URL : jquery-3.3.1.min.js

Chaque version divulguée est reportée comme faible-moyenne : l'outil n'interroge
pas une base CVE mais signale que l'information versionnée devrait être masquée
et qu'il faut vérifier la présence de CVEs sur cette version.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from scanner.vulnerability import Vulnerability
from .base import PassiveDetector

# Régex pour capter "nom/version" ou "nom version" dans les headers
VERSION_REGEX = re.compile(r"([A-Za-z][\w\-.]+)[/ ](\d+(?:\.\d+)+)")

# Fichiers JS fréquents avec version : jquery-3.5.1.min.js, bootstrap-4.0.0.js...
JS_VERSION_REGEX = re.compile(
    r"(jquery|bootstrap|angular|react|vue|lodash|backbone|moment|handlebars)[.\-_]"
    r"v?(\d+(?:\.\d+)+)",
    re.IGNORECASE,
)


class VulnerableComponentsDetector(PassiveDetector):
    name = "Vulnerable Components"
    owasp_id = "A06"
    payloads_file = None

    _reported: set[tuple[str, str, str]] = set()

    def analyze(self, url: str, response) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        # 1) Fingerprint des headers Server / X-Powered-By
        for header in ("Server", "X-Powered-By"):
            val = response.headers.get(header)
            if not val:
                continue
            for component, version in VERSION_REGEX.findall(val):
                key = (origin, component.lower(), version)
                if key in self._reported:
                    continue
                self._reported.add(key)
                vulns.append(Vulnerability(
                    name=self.name, owasp_id=self.owasp_id, url=url,
                    parameter=header, payload=f"{component}/{version}",
                    evidence=(
                        f"Le header {header} divulgue '{component} {version}'. "
                        f"Vérifiez les CVE connues pour cette version et masquez "
                        f"cette information en production."
                    ),
                ))

        # 2) Meta generator dans le HTML
        ctype = response.headers.get("Content-Type", "").lower()
        if "html" in ctype and response.text:
            try:
                soup = BeautifulSoup(response.text, "html.parser")
            except Exception:
                soup = None
            if soup is not None:
                meta = soup.find("meta", attrs={"name": "generator"})
                if meta and meta.get("content"):
                    content = meta["content"]
                    for m in VERSION_REGEX.finditer(content):
                        component, version = m.group(1), m.group(2)
                        key = (origin, component.lower(), version)
                        if key in self._reported:
                            continue
                        self._reported.add(key)
                        vulns.append(Vulnerability(
                            name=self.name, owasp_id=self.owasp_id, url=url,
                            parameter="meta:generator",
                            payload=f"{component}/{version}",
                            evidence=f"Balise meta 'generator' : {content}",
                        ))

                # 3) Bibliothèques JS versionnées
                for script in soup.find_all("script", src=True):
                    src = script.get("src", "")
                    m = JS_VERSION_REGEX.search(src)
                    if not m:
                        continue
                    component, version = m.group(1).lower(), m.group(2)
                    key = (origin, component, version)
                    if key in self._reported:
                        continue
                    self._reported.add(key)
                    vulns.append(Vulnerability(
                        name=self.name, owasp_id=self.owasp_id, url=url,
                        parameter=f"script: {src}",
                        payload=f"{component}/{version}",
                        evidence=(
                            f"Bibliothèque JavaScript '{component}' version {version} "
                            "chargée — vérifiez les CVE (ex: snyk.io/advisor)."
                        ),
                    ))
        return vulns
