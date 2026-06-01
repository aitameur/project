"""Détecteur A08 - Software and Data Integrity Failures.

Contrôle principal : les ressources JavaScript/CSS chargées depuis une origine
externe (CDN) doivent déclarer un attribut `integrity="sha..."` (SRI). Sans SRI,
une compromission du CDN permet l'injection de code arbitraire dans le client.
"""
from __future__ import annotations

from urllib.parse import urlparse

from bs4 import BeautifulSoup

from scanner.vulnerability import Vulnerability
from .base import PassiveDetector


class IntegrityDetector(PassiveDetector):
    name = "Software & Data Integrity"
    owasp_id = "A08"
    payloads_file = None

    _reported_resources: set[tuple[str, str]] = set()

    def analyze(self, url: str, response) -> list[Vulnerability]:
        ctype = response.headers.get("Content-Type", "").lower()
        if "html" not in ctype or not response.text:
            return []
        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            return []

        page_host = urlparse(url).netloc
        vulns: list[Vulnerability] = []

        # <script src="https://cdn..."> sans integrity
        for tag in soup.find_all(["script", "link"]):
            if tag.name == "script":
                src = tag.get("src")
                rel_attr = None
            else:
                src = tag.get("href")
                rel_attr = (tag.get("rel") or [""])
                if isinstance(rel_attr, list):
                    rel_attr = rel_attr[0] if rel_attr else ""
                if "stylesheet" not in str(rel_attr).lower():
                    continue
            if not src:
                continue
            src_host = urlparse(src).netloc
            if not src_host or src_host == page_host:
                continue  # ressource locale : SRI optionnel
            if tag.get("integrity"):
                continue  # SRI présent : OK
            key = (url, src)
            if key in self._reported_resources:
                continue
            self._reported_resources.add(key)
            vulns.append(Vulnerability(
                name=self.name, owasp_id=self.owasp_id, url=url,
                parameter=f"{tag.name}[src|href]",
                payload=src,
                evidence=(
                    f"Ressource externe chargée depuis {src_host} sans "
                    "attribut 'integrity' (Subresource Integrity). "
                    "Une compromission du CDN permettrait l'exécution de "
                    "code arbitraire dans les navigateurs des utilisateurs."
                ),
            ))
        return vulns
