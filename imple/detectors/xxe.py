"""Détecteur XXE - XML External Entity (OWASP A05)."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from crawler import Endpoint
from scanner.vulnerability import Vulnerability
from .base import BaseDetector, PAYLOADS_DIR

logger = logging.getLogger(__name__)

SIGNATURES = [
    re.compile(r"root:[^:]*:0:0:", re.IGNORECASE),
    re.compile(r"\[fonts\]|\[extensions\]", re.IGNORECASE),
]


def _load_xxe_payloads() -> list[str]:
    """Payloads XXE multi-lignes séparés par '===' en début de ligne."""
    path = PAYLOADS_DIR / "xxe.txt"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    blocks = re.split(r"(?m)^===\s*$", text)
    payloads: list[str] = []
    for block in blocks:
        # Retirer les commentaires de début
        lines = [ln for ln in block.splitlines() if not ln.strip().startswith("#")]
        payload = "\n".join(lines).strip()
        if payload:
            payloads.append(payload)
    return payloads


class XXEDetector(BaseDetector):
    name = "XXE"
    owasp_id = "A05"
    payloads_file = None  # surchargé

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.payloads = _load_xxe_payloads()

    def scan(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        # XXE ne s'attaque qu'aux endpoints POST qui pourraient accepter du XML
        if endpoint.method.upper() not in ("POST", "PUT"):
            return vulns
        for payload in self.payloads:
            resp = self._send(
                endpoint.url,
                method=endpoint.method,
                data=payload,
                headers={"Content-Type": "application/xml"},
            )
            if resp is None:
                continue
            for pattern in SIGNATURES:
                if pattern.search(resp.text):
                    vulns.append(
                        Vulnerability(
                            name=self.name,
                            owasp_id=self.owasp_id,
                            url=endpoint.url,
                            parameter="<body>",
                            payload=payload[:200],
                            evidence="Contenu d'un fichier local divulgué via entité XML externe.",
                            method=endpoint.method,
                        )
                    )
                    return vulns
        return vulns
