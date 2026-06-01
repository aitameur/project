"""Détecteur Cross-Site Scripting réfléchi (OWASP A03)."""
from __future__ import annotations

import html

from crawler import Endpoint
from scanner.vulnerability import Vulnerability
from .base import BaseDetector


class XSSDetector(BaseDetector):
    name = "Cross-Site Scripting"
    owasp_id = "A03"
    payloads_file = "xss.txt"

    def scan(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen_params: set[str] = set()
        for param, method, base in self._iter_injection_points(endpoint):
            if param in seen_params:
                continue
            for payload in self.payloads:
                data = dict(base)
                data[param] = payload
                resp = self._send(
                    endpoint.url,
                    method=method,
                    params=data if method == "GET" else None,
                    data=data if method != "GET" else None,
                )
                if resp is None:
                    continue
                # Réflexion brute (non-échappée) = XSS confirmé
                if payload in resp.text and html.escape(payload) != payload:
                    vulns.append(
                        Vulnerability(
                            name=self.name,
                            owasp_id=self.owasp_id,
                            url=endpoint.url,
                            parameter=param,
                            payload=payload,
                            evidence=(
                                "Le payload est réfléchi tel quel dans la réponse "
                                "(pas d'échappement HTML)."
                            ),
                            method=method,
                        )
                    )
                    seen_params.add(param)
                    break
        return vulns
