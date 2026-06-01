"""Détecteur Path Traversal (OWASP A01)."""
from __future__ import annotations

import re

from crawler import Endpoint
from scanner.vulnerability import Vulnerability
from .base import BaseDetector

SIGNATURES = [
    (re.compile(r"root:[^:]*:0:0:", re.IGNORECASE), "Contenu de /etc/passwd"),
    (re.compile(r"\[fonts\]|\[extensions\]", re.IGNORECASE), "Contenu de win.ini"),
    (re.compile(r"daemon:|bin:|sys:", re.IGNORECASE), "Utilisateurs système Unix"),
]

FILE_PARAM_HINTS = ("file", "path", "page", "doc", "folder", "filename",
                    "include", "download", "read", "view", "template")


class PathTraversalDetector(BaseDetector):
    name = "Path Traversal"
    owasp_id = "A01"
    payloads_file = "path_traversal.txt"

    def scan(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen_params: set[str] = set()
        for param, method, base in self._iter_injection_points(endpoint):
            if param in seen_params:
                continue
            if not any(h in param.lower() for h in FILE_PARAM_HINTS):
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
                for pattern, label in SIGNATURES:
                    if pattern.search(resp.text):
                        vulns.append(
                            Vulnerability(
                                name=self.name,
                                owasp_id=self.owasp_id,
                                url=endpoint.url,
                                parameter=param,
                                payload=payload,
                                evidence=f"{label} divulgué dans la réponse.",
                                method=method,
                            )
                        )
                        seen_params.add(param)
                        break
                if param in seen_params:
                    break
        return vulns
