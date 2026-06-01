"""Détecteur SSRF (OWASP A10)."""
from __future__ import annotations

import re

from crawler import Endpoint
from scanner.vulnerability import Vulnerability
from .base import BaseDetector

INTERNAL_CONTENT_PATTERNS = [
    re.compile(r"root:[^:]*:0:0:", re.IGNORECASE),           # /etc/passwd
    re.compile(r"\[extensions\]", re.IGNORECASE),            # win.ini
    re.compile(r"SSH-2\.0-", re.IGNORECASE),                 # bannière SSH
    re.compile(r"ami-id|instance-id", re.IGNORECASE),        # AWS metadata
    re.compile(r"computeMetadata", re.IGNORECASE),           # GCP metadata
    re.compile(r"Metadata-Flavor", re.IGNORECASE),
]

URL_PARAM_HINTS = ("url", "uri", "link", "src", "dest", "redirect", "fetch",
                   "callback", "domain", "host", "path", "page")


class SSRFDetector(BaseDetector):
    name = "SSRF"
    owasp_id = "A10"
    payloads_file = "ssrf.txt"

    def scan(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        seen_params: set[str] = set()
        for param, method, base in self._iter_injection_points(endpoint):
            if param in seen_params:
                continue
            # Ne tester que les paramètres qui semblent manipuler des URLs
            if not any(h in param.lower() for h in URL_PARAM_HINTS):
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
                for pat in INTERNAL_CONTENT_PATTERNS:
                    m = pat.search(resp.text)
                    if m:
                        vulns.append(
                            Vulnerability(
                                name=self.name,
                                owasp_id=self.owasp_id,
                                url=endpoint.url,
                                parameter=param,
                                payload=payload,
                                evidence=(
                                    f"Contenu interne divulgué : '{m.group(0)[:80]}'"
                                ),
                                method=method,
                            )
                        )
                        seen_params.add(param)
                        break
                if param in seen_params:
                    break
        return vulns
