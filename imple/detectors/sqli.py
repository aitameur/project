"""Détecteur SQL Injection (OWASP A03)."""
from __future__ import annotations

import re
import time

from crawler import Endpoint
from scanner.vulnerability import Vulnerability
from .base import BaseDetector

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysql",
    r"mysql_fetch_array\(\)",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"pg_query\(\):",
    r"postgresql.*error",
    r"syntax error at or near",
    r"microsoft sql server",
    r"odbc.*driver",
    r"sqlite_error",
    r"near \".*\": syntax error",
    r"ora-\d{5}",
]

ERROR_REGEX = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

TIME_BASED_PAYLOADS = [
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR pg_sleep(5)--",
]


class SQLiDetector(BaseDetector):
    name = "SQL Injection"
    owasp_id = "A03"
    payloads_file = "sqli.txt"

    TIME_THRESHOLD = 4.5  # seconds

    def scan(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        baseline = self._baseline(endpoint)

        for param, method, base in self._iter_injection_points(endpoint):
            if self._test_error_based(endpoint, param, method, base, vulns):
                continue
            if self._test_time_based(endpoint, param, method, base, baseline, vulns):
                continue
            self._test_boolean_based(endpoint, param, method, base, baseline, vulns)
        return vulns

    # ── Tests spécialisés ────────────────────────────────────────────────
    def _test_error_based(
        self, endpoint, param, method, base, vulns
    ) -> bool:
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
            match = ERROR_REGEX.search(resp.text)
            if match:
                vulns.append(
                    Vulnerability(
                        name=self.name,
                        owasp_id=self.owasp_id,
                        url=endpoint.url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Erreur SQL détectée : '{match.group(0)}'",
                        method=method,
                    )
                )
                return True
        return False

    def _test_time_based(
        self, endpoint, param, method, base, baseline, vulns
    ) -> bool:
        for payload in TIME_BASED_PAYLOADS:
            data = dict(base)
            data[param] = payload
            start = time.perf_counter()
            resp = self._send(
                endpoint.url,
                method=method,
                params=data if method == "GET" else None,
                data=data if method != "GET" else None,
            )
            elapsed = time.perf_counter() - start
            if resp is None:
                continue
            if elapsed >= self.TIME_THRESHOLD and elapsed > baseline + 3:
                vulns.append(
                    Vulnerability(
                        name=self.name,
                        owasp_id=self.owasp_id,
                        url=endpoint.url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Délai de réponse de {elapsed:.2f}s (référence {baseline:.2f}s)",
                        method=method,
                    )
                )
                return True
        return False

    def _test_boolean_based(
        self, endpoint, param, method, base, baseline_resp, vulns
    ) -> bool:
        true_payload = "' OR '1'='1"
        false_payload = "' AND '1'='2"

        resp_true = self._inject_param(endpoint, param, method, base, true_payload)
        resp_false = self._inject_param(endpoint, param, method, base, false_payload)

        if not resp_true or not resp_false:
            return False

        len_true = len(resp_true.text)
        len_false = len(resp_false.text)
        # Différence marquée = comportement différent selon condition
        if abs(len_true - len_false) > max(200, 0.2 * len_true) and resp_true.status_code == 200:
            vulns.append(
                Vulnerability(
                    name=self.name,
                    owasp_id=self.owasp_id,
                    url=endpoint.url,
                    parameter=param,
                    payload=true_payload,
                    evidence=(
                        f"Différence de longueur de réponse entre TRUE et FALSE "
                        f"({len_true} vs {len_false} octets)"
                    ),
                    method=method,
                )
            )
            return True
        return False

    # ── helpers ──────────────────────────────────────────────────────────
    def _inject_param(self, endpoint, param, method, base, payload):
        data = dict(base)
        data[param] = payload
        return self._send(
            endpoint.url,
            method=method,
            params=data if method == "GET" else None,
            data=data if method != "GET" else None,
        )

    def _baseline(self, endpoint: Endpoint) -> float:
        """Mesure le temps de référence (GET simple sans payload)."""
        start = time.perf_counter()
        self._send(
            endpoint.url,
            method=endpoint.method,
            params=endpoint.params or None,
            data=endpoint.form_fields or None,
        )
        return time.perf_counter() - start
