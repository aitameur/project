"""Classe de base pour tous les détecteurs de vulnérabilités."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

import requests

from crawler import Endpoint
from scanner.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

PAYLOADS_DIR = Path(__file__).resolve().parent.parent / "payloads"

USER_AGENT = "OWASP-Top10-Scanner/1.0 (PFA-EMSI)"


def load_payloads(filename: str) -> list[str]:
    """Charge les payloads depuis `payloads/<filename>`. Ignore lignes vides et commentaires."""
    path = PAYLOADS_DIR / filename
    if not path.exists():
        logger.warning("Fichier de payloads introuvable : %s", path)
        return []
    payloads: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        payloads.append(line)
    return payloads


class BaseDetector:
    """Classe abstraite : chaque détecteur implémente `scan`."""

    name: str = "Vulnerability"
    owasp_id: str = "Axx"
    payloads_file: str | None = None

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: int = 10,
        verbose: bool = False,
    ):
        self.session = session or self._build_session()
        self.timeout = timeout
        self.verbose = verbose
        self.payloads: list[str] = (
            load_payloads(self.payloads_file) if self.payloads_file else []
        )

    @staticmethod
    def _build_session() -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        return session

    # ── helpers partagés ────────────────────────────────────────────────
    def _send(
        self,
        url: str,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> requests.Response | None:
        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True,
                **kwargs,
            )
            return resp
        except requests.RequestException as exc:
            logger.debug("Erreur réseau sur %s : %s", url, exc)
            return None

    def _iter_injection_points(
        self, endpoint: Endpoint
    ) -> Iterable[tuple[str, str, dict[str, Any]]]:
        """Yield (parameter_name, method, base_data_or_params) pour chaque champ injectable."""
        if endpoint.method.upper() == "GET":
            if not endpoint.params:
                return
            for param in endpoint.params:
                base = dict(endpoint.params)
                yield param, "GET", base
        else:
            for param in endpoint.form_fields:
                base = dict(endpoint.form_fields)
                yield param, endpoint.method.upper(), base

    # ── API ─────────────────────────────────────────────────────────────
    def scan(self, endpoint: Endpoint) -> list[Vulnerability]:
        raise NotImplementedError

    def scan_all(self, endpoints: list[Endpoint]) -> list[Vulnerability]:
        results: list[Vulnerability] = []
        for ep in endpoints:
            try:
                results.extend(self.scan(ep))
            except Exception as exc:
                logger.warning(
                    "Erreur dans %s sur %s : %s", self.name, ep.url, exc
                )
        return results


class PassiveDetector(BaseDetector):
    """Détecteur qui analyse les réponses sans injection de payload.

    Déduplique par URL pour ne pas refaire la même requête plusieurs fois.
    Les sous-classes implémentent `analyze(url, response)`.
    """

    def scan(self, endpoint: Endpoint) -> list[Vulnerability]:
        resp = self._send(endpoint.url, method="GET")
        if resp is None:
            return []
        return self.analyze(endpoint.url, resp)

    def scan_all(self, endpoints: list[Endpoint]) -> list[Vulnerability]:
        results: list[Vulnerability] = []
        seen: set[str] = set()
        for ep in endpoints:
            if ep.url in seen:
                continue
            seen.add(ep.url)
            try:
                results.extend(self.scan(ep))
            except Exception as exc:
                logger.warning(
                    "Erreur dans %s sur %s : %s", self.name, ep.url, exc
                )
        return results

    def analyze(self, url: str, response) -> list[Vulnerability]:
        raise NotImplementedError
