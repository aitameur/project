"""Orchestrateur principal : crawl -> détection -> évaluation -> rapport."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

from crawler import Crawler, Endpoint
from detectors import ALL_DETECTORS, PassiveDetector
from evaluator import CVSSEvaluator
from reporter import HTMLReporter
from .authenticator import login_dvwa, login_form_based
from .vulnerability import Vulnerability

logger = logging.getLogger(__name__)

USER_AGENT = "OWASP-Top10-Scanner/1.0 (PFA-EMSI)"


@dataclass
class ScanOptions:
    output: str = "rapport.html"
    depth: int = 2
    timeout: int = 10
    max_pages: int = 100
    only: list[str] = field(default_factory=list)  # nom des détecteurs, ex ['sqli','xss']
    verbose: bool = False
    cookie: str = ""  # ex: "PHPSESSID=xxx; security=low"
    extra_headers: dict[str, str] = field(default_factory=dict)
    # Auto-login
    login_url: str = ""            # URL du formulaire de login (mode générique)
    username: str = ""
    password: str = ""
    dvwa: bool = False             # Mode DVWA : login + security=low
    dvwa_security: str = "low"     # niveau de sécurité DVWA à régler


class Scanner:
    def __init__(self, url: str, options: ScanOptions | None = None):
        self.url = url
        self.options = options or ScanOptions()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        if self.options.cookie:
            self.session.headers["Cookie"] = self.options.cookie
        if self.options.extra_headers:
            self.session.headers.update(self.options.extra_headers)
        self.vulnerabilities: list[Vulnerability] = []
        self.pages_scanned = 0
        self.duration = 0.0
        self._report_path: Path | None = None

    def run(self) -> list[Vulnerability]:
        start = time.perf_counter()
        logger.info("Démarrage du scan sur %s", self.url)

        # 0) Auto-login éventuel
        self._maybe_login()

        # 1) Crawl
        crawler = Crawler(
            base_url=self.url,
            max_depth=self.options.depth,
            max_pages=self.options.max_pages,
            timeout=self.options.timeout,
            session=self.session,
            verbose=self.options.verbose,
        )
        endpoints = crawler.crawl()
        self.pages_scanned = len(crawler.visited)
        logger.info("%d endpoints à tester", len(endpoints))

        # Les détecteurs passifs s'intéressent à toutes les pages visitées,
        # pas seulement à celles avec des paramètres injectables.
        endpoint_urls = {ep.url for ep in endpoints}
        passive_endpoints: list[Endpoint] = list(endpoints)
        # S'assurer que l'URL cible est toujours incluse, même si le crawl a
        # été redirigé (cas DVWA où la page demandée n'est pas dans visited).
        for extra_url in list(crawler.visited) + [self.url]:
            if extra_url and extra_url not in endpoint_urls:
                endpoint_urls.add(extra_url)
                passive_endpoints.append(Endpoint(url=extra_url, method="GET"))

        # 2) Détection
        detector_names = self.options.only or list(ALL_DETECTORS.keys())
        raw_vulns: list[Vulnerability] = []
        for name in detector_names:
            cls = ALL_DETECTORS.get(name)
            if cls is None:
                logger.warning("Détecteur inconnu ignoré : %s", name)
                continue
            detector = cls(
                session=self.session,
                timeout=self.options.timeout,
                verbose=self.options.verbose,
            )
            logger.info("Exécution : %s", detector.name)
            targets = passive_endpoints if isinstance(detector, PassiveDetector) else endpoints
            raw_vulns.extend(detector.scan_all(targets))

        # 3) Déduplication
        deduped = self._deduplicate(raw_vulns)

        # 4) Évaluation CVSS
        evaluator = CVSSEvaluator()
        self.vulnerabilities = evaluator.evaluate_all(deduped)

        # 5) Rapport
        self.duration = time.perf_counter() - start
        reporter = HTMLReporter(self.options.output)
        self._report_path = reporter.save(
            self.vulnerabilities,
            target_url=self.url,
            duration=self.duration,
            pages_scanned=self.pages_scanned,
        )
        logger.info(
            "Scan terminé en %.2fs : %d vulnérabilités, rapport: %s",
            self.duration,
            len(self.vulnerabilities),
            self._report_path,
        )
        return self.vulnerabilities

    def get_report(self) -> Path | None:
        return self._report_path

    def _maybe_login(self) -> None:
        opt = self.options
        if opt.dvwa:
            username = opt.username or "admin"
            password = opt.password or "password"
            ok = login_dvwa(
                self.session, self.url, username, password,
                security=opt.dvwa_security, timeout=opt.timeout,
            )
            if not ok:
                logger.warning(
                    "Auto-login DVWA a échoué — le scan continue "
                    "(pages protégées ne seront pas accessibles)."
                )
            return
        if opt.login_url and opt.username and opt.password:
            ok = login_form_based(
                self.session, opt.login_url, opt.username, opt.password,
                timeout=opt.timeout,
            )
            if not ok:
                logger.warning("Auto-login a échoué — le scan continue.")

    @staticmethod
    def _deduplicate(vulns: list[Vulnerability]) -> list[Vulnerability]:
        seen: dict[tuple, Vulnerability] = {}
        for v in vulns:
            if v.key() not in seen:
                seen[v.key()] = v
        return list(seen.values())
