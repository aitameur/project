"""Crawler BFS qui explore une application web et extrait les endpoints testables."""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

USER_AGENT = "OWASP-Top10-Scanner/1.0 (PFA-EMSI)"


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    form_fields: dict[str, str] = field(default_factory=dict)
    file_fields: list[str] = field(default_factory=list)
    enctype: str = ""

    def signature(self) -> str:
        keys = ",".join(sorted(self.params.keys() | self.form_fields.keys()))
        return f"{self.method}:{self.url}?{keys}"


def _same_domain(url: str, base: str) -> bool:
    try:
        return urlparse(url).netloc == urlparse(base).netloc
    except ValueError:
        return False


def _strip_query(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


class Crawler:
    def __init__(
        self,
        base_url: str,
        max_depth: int = 2,
        max_pages: int = 100,
        timeout: int = 10,
        session: requests.Session | None = None,
        verbose: bool = False,
    ):
        # NE PAS rstrip('/') : certains serveurs (DVWA/Apache) redirigent
        # `/path` vers la page de login au lieu de servir `/path/`.
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.verbose = verbose
        self.session = session or self._build_session()
        self.visited: set[str] = set()
        self.endpoints: list[Endpoint] = []

    @staticmethod
    def _build_session() -> requests.Session:
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT})
        return s

    def crawl(self) -> list[Endpoint]:
        """BFS depuis base_url. Retourne tous les endpoints découverts."""
        queue: deque[tuple[str, int]] = deque([(self.base_url, 0)])
        seen_signatures: set[str] = set()

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.popleft()
            canonical = _strip_query(url)
            if canonical in self.visited or depth > self.max_depth:
                continue
            self.visited.add(canonical)

            resp = self._fetch(url)
            if resp is None:
                continue

            # 1) Enregistrer l'endpoint GET si params
            qs = parse_qs(urlparse(url).query, keep_blank_values=True)
            params = {k: (v[0] if v else "") for k, v in qs.items()}
            if params:
                ep = Endpoint(
                    url=canonical, method="GET", params=params
                )
                if ep.signature() not in seen_signatures:
                    seen_signatures.add(ep.signature())
                    self.endpoints.append(ep)

            content_type = resp.headers.get("Content-Type", "")
            if "html" not in content_type.lower():
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # 2) Extraire formulaires
            for form in soup.find_all("form"):
                action = form.get("action") or url
                # action="#" ou vide : formulaire qui se poste sur la page actuelle
                if action.strip() in ("", "#"):
                    form_url = _strip_query(url)
                else:
                    form_url = _strip_query(urljoin(url, action))
                method = (form.get("method") or "GET").upper()
                enctype = form.get("enctype", "").lower()
                fields: dict[str, str] = {}
                file_fields: list[str] = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    if (inp.get("type") or "").lower() == "file":
                        file_fields.append(name)
                    else:
                        fields[name] = inp.get("value", "test")
                if not fields and not file_fields:
                    continue
                ep = Endpoint(
                    url=form_url,
                    method=method,
                    params={} if method != "GET" else fields,
                    form_fields=fields if method != "GET" else {},
                    file_fields=file_fields,
                    enctype=enctype,
                )
                if ep.signature() not in seen_signatures:
                    seen_signatures.add(ep.signature())
                    self.endpoints.append(ep)

            # 3) Suivre les liens internes
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                # Ignorer logout pour ne pas invalider la session
                if "logout" in href.lower():
                    continue
                next_url = urljoin(url, href)
                if not _same_domain(next_url, self.base_url):
                    continue
                if _strip_query(next_url) not in self.visited:
                    queue.append((next_url, depth + 1))

        logger.info(
            "Crawl terminé : %d pages visitées, %d endpoints testables",
            len(self.visited),
            len(self.endpoints),
        )
        return self.endpoints

    def _fetch(self, url: str) -> requests.Response | None:
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if self.verbose:
                logger.info("GET %s -> %d", url, resp.status_code)
            return resp
        except requests.RequestException as exc:
            logger.debug("Requête échouée sur %s : %s", url, exc)
            return None
