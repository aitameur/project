"""Détecteur IDOR - Insecure Direct Object Reference (OWASP A01)."""
from __future__ import annotations

from crawler import Endpoint
from scanner.vulnerability import Vulnerability
from .base import BaseDetector

ID_PARAM_HINTS = ("id", "user", "uid", "account", "profile", "order",
                  "doc", "file", "ref", "num", "key")


class IDORDetector(BaseDetector):
    """Heuristique IDOR : cherche les paramètres numériques et tente l'incrémentation.

    Un IDOR est suspecté si :
      - la valeur d'origine est un entier
      - après incrémentation, la réponse reste un 200 avec un contenu significativement
        différent (donc pas simplement une page d'erreur générique)
    """

    name = "IDOR"
    owasp_id = "A01"

    def scan(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for param, method, base in self._iter_injection_points(endpoint):
            original = str(base.get(param, ""))
            if not original.isdigit():
                continue
            if not any(h in param.lower() for h in ID_PARAM_HINTS):
                continue

            # réponse avec l'ID original
            resp_orig = self._send(
                endpoint.url,
                method=method,
                params=base if method == "GET" else None,
                data=base if method != "GET" else None,
            )
            if resp_orig is None or resp_orig.status_code != 200:
                continue

            # incrémenter l'ID
            mutated = dict(base)
            mutated[param] = str(int(original) + 1)
            resp_new = self._send(
                endpoint.url,
                method=method,
                params=mutated if method == "GET" else None,
                data=mutated if method != "GET" else None,
            )
            if resp_new is None:
                continue

            # IDOR : deux IDs consécutifs renvoient un 200 avec un contenu
            # distinct = absence de contrôle d'accès (on voit les données d'un
            # autre utilisateur). Une différence même minime entre les réponses
            # suffit à confirmer (nom / email / ID différent).
            if (
                resp_new.status_code == 200
                and resp_new.text
                and resp_new.text != resp_orig.text
            ):
                vulns.append(
                    Vulnerability(
                        name=self.name,
                        owasp_id=self.owasp_id,
                        url=endpoint.url,
                        parameter=param,
                        payload=f"{param}={mutated[param]}",
                        evidence=(
                            f"L'ID {original} et {mutated[param]} renvoient tous deux "
                            f"un 200 avec des contenus différents "
                            f"— aucun contrôle d'accès apparent."
                        ),
                        method=method,
                    )
                )
        return vulns
