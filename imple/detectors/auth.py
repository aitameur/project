"""Détecteur A07 - Identification and Authentication Failures.

Sur les formulaires qui contiennent un champ <input type="password"> :
  - Test d'identifiants par défaut (admin/admin, admin/password, root/root, etc.)
  - Vérifie si le mot de passe transite en paramètre GET (URL)
"""
from __future__ import annotations

from crawler import Endpoint
from scanner.vulnerability import Vulnerability
from .base import BaseDetector

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("root",  "root"),
    ("root",  "toor"),
    ("user",  "user"),
    ("test",  "test"),
    ("guest", "guest"),
]

USER_FIELDS = ("username", "user", "login", "email", "name", "uname", "id")
PASS_FIELDS = ("password", "pwd", "pass", "passwd")

# Marqueurs typiques de login raté pour comparaison.
FAILURE_MARKERS = (
    "login failed", "invalid", "incorrect", "erreur",
    "failed", "wrong", "bad credentials", "try again",
)
SUCCESS_MARKERS = (
    "logout", "sign out", "bienvenue", "welcome,", "dashboard",
    "profile", "my account",
)


def _find_fields(form_fields: dict[str, str]) -> tuple[str | None, str | None]:
    """Identifie le champ username et le champ password dans un formulaire."""
    user_field = None
    pass_field = None
    for name in form_fields:
        low = name.lower()
        if pass_field is None and any(p in low for p in PASS_FIELDS):
            pass_field = name
            continue
        if user_field is None and any(u in low for u in USER_FIELDS):
            user_field = name
    return user_field, pass_field


class AuthFailuresDetector(BaseDetector):
    name = "Authentication Failures"
    owasp_id = "A07"
    payloads_file = None

    def scan(self, endpoint: Endpoint) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []

        # (1) Mot de passe en GET — alerte immédiate
        if endpoint.method.upper() == "GET":
            for p in endpoint.params:
                if any(x in p.lower() for x in PASS_FIELDS):
                    vulns.append(Vulnerability(
                        name=self.name, owasp_id=self.owasp_id,
                        url=endpoint.url, parameter=p,
                        payload="(paramètre GET)",
                        evidence="Mot de passe transmis en paramètre GET : "
                                 "exposé dans les logs, l'historique du navigateur "
                                 "et le Referer.",
                        method="GET",
                    ))

        # (2) Test d'identifiants par défaut sur les formulaires POST de login
        if endpoint.method.upper() != "POST":
            return vulns
        user_field, pass_field = _find_fields(endpoint.form_fields)
        if not (user_field and pass_field):
            return vulns

        # Baseline : login avec des identifiants bidons pour capturer
        # les marqueurs d'échec et la taille de la réponse d'échec.
        baseline_resp = self._try_login(
            endpoint, user_field, pass_field, "__scanner_user__", "__invalid_pw__"
        )
        if baseline_resp is None:
            return vulns
        baseline_len = len(baseline_resp.text or "")
        baseline_low = (baseline_resp.text or "").lower()

        for username, password in DEFAULT_CREDENTIALS:
            resp = self._try_login(
                endpoint, user_field, pass_field, username, password
            )
            if resp is None:
                continue
            body_low = (resp.text or "").lower()

            # Cas 1 : marqueur de succès présent alors qu'il était absent de la baseline
            success_hit = any(m in body_low for m in SUCCESS_MARKERS) \
                          and not any(m in baseline_low for m in SUCCESS_MARKERS)
            # Cas 2 : disparition du marqueur d'échec
            failure_gone = any(m in baseline_low for m in FAILURE_MARKERS) \
                           and not any(m in body_low for m in FAILURE_MARKERS)
            # Cas 3 : taille très différente (heuristique)
            size_diff = abs(len(resp.text or "") - baseline_len) > max(500, 0.3 * baseline_len)

            if success_hit or failure_gone or (size_diff and resp.status_code == 200):
                vulns.append(Vulnerability(
                    name=self.name, owasp_id=self.owasp_id,
                    url=endpoint.url, parameter=f"{user_field}/{pass_field}",
                    payload=f"{username}:{password}",
                    evidence=f"Identifiants par défaut acceptés : "
                             f"'{username}' / '{password}'.",
                    method="POST",
                ))
                break  # inutile de continuer après une découverte
        return vulns

    def _try_login(self, endpoint, user_field, pass_field, username, password):
        data = dict(endpoint.form_fields)
        data[user_field] = username
        data[pass_field] = password
        return self._send(endpoint.url, method="POST", data=data)
