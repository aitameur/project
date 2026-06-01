"""Auto-login : authentification avant scan.

Deux modes :
  - `login_form_based` : mode générique. Récupère le formulaire de login,
    extrait tous les champs cachés (y compris les tokens CSRF type `user_token`),
    et soumet les identifiants.
  - `login_dvwa` : raccourci DVWA. Fait le login via /login.php puis règle la
    sécurité sur `low` via /security.php.
"""
from __future__ import annotations

import logging
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def _find_login_form(html: str) -> tuple[dict[str, str], str | None, str | None]:
    """Retourne (fields, user_field_name, pass_field_name) du premier formulaire
    contenant un input[type=password]."""
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        pwd = form.find("input", {"type": "password"})
        if not pwd:
            continue
        fields: dict[str, str] = {}
        pass_field = pwd.get("name")
        user_field: str | None = None
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            t = (inp.get("type") or "").lower()
            fields[name] = inp.get("value", "")
            if t in ("", "text", "email") and user_field is None and name != pass_field:
                user_field = name
        return fields, user_field, pass_field
    return {}, None, None


def login_form_based(
    session: requests.Session,
    login_url: str,
    username: str,
    password: str,
    timeout: int = 10,
) -> bool:
    """Connexion générique par POST du formulaire de login."""
    try:
        resp = session.get(login_url, timeout=timeout)
    except requests.RequestException as exc:
        logger.error("Impossible de récupérer la page de login %s : %s", login_url, exc)
        return False
    fields, user_field, pass_field = _find_login_form(resp.text)
    if not pass_field:
        logger.error("Aucun formulaire de login trouvé sur %s", login_url)
        return False
    fields[user_field or "username"] = username
    fields[pass_field] = password
    try:
        post = session.post(login_url, data=fields, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        logger.error("POST login échoué : %s", exc)
        return False

    # Heuristique de succès : plus de champ password sur la page finale,
    # ou redirection hors de la page de login.
    still_login = "<input" in post.text.lower() and 'type="password"' in post.text.lower()
    if still_login and urlparse(post.url).path == urlparse(login_url).path:
        logger.error("Login refusé (identifiants invalides ?)")
        return False
    logger.info("Login OK sur %s (user=%s)", login_url, username)
    return True


def login_dvwa(
    session: requests.Session,
    base_url: str,
    username: str = "admin",
    password: str = "password",
    security: str = "low",
    timeout: int = 10,
) -> bool:
    """Auto-login DVWA : /login.php puis bascule sécurité = low."""
    base = base_url if base_url.endswith("/") else base_url + "/"
    login_url = urljoin(base, "login.php")
    security_url = urljoin(base, "security.php")

    if not login_form_based(session, login_url, username, password, timeout):
        return False

    # Bascule du niveau de sécurité
    try:
        sec_page = session.get(security_url, timeout=timeout)
    except requests.RequestException as exc:
        logger.warning("Impossible d'atteindre %s : %s", security_url, exc)
        return True  # login a réussi, on continue quand même
    soup = BeautifulSoup(sec_page.text, "html.parser")
    form = soup.find("form")
    data: dict[str, str] = {}
    if form:
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name:
                data[name] = inp.get("value", "")
    data["security"] = security
    data["seclev_submit"] = "Submit"
    try:
        session.post(security_url, data=data, timeout=timeout)
        logger.info("Niveau de sécurité DVWA réglé sur '%s'", security)
    except requests.RequestException as exc:
        logger.warning("Impossible de régler le niveau de sécurité : %s", exc)
    return True
