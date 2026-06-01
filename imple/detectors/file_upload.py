"""Détecteur d'Unrestricted File Upload (OWASP A04 - Insecure Design).

Logique :
  1. Sur un endpoint disposant d'un champ <input type="file">, on uploade un
     petit fichier malicieux (PHP, JS, HTML) avec un marqueur unique dans son
     contenu.
  2. On analyse la réponse pour trouver le chemin où le fichier a été sauvegardé
     (motif de type `uploads/NOMDUFICHIER`).
  3. On essaie des chemins classiques (`/uploads/`, `/hackable/uploads/`, etc.).
  4. Si le fichier est accessible ET que le marqueur unique apparaît, la faille
     est confirmée (le serveur accepte des extensions dangereuses et les sert).
"""
from __future__ import annotations

import logging
import re
import uuid
from urllib.parse import urljoin, urlparse

from crawler import Endpoint
from scanner.vulnerability import Vulnerability
from .base import BaseDetector

logger = logging.getLogger(__name__)

# Chemins typiques où les applications stockent les uploads. Testés en
# dernier recours si la réponse ne révèle pas le chemin exact.
COMMON_UPLOAD_PATHS = [
    "hackable/uploads/",  # DVWA
    "uploads/",
    "upload/",
    "files/",
    "images/",
    "media/",
    "assets/uploads/",
    "public/uploads/",
]

# Extensions dangereuses à tester. Une appli sécurisée doit toutes les refuser.
MALICIOUS_FILES = [
    ("shell.php",    "<?php echo 'SCANNER_MARKER_{marker}'; ?>",          "application/x-php"),
    ("shell.phtml",  "<?php echo 'SCANNER_MARKER_{marker}'; ?>",          "application/x-php"),
    ("shell.php.jpg", "<?php echo 'SCANNER_MARKER_{marker}'; ?>",         "image/jpeg"),
]


def _same_host(url_a: str, url_b: str) -> bool:
    return urlparse(url_a).netloc == urlparse(url_b).netloc


class FileUploadDetector(BaseDetector):
    name = "Unrestricted File Upload"
    owasp_id = "A04"
    payloads_file = None  # payloads codés en dur (fichiers malicieux)

    def scan(self, endpoint: Endpoint) -> list[Vulnerability]:
        if not endpoint.file_fields:
            return []
        if endpoint.method.upper() not in ("POST", "PUT"):
            return []

        vulns: list[Vulnerability] = []
        for field in endpoint.file_fields:
            vuln = self._try_upload(endpoint, field)
            if vuln:
                vulns.append(vuln)
        return vulns

    # ── internal ────────────────────────────────────────────────────────
    def _try_upload(self, endpoint: Endpoint, field: str) -> Vulnerability | None:
        for filename_tpl, content_tpl, content_type in MALICIOUS_FILES:
            marker = uuid.uuid4().hex[:12]
            content = content_tpl.format(marker=marker).encode()
            # Rendre le nom de fichier unique (évite collisions entre runs)
            fname = f"{uuid.uuid4().hex[:8]}_{filename_tpl}"

            files = {field: (fname, content, content_type)}
            # champs non-fichier du formulaire (ex: MAX_FILE_SIZE, Upload=Upload)
            data = {k: v for k, v in endpoint.form_fields.items() if k != field}

            resp = self._send(
                endpoint.url,
                method=endpoint.method,
                data=data,
                files=files,
            )
            if resp is None:
                continue

            # 1) Le serveur a-t-il refusé l'upload ?
            if resp.status_code >= 400:
                continue
            if self._looks_rejected(resp.text):
                continue

            # 2) Chercher le chemin du fichier uploadé dans la réponse
            uploaded_url = self._locate_uploaded_file(
                endpoint.url, resp.text, fname, marker
            )
            if uploaded_url:
                return Vulnerability(
                    name=self.name,
                    owasp_id=self.owasp_id,
                    url=endpoint.url,
                    parameter=field,
                    payload=f"Upload de {fname} ({content_type})",
                    evidence=(
                        f"Le serveur a accepté un fichier avec une extension "
                        f"dangereuse et l'a rendu accessible à {uploaded_url}. "
                        f"Marqueur unique retrouvé dans la réponse servie."
                    ),
                    method=endpoint.method,
                )
            # 3) Si on ne trouve pas le fichier mais que le serveur a clairement
            #    dit "upload réussi" pour une extension dangereuse, on remonte
            #    une vuln de sévérité moindre (upload accepté sans validation).
            if self._looks_accepted(resp.text):
                return Vulnerability(
                    name=self.name,
                    owasp_id=self.owasp_id,
                    url=endpoint.url,
                    parameter=field,
                    payload=f"Upload de {fname} ({content_type})",
                    evidence=(
                        "Le serveur a accepté un fichier avec une extension "
                        "dangereuse (PHP). Le chemin exact du fichier n'a pas "
                        "été localisé mais l'upload n'a pas été rejeté."
                    ),
                    method=endpoint.method,
                )
        return None

    def _locate_uploaded_file(
        self, form_url: str, body: str, filename: str, marker: str
    ) -> str | None:
        candidates: set[str] = set()

        # (a) Chemin exact trouvé dans la réponse
        pattern = re.compile(
            r"[\w./\-]*/" + re.escape(filename), re.IGNORECASE
        )
        for m in pattern.findall(body):
            candidates.add(urljoin(form_url, m.lstrip("./")))

        # (b) Essais sur les chemins standards, relatifs à la racine du site
        parsed = urlparse(form_url)
        root = f"{parsed.scheme}://{parsed.netloc}/"
        for p in COMMON_UPLOAD_PATHS:
            candidates.add(urljoin(root, p + filename))

        # (c) Relatif au répertoire courant de l'URL du formulaire
        current_dir = form_url.rsplit("/", 1)[0] + "/"
        for p in COMMON_UPLOAD_PATHS:
            candidates.add(urljoin(current_dir, p + filename))

        # Essayer chaque candidat : vérifier que le marqueur apparaît
        for candidate in candidates:
            if not _same_host(candidate, form_url):
                continue
            resp = self._send(candidate, method="GET")
            if resp is None or resp.status_code != 200:
                continue
            if marker in resp.text:
                return candidate
        return None

    @staticmethod
    def _looks_rejected(body: str) -> bool:
        body_low = body.lower()
        markers = (
            "not allowed", "not permitted", "extension", "invalide",
            "interdit", "refusé", "error", "your image was not uploaded",
        )
        return any(m in body_low for m in markers) and "success" not in body_low

    @staticmethod
    def _looks_accepted(body: str) -> bool:
        body_low = body.lower()
        markers = ("succesfully uploaded", "successfully uploaded", "uploaded", "uploadé")
        return any(m in body_low for m in markers)
