"""Fixtures partagées : mini-application Flask volontairement vulnérable.

ATTENTION : cette app est DÉLIBÉRÉMENT vulnérable à SQLi, XSS, SSRF, IDOR,
Path Traversal et XXE. Elle ne doit JAMAIS être exposée publiquement.
"""
from __future__ import annotations

import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
import requests
from werkzeug.serving import make_server

# Expose le dossier `imple/` au PYTHONPATH pour que `scanner`, `crawler`, etc.
# soient importables sans installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, request, Response, send_from_directory  # noqa: E402

# ── contenu système factice pour les tests (pas besoin de toucher aux fichiers réels) ──
FAKE_PASSWD = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n"
USERS_DB = {
    1: {"name": "Alice",   "email": "alice@example.com",   "role": "user"},
    2: {"name": "Bob",     "email": "bob@example.com",     "role": "user"},
    3: {"name": "Charlie", "email": "charlie@example.com", "role": "admin"},
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def create_vulnerable_app() -> Flask:
    app = Flask(__name__)
    upload_dir = Path(tempfile.mkdtemp(prefix="vuln_uploads_"))

    @app.route("/")
    def index():
        return """
        <html><body>
          <h1>Bienvenue</h1>
          <ul>
            <li><a href="/search?q=test">Recherche (SQLi)</a></li>
            <li><a href="/greet?name=world">Salutation (XSS)</a></li>
            <li><a href="/user?id=1">Profil user (IDOR)</a></li>
            <li><a href="/file?page=index.html">Fichier (Path Traversal)</a></li>
            <li><a href="/fetch?url=http://example.com">Fetch URL (SSRF)</a></li>
            <li><a href="/xml-form">Formulaire XML (XXE)</a></li>
            <li><a href="/upload">Upload (File Upload)</a></li>
            <li><a href="/login">Login (A02/A07)</a></li>
            <li><a href="/page-with-old-jquery">Vieille lib (A06)</a></li>
            <li><a href="/no-sri">Scripts CDN sans SRI (A08)</a></li>
          </ul>
        </body></html>
        """

    # ── SQLi (error-based) ─────────────────────────────────────────────
    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        # Simule une erreur MySQL si le payload contient une quote
        if "'" in q and "--" not in q.lower() and "or " not in q.lower():
            return (
                "<h1>Erreur</h1><pre>You have an error in your SQL syntax; "
                f"check the manual near '{q}' at line 1</pre>", 500,
            )
        return f"<h1>Résultats pour {q}</h1><p>Aucun résultat</p>"

    # ── XSS réfléchi ───────────────────────────────────────────────────
    @app.route("/greet")
    def greet():
        name = request.args.get("name", "")
        return f"<html><body><h1>Bonjour {name}</h1></body></html>"

    # ── IDOR ──────────────────────────────────────────────────────────
    @app.route("/user")
    def user():
        try:
            uid = int(request.args.get("id", "0"))
        except ValueError:
            return "Bad request", 400
        u = USERS_DB.get(uid)
        if not u:
            return "Not found", 404
        return (
            f"<h1>Profil {u['name']}</h1>"
            f"<p>Email: {u['email']}</p><p>Role: {u['role']}</p>"
        )

    # ── Path Traversal ────────────────────────────────────────────────
    @app.route("/file")
    def read_file():
        page = request.args.get("page", "")
        if "etc/passwd" in page or "etc%2fpasswd" in page.lower():
            return Response(FAKE_PASSWD, mimetype="text/plain")
        return f"<h1>Page {page}</h1>"

    # ── SSRF ──────────────────────────────────────────────────────────
    @app.route("/fetch")
    def fetch():
        url = request.args.get("url", "")
        # Simule de la SSRF : si l'URL pointe vers 127.0.0.1, on renvoie des metadata factices
        if "127.0.0.1" in url or "localhost" in url:
            return Response(
                "ami-id: ami-12345\ninstance-id: i-0abcdef1234567890\n",
                mimetype="text/plain",
            )
        if "169.254.169.254" in url:
            return Response(
                "Metadata-Flavor: Google\ninstance-id: 1234\n",
                mimetype="text/plain",
            )
        return "fetched OK"

    # ── XXE ───────────────────────────────────────────────────────────
    @app.route("/xml-form")
    def xml_form():
        return (
            '<html><body><form method="POST" action="/xml" '
            'enctype="application/xml"><textarea name="xml"></textarea>'
            '<button type="submit">Envoyer</button></form></body></html>'
        )

    @app.route("/xml", methods=["POST"])
    def xml_endpoint():
        try:
            # Parser XML VOLONTAIREMENT vulnérable aux XXE : on résout l'entité nous-mêmes
            body = request.get_data(as_text=True)
            if "SYSTEM" in body and "passwd" in body:
                return Response(
                    f"<result>{FAKE_PASSWD}</result>", mimetype="application/xml"
                )
            return "<result>ok</result>"
        except ET.ParseError:
            return "parse error", 400

    # ── File Upload (volontairement non validé) ───────────────────────
    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        if request.method == "GET":
            return (
                '<html><body><h1>Upload</h1>'
                '<form method="POST" enctype="multipart/form-data" action="/upload">'
                '<input type="hidden" name="MAX_FILE_SIZE" value="100000">'
                '<input type="file" name="uploaded">'
                '<input type="submit" name="Upload" value="Upload">'
                '</form></body></html>'
            )
        f = request.files.get("uploaded")
        if f is None or not f.filename:
            return "Aucun fichier", 400
        # VOLONTAIREMENT : aucune validation d'extension
        dest = upload_dir / Path(f.filename).name
        f.save(dest)
        return (
            f'<p>../uploads/{dest.name} succesfully uploaded!</p>',
            200,
        )

    @app.route("/uploads/<path:filename>")
    def serve_upload(filename: str):
        return send_from_directory(upload_dir, filename)

    # ── A02 Crypto : login en HTTP clair + creds en GET ─────────────────
    @app.route("/login")
    def login_clear():
        # page contient un champ password mais est servie en HTTP (le scanner
        # est en HTTP par construction dans les tests).
        return (
            '<html><body><form method="POST" action="/login">'
            '<input name="username" type="text">'
            '<input name="password" type="password">'
            '<button type="submit" name="Login">Login</button>'
            '</form></body></html>'
        )

    @app.route("/login", methods=["POST"])
    def login_submit():
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if (u, p) == ("admin", "admin"):
            # Marqueurs de succès + cookie de session sans flags
            resp = Response("<h1>Welcome, admin</h1><a href=/logout>Logout</a>")
            resp.set_cookie("session_id", "abc123")  # PAS de HttpOnly/Secure
            return resp
        return "<p>Login failed. Invalid credentials. Try again.</p>", 200

    # ── A05 Security Misconfig : fichiers sensibles exposés ─────────────
    @app.route("/.env")
    def env_file():
        return Response(
            "DB_PASSWORD=super-secret\nAPI_KEY=xyz\n",
            mimetype="text/plain",
        )

    @app.route("/phpinfo.php")
    def phpinfo():
        return Response("<h1>phpinfo()</h1><p>PHP Version 7.0.30</p>")

    @app.route("/listing/")
    def listing():
        return "<html><body><h1>Index of /listing/</h1></body></html>"

    # ── A06 Vulnerable Components : headers + JS versionné ──────────────
    @app.after_request
    def inject_version_headers(resp):
        # Simule un Apache/PHP révélant leur version sur certaines pages
        if request.path in ("/", "/greet", "/login"):
            resp.headers["Server"] = "Apache/2.4.25 (Debian)"
            resp.headers["X-Powered-By"] = "PHP/7.0.30"
        return resp

    @app.route("/page-with-old-jquery")
    def old_jquery():
        return (
            '<html><head>'
            '<meta name="generator" content="WordPress 4.7.1">'
            '<script src="https://code.jquery.com/jquery-1.6.4.min.js"></script>'
            '</head><body>page</body></html>'
        )

    # ── A08 Integrity : scripts externes sans SRI ───────────────────────
    @app.route("/no-sri")
    def no_sri():
        return (
            '<html><head>'
            '<script src="https://cdn.example.com/lib.js"></script>'
            '<link rel="stylesheet" href="https://cdn.example.com/style.css">'
            '</head><body>page</body></html>'
        )

    return app


class _ServerThread(threading.Thread):
    def __init__(self, app: Flask, port: int):
        super().__init__(daemon=True)
        self.server = make_server("127.0.0.1", port, app, threaded=True)
        self.port = port

    def run(self) -> None:
        self.server.serve_forever()

    def shutdown(self) -> None:
        self.server.shutdown()


@pytest.fixture(scope="session")
def vulnerable_app():
    app = create_vulnerable_app()
    port = _free_port()
    thread = _ServerThread(app, port)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    # attendre que le serveur réponde
    for _ in range(50):
        try:
            requests.get(base_url, timeout=0.5)
            break
        except Exception:
            time.sleep(0.05)
    yield base_url
    thread.shutdown()
