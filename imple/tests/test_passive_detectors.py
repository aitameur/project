"""Tests des détecteurs passifs (A02, A05, A06, A07, A08)."""
from crawler import Endpoint
from detectors import (
    CryptographicFailuresDetector,
    SecurityMisconfigDetector,
    VulnerableComponentsDetector,
    AuthFailuresDetector,
    IntegrityDetector,
)


def _ep(url, method="GET", params=None, form_fields=None):
    return Endpoint(
        url=url, method=method,
        params=params or {}, form_fields=form_fields or {},
    )


# ─── A02 Cryptographic Failures ───────────────────────────────────────────
def test_crypto_detects_http_login_page(vulnerable_app):
    ep = _ep(f"{vulnerable_app}/login")
    vulns = CryptographicFailuresDetector(timeout=5).scan(ep)
    assert any("HTTP en clair" in v.payload for v in vulns)


def test_crypto_detects_credentials_in_url(vulnerable_app):
    ep = _ep(f"{vulnerable_app}/search?password=abc")
    vulns = CryptographicFailuresDetector(timeout=5).scan(ep)
    assert any(v.parameter == "password" for v in vulns)


# ─── A05 Security Misconfiguration ────────────────────────────────────────
def test_security_headers_missing(vulnerable_app):
    ep = _ep(f"{vulnerable_app}/")
    vulns = SecurityMisconfigDetector(timeout=5).scan(ep)
    # Flask par défaut ne renvoie aucun de ces headers
    headers_reported = {v.parameter for v in vulns}
    assert "Header: x-content-type-options" in headers_reported
    assert "Header: content-security-policy" in headers_reported


def test_exposed_sensitive_files(vulnerable_app):
    # Le premier appel teste aussi les chemins sensibles
    SecurityMisconfigDetector._tested_base.clear()  # reset du cache classe
    ep = _ep(f"{vulnerable_app}/")
    vulns = SecurityMisconfigDetector(timeout=5).scan(ep)
    names = {v.parameter for v in vulns}
    assert ".env" in names
    assert "phpinfo.php" in names


# ─── A06 Vulnerable Components ────────────────────────────────────────────
def test_components_detect_server_version(vulnerable_app):
    VulnerableComponentsDetector._reported.clear()
    ep = _ep(f"{vulnerable_app}/")
    vulns = VulnerableComponentsDetector(timeout=5).scan(ep)
    payloads = {v.payload for v in vulns}
    assert any("Apache" in p for p in payloads)
    assert any("PHP" in p for p in payloads)


def test_components_detect_js_library_version(vulnerable_app):
    VulnerableComponentsDetector._reported.clear()
    ep = _ep(f"{vulnerable_app}/page-with-old-jquery")
    vulns = VulnerableComponentsDetector(timeout=5).scan(ep)
    payloads = {v.payload for v in vulns}
    assert any("jquery" in p for p in payloads)


# ─── A07 Authentication Failures ──────────────────────────────────────────
def test_auth_detects_default_credentials(vulnerable_app):
    ep = _ep(
        f"{vulnerable_app}/login",
        method="POST",
        form_fields={"username": "", "password": "", "Login": "Login"},
    )
    vulns = AuthFailuresDetector(timeout=5).scan(ep)
    assert any(v.name == "Authentication Failures" for v in vulns)
    assert any("admin:admin" in v.payload for v in vulns)


def test_auth_detects_password_in_url():
    ep = _ep("http://example.com/bad", params={"user": "x", "password": "y"})
    vulns = AuthFailuresDetector(timeout=1).scan(ep)
    assert any(v.parameter == "password" for v in vulns)


# ─── A08 Software & Data Integrity ────────────────────────────────────────
def test_integrity_detects_missing_sri(vulnerable_app):
    IntegrityDetector._reported_resources.clear()
    ep = _ep(f"{vulnerable_app}/no-sri")
    vulns = IntegrityDetector(timeout=5).scan(ep)
    assert any(v.name == "Software & Data Integrity" for v in vulns)
    assert len(vulns) >= 2  # script + stylesheet
