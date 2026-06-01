import pytest

from crawler import Endpoint
from detectors import (
    SQLiDetector, XSSDetector, SSRFDetector,
    IDORDetector, PathTraversalDetector, XXEDetector,
)


def _ep(url, method="GET", params=None, form_fields=None):
    return Endpoint(
        url=url, method=method,
        params=params or {}, form_fields=form_fields or {},
    )


def test_sqli_detects_error(vulnerable_app):
    ep = _ep(f"{vulnerable_app}/search", params={"q": "test"})
    vulns = SQLiDetector(timeout=5).scan(ep)
    assert any(v.name == "SQL Injection" for v in vulns)


def test_xss_detects_reflection(vulnerable_app):
    ep = _ep(f"{vulnerable_app}/greet", params={"name": "test"})
    vulns = XSSDetector(timeout=5).scan(ep)
    assert any(v.name == "Cross-Site Scripting" for v in vulns)


def test_idor_detects_enumeration(vulnerable_app):
    ep = _ep(f"{vulnerable_app}/user", params={"id": "1"})
    vulns = IDORDetector(timeout=5).scan(ep)
    assert any(v.name == "IDOR" for v in vulns)


def test_path_traversal_detects(vulnerable_app):
    ep = _ep(f"{vulnerable_app}/file", params={"page": "index.html"})
    vulns = PathTraversalDetector(timeout=5).scan(ep)
    assert any(v.name == "Path Traversal" for v in vulns)


def test_ssrf_detects(vulnerable_app):
    ep = _ep(f"{vulnerable_app}/fetch", params={"url": "http://example.com"})
    vulns = SSRFDetector(timeout=5).scan(ep)
    assert any(v.name == "SSRF" for v in vulns)


def test_xxe_detects(vulnerable_app):
    ep = _ep(f"{vulnerable_app}/xml", method="POST")
    vulns = XXEDetector(timeout=5).scan(ep)
    assert any(v.name == "XXE" for v in vulns)


def test_detectors_handle_network_errors_gracefully():
    """Tous les détecteurs doivent retourner [] en cas d'erreur réseau, pas crasher."""
    ep = _ep("http://127.0.0.1:1/nonexistent", params={"x": "1"})
    for det_cls in (SQLiDetector, XSSDetector, SSRFDetector, IDORDetector,
                    PathTraversalDetector):
        detector = det_cls(timeout=1)
        vulns = detector.scan(ep)
        assert vulns == []
