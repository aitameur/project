from pathlib import Path

from reporter import HTMLReporter
from scanner.vulnerability import Vulnerability
from evaluator import CVSSEvaluator


def _sample_vulns():
    evaluator = CVSSEvaluator()
    vulns = [
        Vulnerability(
            name="SQL Injection", owasp_id="A03",
            url="http://x/search", parameter="q",
            payload="' OR 1=1--", evidence="Erreur SQL",
        ),
        Vulnerability(
            name="Cross-Site Scripting", owasp_id="A03",
            url="http://x/greet", parameter="name",
            payload="<script>alert(1)</script>", evidence="Payload réfléchi",
        ),
    ]
    return evaluator.evaluate_all(vulns)


def test_generate_html_contains_expected_sections(tmp_path):
    out = tmp_path / "rapport.html"
    reporter = HTMLReporter(out)
    reporter.save(
        _sample_vulns(),
        target_url="http://x",
        duration=1.23,
        pages_scanned=4,
    )
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "Rapport de scan" in content
    assert "SQL Injection" in content
    assert "Cross-Site Scripting" in content
    assert "Tableau de bord" in content
    assert "CVSS" in content
    assert "Recommandation" in content


def test_empty_vulns_shows_success_state(tmp_path):
    out = tmp_path / "rapport.html"
    HTMLReporter(out).save([], "http://x", 0.5, 1)
    content = out.read_text(encoding="utf-8")
    assert "Aucune vulnérabilité" in content
