from evaluator.cvss import CVSSEvaluator, get_severity
from scanner.vulnerability import Vulnerability


def test_severity_thresholds():
    assert get_severity(9.8) == "Critique"
    assert get_severity(9.0) == "Critique"
    assert get_severity(8.9) == "Élevé"
    assert get_severity(7.0) == "Élevé"
    assert get_severity(6.9) == "Moyen"
    assert get_severity(4.0) == "Moyen"
    assert get_severity(3.9) == "Faible"
    assert get_severity(0.1) == "Faible"
    assert get_severity(0.0) == "Aucun"


def test_evaluator_sets_score_and_vector():
    v = Vulnerability(
        name="SQL Injection",
        owasp_id="A03",
        url="http://x/search",
        parameter="q",
        payload="'",
        evidence="err",
    )
    CVSSEvaluator().evaluate(v)
    assert v.cvss_score == 9.8
    assert v.severity == "Critique"
    assert "AV:N" in v.cvss_vector
    assert "paramétr" in v.recommendation  # recommandation remplie


def test_evaluator_unknown_name_defaults_to_medium():
    v = Vulnerability(
        name="Vulnérabilité Inconnue",
        owasp_id="A99",
        url="http://x",
        parameter="",
        payload="",
        evidence="",
    )
    CVSSEvaluator().evaluate(v)
    assert 4.0 <= v.cvss_score < 7.0
    assert v.severity == "Moyen"
