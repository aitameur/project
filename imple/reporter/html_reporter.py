"""Génération du rapport HTML autonome (CSS inline)."""
from __future__ import annotations

import html
from collections import Counter
from datetime import datetime
from pathlib import Path

from scanner.vulnerability import Vulnerability

SEVERITY_COLORS = {
    "Critique": ("#c80000", "#fee2e2"),
    "Élevé":    ("#dc7800", "#ffedd5"),
    "Moyen":    ("#b4a000", "#fef9c3"),
    "Faible":   ("#008c3c", "#dcfce7"),
    "Aucun":    ("#64748b", "#f1f5f9"),
}

SEVERITY_ORDER = ["Critique", "Élevé", "Moyen", "Faible", "Aucun"]

CSS = """
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0; font-family: -apple-system, Segoe UI, sans-serif;
  background: #f5f5f5; color: #1e293b;
}
.container { max-width: 1100px; margin: 0 auto; padding: 30px; }
header {
  background: linear-gradient(135deg, #003366 0%, #004d99 100%);
  color: white; padding: 40px 30px; border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}
header h1 { margin: 0 0 8px 0; font-size: 28px; }
header .meta { opacity: 0.9; font-size: 14px; }
header .meta span { display: inline-block; margin-right: 20px; }
.dashboard {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 15px; margin: 25px 0;
}
.card {
  padding: 20px; border-radius: 8px; border-left: 6px solid;
  background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.06);
}
.card .count { font-size: 36px; font-weight: bold; }
.card .label { font-size: 14px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; }
h2 { color: #003366; border-bottom: 2px solid #b40000; padding-bottom: 8px; }
.vuln {
  background: white; border-radius: 8px; margin-bottom: 15px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.06); overflow: hidden;
}
.vuln summary {
  cursor: pointer; padding: 16px 20px; font-weight: 600;
  display: flex; align-items: center; gap: 12px;
  list-style: none;
}
.vuln summary::-webkit-details-marker { display: none; }
.badge {
  display: inline-block; padding: 4px 10px; border-radius: 4px;
  font-size: 12px; font-weight: bold; color: white;
}
.owasp-badge {
  background: #003366; color: white; padding: 4px 8px;
  border-radius: 4px; font-size: 12px;
}
.vuln-body { padding: 0 20px 20px 20px; border-top: 1px solid #e2e8f0; }
.vuln-body dl { display: grid; grid-template-columns: 140px 1fr; gap: 8px 16px; margin: 16px 0; }
.vuln-body dt { font-weight: 600; color: #475569; }
.vuln-body dd { margin: 0; }
code, pre {
  background: #f1f5f9; padding: 2px 6px; border-radius: 4px;
  font-family: Consolas, Monaco, monospace; font-size: 13px;
  word-break: break-all;
}
pre { padding: 12px; overflow-x: auto; }
.recommendation {
  background: #ecfdf5; border-left: 4px solid #008c3c;
  padding: 12px 16px; border-radius: 4px; margin-top: 12px;
}
footer {
  text-align: center; padding: 20px; color: #64748b; font-size: 13px;
  margin-top: 40px;
}
.empty-state {
  text-align: center; padding: 60px 20px; background: white;
  border-radius: 8px; color: #64748b;
}
.empty-state .icon { font-size: 48px; margin-bottom: 16px; }
"""


class HTMLReporter:
    def __init__(self, output_path: str | Path = "rapport.html"):
        self.output_path = Path(output_path)

    def generate(
        self,
        vulns: list[Vulnerability],
        target_url: str,
        duration: float,
        pages_scanned: int,
    ) -> str:
        vulns_sorted = sorted(
            vulns, key=lambda v: (-v.cvss_score, v.name, v.url)
        )
        counts = Counter(v.severity for v in vulns)
        now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        cards = "".join(
            self._card(sev, counts.get(sev, 0))
            for sev in SEVERITY_ORDER
            if sev != "Aucun" or counts.get(sev, 0) > 0
        )

        if not vulns_sorted:
            vulns_html = (
                '<div class="empty-state">'
                '<div class="icon">OK</div>'
                "<h3>Aucune vulnérabilité détectée</h3>"
                "<p>Le scan s'est terminé sans identifier de faille parmi "
                "les catégories OWASP testées.</p>"
                "</div>"
            )
        else:
            vulns_html = "".join(self._vuln_block(v) for v in vulns_sorted)

        html_doc = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Rapport de scan - {html.escape(target_url)}</title>
  <style>{CSS}</style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Rapport de scan de vulnérabilités</h1>
      <div class="meta">
        <span><strong>Cible :</strong> {html.escape(target_url)}</span>
        <span><strong>Date :</strong> {now}</span>
        <span><strong>Durée :</strong> {duration:.2f}s</span>
        <span><strong>Pages scannées :</strong> {pages_scanned}</span>
      </div>
    </header>

    <h2>Tableau de bord</h2>
    <div class="dashboard">{cards}</div>

    <h2>Vulnérabilités détectées ({len(vulns_sorted)})</h2>
    {vulns_html}

    <footer>
      Généré par <strong>OWASP Top 10 Scanner</strong> — PFA EMSI 2024-2025
      <br>Salma El Kamili &amp; Fatima Ezzahrae Nouama
    </footer>
  </div>
</body>
</html>
"""
        return html_doc

    def _card(self, severity: str, count: int) -> str:
        color, bg = SEVERITY_COLORS[severity]
        return (
            f'<div class="card" style="border-left-color:{color};background:{bg};">'
            f'<div class="count" style="color:{color};">{count}</div>'
            f'<div class="label">{severity}</div>'
            f"</div>"
        )

    def _vuln_block(self, v: Vulnerability) -> str:
        color, _bg = SEVERITY_COLORS.get(v.severity, SEVERITY_COLORS["Aucun"])
        return f"""
<details class="vuln" open>
  <summary>
    <span class="badge" style="background:{color};">{html.escape(v.severity)}</span>
    <span class="owasp-badge">{html.escape(v.owasp_id)}</span>
    <span>{html.escape(v.name)}</span>
    <span style="margin-left:auto; color:#64748b; font-size:13px;">
      CVSS {v.cvss_score:.1f}
    </span>
  </summary>
  <div class="vuln-body">
    <dl>
      <dt>URL</dt><dd><code>{html.escape(v.url)}</code></dd>
      <dt>Méthode</dt><dd><code>{html.escape(v.method)}</code></dd>
      <dt>Paramètre</dt><dd><code>{html.escape(v.parameter)}</code></dd>
      <dt>Payload</dt><dd><pre>{html.escape(v.payload)}</pre></dd>
      <dt>Preuve</dt><dd>{html.escape(v.evidence)}</dd>
      <dt>Vecteur CVSS</dt><dd><code>{html.escape(v.cvss_vector)}</code></dd>
    </dl>
    <div class="recommendation">
      <strong>Recommandation :</strong> {html.escape(v.recommendation)}
    </div>
  </div>
</details>
"""

    def save(
        self,
        vulns: list[Vulnerability],
        target_url: str,
        duration: float,
        pages_scanned: int,
    ) -> Path:
        content = self.generate(vulns, target_url, duration, pages_scanned)
        self.output_path.write_text(content, encoding="utf-8")
        return self.output_path
