"""Redesigns the cover page of rapport.docx with a clean, premium look."""
import sys

with open(r"rapport_analysis_unpacked\word\document.xml", "r", encoding="utf-8") as f:
    content = f.read()

# â”€â”€ Locate the cover region to replace â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# The logo paragraph starts the cover. We want to:
#   1. Tighten the spacing AFTER the logo (600 â†’ 240)
#   2. Replace everything from the "Rapport de Projet" paragraph
#      up to (but NOT including) the page-break paragraph.

# 1. Fix logo spacing
content = content.replace(
    '<w:spacing w:after="600"/>\n        <w:jc w:val="center"/>\n        <w:rPr>\n          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>\n          <w:color w:val="505050"/>',
    '<w:spacing w:after="240"/>\n        <w:jc w:val="center"/>\n        <w:rPr>\n          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>\n          <w:color w:val="505050"/>',
    1  # only first occurrence (the logo paragraph)
)

# 2. Find the block to replace
START_ID = 'w14:paraId="37408063"'   # "Rapport de Projet" paragraph
END_ID   = 'w14:paraId="5334ED35"'   # page-break paragraph (keep it)

start_para_pos = content.find(START_ID)
if start_para_pos == -1:
    sys.exit("ERROR: start marker not found")

# Walk back to the opening <w:p tag
region_start = content.rfind("<w:p ", 0, start_para_pos)

end_para_pos = content.find(END_ID)
if end_para_pos == -1:
    sys.exit("ERROR: end marker not found")

region_end = content.rfind("<w:p ", 0, end_para_pos)

# â”€â”€ New premium cover XML â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
NEW_COVER = """\
    <w:p w14:paraId="0A100001" w14:textId="77777777" w:rsidR="000A0001" w:rsidRDefault="000A0001">
      <w:pPr>
        <w:pBdr>
          <w:bottom w:val="single" w:sz="10" w:space="6" w:color="1A2B4A"/>
        </w:pBdr>
        <w:spacing w:before="0" w:after="400"/>
        <w:jc w:val="center"/>
      </w:pPr>
    </w:p>
    <w:p w14:paraId="0A100002" w14:textId="77777777" w:rsidR="000A0001" w:rsidRDefault="000A0001">
      <w:pPr>
        <w:spacing w:before="0" w:after="320"/>
        <w:jc w:val="center"/>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:color w:val="8A8A8A"/>
          <w:sz w:val="20"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:color w:val="8A8A8A"/>
          <w:sz w:val="20"/>
          <w:spacing w:val="120"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
        <w:t>RAPPORT DE PROJET DE FIN D&#x2019;ANN&#xC9;E</w:t>
      </w:r>
    </w:p>
    <w:p w14:paraId="0A100003" w14:textId="77777777" w:rsidR="000A0001" w:rsidRDefault="000A0001">
      <w:pPr>
        <w:spacing w:before="160" w:after="80"/>
        <w:jc w:val="center"/>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:b/>
          <w:color w:val="1A2B4A"/>
          <w:sz w:val="80"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:b/>
          <w:color w:val="1A2B4A"/>
          <w:sz w:val="80"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
        <w:t>Scanner de Vuln&#xE9;rabilit&#xE9;s Web</w:t>
      </w:r>
    </w:p>
    <w:p w14:paraId="0A100004" w14:textId="77777777" w:rsidR="000A0001" w:rsidRDefault="000A0001">
      <w:pPr>
        <w:spacing w:before="0" w:after="360"/>
        <w:jc w:val="center"/>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:b/>
          <w:color w:val="8B1A1A"/>
          <w:sz w:val="48"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:b/>
          <w:color w:val="8B1A1A"/>
          <w:sz w:val="48"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
        <w:t>OWASP Top 10 &#x2014; 2021</w:t>
      </w:r>
    </w:p>
    <w:p w14:paraId="0A100005" w14:textId="77777777" w:rsidR="000A0001" w:rsidRDefault="000A0001">
      <w:pPr>
        <w:pBdr>
          <w:bottom w:val="single" w:sz="4" w:space="4" w:color="CCCCCC"/>
        </w:pBdr>
        <w:spacing w:before="0" w:after="280"/>
        <w:jc w:val="center"/>
      </w:pPr>
    </w:p>
    <w:p w14:paraId="0A100006" w14:textId="77777777" w:rsidR="000A0001" w:rsidRDefault="000A0001">
      <w:pPr>
        <w:spacing w:before="0" w:after="0"/>
        <w:jc w:val="center"/>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:i/>
          <w:color w:val="4D4D4D"/>
          <w:sz w:val="22"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:i/>
          <w:color w:val="4D4D4D"/>
          <w:sz w:val="22"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
        <w:t>D&#xE9;tection automatique des vuln&#xE9;rabilit&#xE9;s critiques des applications web</w:t>
      </w:r>
    </w:p>
    <w:p w14:paraId="0A100007" w14:textId="77777777" w:rsidR="000A0001" w:rsidRDefault="000A0001">
      <w:pPr>
        <w:spacing w:before="0" w:after="1200"/>
        <w:jc w:val="center"/>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:i/>
          <w:color w:val="4D4D4D"/>
          <w:sz w:val="22"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:i/>
          <w:color w:val="4D4D4D"/>
          <w:sz w:val="22"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
        <w:t>bas&#xE9;e sur le r&#xE9;f&#xE9;rentiel OWASP Top 10 2021</w:t>
      </w:r>
    </w:p>
    <w:p w14:paraId="0A100008" w14:textId="77777777" w:rsidR="000A0001" w:rsidRDefault="000A0001">
      <w:pPr>
        <w:pBdr>
          <w:top w:val="single" w:sz="10" w:space="8" w:color="1A2B4A"/>
        </w:pBdr>
        <w:tabs>
          <w:tab w:val="right" w:pos="9020"/>
        </w:tabs>
        <w:spacing w:before="200" w:after="80"/>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:color w:val="8A8A8A"/>
          <w:sz w:val="18"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:color w:val="8A8A8A"/>
          <w:sz w:val="18"/>
          <w:spacing w:val="80"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
        <w:t>R&#xC9;ALIS&#xC9; PAR</w:t>
      </w:r>
      <w:r>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:color w:val="8A8A8A"/>
          <w:sz w:val="18"/>
          <w:spacing w:val="80"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
        <w:tab/>
        <w:t>ANN&#xC9;E UNIVERSITAIRE</w:t>
      </w:r>
    </w:p>
    <w:p w14:paraId="0A100009" w14:textId="77777777" w:rsidR="000A0001" w:rsidRDefault="000A0001">
      <w:pPr>
        <w:tabs>
          <w:tab w:val="right" w:pos="9020"/>
        </w:tabs>
        <w:spacing w:before="0" w:after="0"/>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:b/>
          <w:color w:val="1A2B4A"/>
          <w:sz w:val="24"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
      </w:pPr>
      <w:r>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:b/>
          <w:color w:val="1A2B4A"/>
          <w:sz w:val="24"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
        <w:t>Fatima Ezzahrae N.</w:t>
      </w:r>
      <w:r>
        <w:rPr>
          <w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/>
          <w:b/>
          <w:color w:val="8B1A1A"/>
          <w:sz w:val="24"/>
          <w:lang w:val="fr-FR"/>
        </w:rPr>
        <w:tab/>
        <w:t>2025 &#x2013; 2026</w:t>
      </w:r>
    </w:p>
"""

# â”€â”€ Stitch together â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
content = content[:region_start] + NEW_COVER + content[region_end:]

with open(r"rapport_analysis_unpacked\word\document.xml", "w", encoding="utf-8") as f:
    f.write(content)

print("Cover page replaced successfully.")
print(f"Region replaced: chars {region_start} â€“ {region_end}")

