import shutil, struct, sys
from pathlib import Path

BASE      = Path(r"C:\Users\Fati\Desktop\PFa\finale\rapport_analysis_unpacked")
MEDIA     = BASE / "word" / "media"
RELS_FILE = BASE / "word" / "_rels" / "document.xml.rels"
DOC_FILE  = BASE / "word" / "document.xml"
SHOTS_DIR = Path(r"C:\Users\Fati\Desktop\PFa\screenshoots")

DIAGRAMS = [
    ("Diagram 1 — Architecture en Pipeline (2.1).png", "image10.png", "rId21"),
    ("Diagram 2 — Cas d'Utilisation (2.2).png",        "image11.png", "rId22"),
    ("Diagram 3 — Diagramme de Classes (2.3).png",     "image12.png", "rId23"),
    ("Diagram 4 — Diagramme de Séquence (2.4).png","image13.png", "rId24"),
]

def png_size(path):
    with open(path, "rb") as f:
        f.seek(16)
        w = struct.unpack(">I", f.read(4))[0]
        h = struct.unpack(">I", f.read(4))[0]
    return w, h

# 1. Copy PNGs
print("Copying PNGs...")
for src_name, dst_name, _ in DIAGRAMS:
    src = SHOTS_DIR / src_name
    if not src.exists():
        sys.exit("ERROR: not found: " + str(src))
    shutil.copy2(src, MEDIA / dst_name)
    print("  copied " + dst_name)

# 2. Add relationships
print("Adding relationships...")
rels = RELS_FILE.read_text(encoding="utf-8")
img_type = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"
for _, dst_name, rid in DIAGRAMS:
    if rid not in rels:
        entry = '  <Relationship Id="' + rid + '" Type="' + img_type + '" Target="media/' + dst_name + '"/>\n'
        rels = rels.replace("</Relationships>", entry + "</Relationships>")
        print("  added " + rid)
RELS_FILE.write_text(rels, encoding="utf-8")

# 3. Build image paragraph XML
TARGET_WIDTH_EMU = 5900000

def drawing_xml(rid, img_name, desc, doc_id):
    src_name = [s for s, d, r in DIAGRAMS if r == rid][0]
    pw, ph   = png_size(SHOTS_DIR / src_name)
    cx = TARGET_WIDTH_EMU
    cy = int(cx * ph / pw)
    return (
        '    <w:p w14:paraId="0C' + format(doc_id, "06X") + '" w14:textId="77777777"'
        ' w:rsidR="000C0001" w:rsidRDefault="000C0001">\n'
        '      <w:pPr>\n'
        '        <w:spacing w:before="200" w:after="200"/>\n'
        '        <w:jc w:val="center"/>\n'
        '      </w:pPr>\n'
        '      <w:r>\n'
        '        <w:rPr><w:noProof/></w:rPr>\n'
        '        <w:drawing>\n'
        '          <wp:inline distT="0" distB="0" distL="0" distR="0"'
        ' xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">\n'
        '            <wp:extent cx="' + str(cx) + '" cy="' + str(cy) + '"/>\n'
        '            <wp:effectExtent l="0" t="0" r="0" b="0"/>\n'
        '            <wp:docPr id="' + str(doc_id) + '" name="' + img_name + '" descr="' + desc + '"/>\n'
        '            <wp:cNvGraphicFramePr>\n'
        '              <a:graphicFrameLocks xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
        ' noChangeAspect="1"/>\n'
        '            </wp:cNvGraphicFramePr>\n'
        '            <a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">\n'
        '              <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">\n'
        '                <pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">\n'
        '                  <pic:nvPicPr>\n'
        '                    <pic:cNvPr id="' + str(doc_id) + '" name="' + img_name + '"/>\n'
        '                    <pic:cNvPicPr>'
        '<a:picLocks noChangeAspect="1" noChangeArrowheads="1"/>'
        '</pic:cNvPicPr>\n'
        '                  </pic:nvPicPr>\n'
        '                  <pic:blipFill>\n'
        '                    <a:blip r:embed="' + rid + '"'
        ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>\n'
        '                    <a:stretch><a:fillRect/></a:stretch>\n'
        '                  </pic:blipFill>\n'
        '                  <pic:spPr bwMode="auto">\n'
        '                    <a:xfrm><a:off x="0" y="0"/>'
        '<a:ext cx="' + str(cx) + '" cy="' + str(cy) + '"/></a:xfrm>\n'
        '                    <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>\n'
        '                    <a:noFill/><a:ln><a:noFill/></a:ln>\n'
        '                  </pic:spPr>\n'
        '                </pic:pic>\n'
        '              </a:graphicData>\n'
        '            </a:graphic>\n'
        '          </wp:inline>\n'
        '        </w:drawing>\n'
        '      </w:r>\n'
        '    </w:p>\n'
    )

# 4. Edit document.xml
print("Editing document.xml...")
doc = DOC_FILE.read_text(encoding="utf-8")

def insert_after_para(content, para_id, xml_to_insert):
    pos   = content.find('w14:paraId="' + para_id + '"')
    close = content.find("</w:p>", pos) + len("</w:p>")
    return content[:close] + "\n" + xml_to_insert + content[close:]

def replace_para(content, para_id, replacement):
    anchor = 'w14:paraId="' + para_id + '"'
    start  = content.rfind("<w:p ", 0, content.find(anchor))
    end    = content.find("</w:p>", content.find(anchor)) + len("</w:p>")
    return content[:start] + replacement + content[end:]

# Diagram 1: insert after pipeline Code label (paraId 478C56C1)
if 'w14:paraId="478C56C1"' not in doc:
    sys.exit("ERROR: pipeline label not found")
doc = insert_after_para(doc, "478C56C1", drawing_xml("rId21", "diag_pipeline", "Architecture Pipeline", 2001))
print("  [1] Pipeline diagram inserted")

# Diagram 2: insert after use-case intro text (paraId 5E34F647)
if 'w14:paraId="5E34F647"' not in doc:
    sys.exit("ERROR: use-case intro not found")
doc = insert_after_para(doc, "5E34F647", drawing_xml("rId22", "diag_usecase", "Use Case Diagram", 2002))
print("  [2] Use Case diagram inserted")

# Diagram 3: replace class ASCII art paragraph (paraId 125CA1A5)
if 'w14:paraId="125CA1A5"' not in doc:
    sys.exit("ERROR: class ASCII para not found")
doc = replace_para(doc, "125CA1A5", drawing_xml("rId23", "diag_classes", "Class Diagram", 2003))
print("  [3] Class diagram replaced")

# Diagram 4: replace sequence ASCII art paragraph (paraId 0E949D43)
if 'w14:paraId="0E949D43"' not in doc:
    sys.exit("ERROR: sequence ASCII para not found")
doc = replace_para(doc, "0E949D43", drawing_xml("rId24", "diag_sequence", "Sequence Diagram", 2004))
print("  [4] Sequence diagram replaced")

DOC_FILE.write_text(doc, encoding="utf-8")
print("Done. document.xml updated.")
