import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

import zipfile, xml.etree.ElementTree as ET

with zipfile.ZipFile("rapport.docx", "r") as z:
    with z.open("word/document.xml") as f:
        tree = ET.parse(f)

root = tree.getroot()
body = root.find(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}body")

text_parts = []
for para in body.findall(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"):
    texts = []
    for t in para.findall(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"):
        if t.text:
            texts.append(t.text)
    line = "".join(texts)
    if line.strip():
        text_parts.append(line)

for line in text_parts:
    print(line)
