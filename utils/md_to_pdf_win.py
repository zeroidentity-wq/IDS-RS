#!/usr/bin/env python3
"""Conversie fisier Markdown -> PDF cu pdfkit + wkhtmltopdf.

Varianta portabila Windows/Linux. Necesita:
  pip install pdfkit markdown
  + wkhtmltopdf instalat (https://wkhtmltopdf.org/downloads.html)

Utilizare:
  python md_to_pdf_win.py                    # converteste PREZENTARE_PROIECT_IDS-RS.md
  python md_to_pdf_win.py raport.md          # converteste raport.md -> raport.pdf
  python md_to_pdf_win.py docs/altceva.md   # converteste cu cale relativa
"""

import sys
import markdown
import pdfkit
from pathlib import Path

# -----------------------------------------------------------------------------
# Fisiere input / output
# -----------------------------------------------------------------------------

if len(sys.argv) >= 2:
    MD_FILE = Path(sys.argv[1])
else:
    MD_FILE = Path("PREZENTARE_PROIECT_IDS-RS.md")

PDF_FILE = MD_FILE.with_suffix(".pdf")

if not MD_FILE.exists():
    print(f"Eroare: fisierul '{MD_FILE}' nu exista.")
    sys.exit(1)

# -----------------------------------------------------------------------------
# Detectare automata wkhtmltopdf (Windows vs Linux)
# -----------------------------------------------------------------------------

WKHTMLTOPDF_WINDOWS = Path(r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")

def get_pdfkit_config():
    """Returneaza configuratia pdfkit cu calea corecta spre wkhtmltopdf."""
    if sys.platform == "win32":
        if not WKHTMLTOPDF_WINDOWS.exists():
            print(f"Eroare: wkhtmltopdf nu a fost gasit la:\n  {WKHTMLTOPDF_WINDOWS}")
            print("Descarca de la: https://wkhtmltopdf.org/downloads.html")
            sys.exit(1)
        return pdfkit.configuration(wkhtmltopdf=str(WKHTMLTOPDF_WINDOWS))
    # Linux/macOS: wkhtmltopdf trebuie sa fie in PATH
    return None

# -----------------------------------------------------------------------------
# CSS
# -----------------------------------------------------------------------------

CSS = """
body {
    font-family: Arial, "Liberation Sans", sans-serif;
    font-size: 11pt;
    line-height: 1.5;
    color: #1a1a1a;
    margin: 2cm 2.5cm;
}

h1 {
    font-size: 22pt;
    text-align: center;
    border-bottom: 3px solid #2c3e50;
    padding-bottom: 12px;
    margin-top: 0;
    color: #2c3e50;
}

h2 {
    font-size: 16pt;
    color: #2c3e50;
    border-bottom: 1px solid #bdc3c7;
    padding-bottom: 6px;
    margin-top: 28px;
    page-break-after: avoid;
}

h3 {
    font-size: 13pt;
    color: #34495e;
    margin-top: 20px;
    page-break-after: avoid;
}

p, li {
    text-align: justify;
}

strong {
    color: #2c3e50;
}

blockquote {
    border-left: 4px solid #2c3e50;
    background: #f0f3f5;
    padding: 8px 14px;
    margin: 12px 0;
    font-style: italic;
    page-break-inside: avoid;
}

pre {
    background: #f4f6f8;
    border: 1px solid #dce1e5;
    border-radius: 4px;
    padding: 10px 14px;
    font-size: 8.5pt;
    line-height: 1.35;
    white-space: pre-wrap;
    font-family: "Courier New", "Liberation Mono", monospace;
    page-break-inside: avoid;
}

code {
    font-family: "Courier New", "Liberation Mono", monospace;
    font-size: 9.5pt;
    background: #eef1f4;
    padding: 1px 4px;
    border-radius: 3px;
}

pre code {
    background: none;
    padding: 0;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 14px 0;
    font-size: 10pt;
    page-break-inside: avoid;
}

th {
    background: #2c3e50;
    color: white;
    padding: 8px 10px;
    text-align: left;
    font-weight: bold;
}

td {
    padding: 7px 10px;
    border-bottom: 1px solid #dce1e5;
}

tr:nth-child(even) td {
    background: #f8f9fa;
}

hr {
    border: none;
    border-top: 1px solid #dce1e5;
    margin: 24px 0;
}

ul, ol {
    padding-left: 22px;
}

li {
    margin-bottom: 4px;
}
"""

# -----------------------------------------------------------------------------
# Conversie
# -----------------------------------------------------------------------------

with open(MD_FILE, "r", encoding="utf-8") as f:
    md_content = f.read()

html_body = markdown.markdown(
    md_content,
    extensions=["tables", "fenced_code"],
)

full_html = f"""<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="utf-8">
    <style>{CSS}</style>
</head>
<body>
{html_body}
</body>
</html>"""

options = {
    "page-size": "A4",
    "margin-top": "2cm",
    "margin-bottom": "2cm",
    "margin-left": "2.5cm",
    "margin-right": "2.5cm",
    "encoding": "UTF-8",
    "footer-center": "Pagina [page] din [topage]",
    "footer-font-size": "9",
    "footer-spacing": "5",
}

config = get_pdfkit_config()
pdfkit.from_string(full_html, str(PDF_FILE), options=options, configuration=config)
print(f"PDF generat: {PDF_FILE}")