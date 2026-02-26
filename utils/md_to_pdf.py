#!/usr/bin/env python3
"""Conversie PREZENTARE_PROIECT_IDS-RS.md -> PDF cu weasyprint."""

import markdown
from weasyprint import HTML

MD_FILE = "PREZENTARE_PROIECT_IDS-RS.md"
PDF_FILE = "PREZENTARE_PROIECT_IDS-RS.pdf"

CSS = """
@page {
    size: A4;
    margin: 2cm 2.5cm;
    @bottom-center {
        content: "Pagina " counter(page) " din " counter(pages);
        font-size: 9px;
        color: #888;
    }
}

body {
    font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.5;
    color: #1a1a1a;
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
    overflow-x: auto;
    white-space: pre;
    font-family: "DejaVu Sans Mono", "Liberation Mono", "Courier New", monospace;
    page-break-inside: avoid;
}

code {
    font-family: "DejaVu Sans Mono", "Liberation Mono", "Courier New", monospace;
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

HTML(string=full_html).write_pdf(PDF_FILE)
print(f"PDF generat: {PDF_FILE}")
