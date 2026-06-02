#!/usr/bin/env python3
"""
Generate a PPTX presentation for IDS-RS without external Python packages.

The file is built as a minimal Office Open XML presentation so it can be
opened in PowerPoint, LibreOffice Impress, or OnlyOffice.
"""

from __future__ import annotations

import html
import mimetypes
import shutil
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "utils" / "Prezentare" / "IDS-RS_PREZENTARE_PROIECT.pptx"
MEDIA_DIR = ROOT / "utils" / "Prezentare"

SLIDE_W = 13_333_333
SLIDE_H = 7_500_000

COL_BG = "0F172A"
COL_PANEL = "172033"
COL_PANEL_2 = "1E293B"
COL_TEXT = "F8FAFC"
COL_MUTED = "CBD5E1"
COL_BLUE = "38BDF8"
COL_GREEN = "22C55E"
COL_ORANGE = "F97316"
COL_RED = "EF4444"
COL_YELLOW = "FACC15"


def esc(value: str) -> str:
    return html.escape(value, quote=True)


def a_ns() -> str:
    return (
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'
    )


def text_box(
    shape_id: int,
    x: int,
    y: int,
    cx: int,
    cy: int,
    text: str,
    font_size: int = 28,
    color: str = COL_TEXT,
    bold: bool = False,
    align: str = "l",
    fill: str | None = None,
    radius: bool = False,
    line: str | None = None,
) -> str:
    lines = text.split("\n")
    body = []
    for line_text in lines:
        bullet = line_text.startswith("- ")
        clean = line_text[2:] if bullet else line_text
        bu = '<a:buChar char="•"/>' if bullet else "<a:buNone/>"
        body.append(
            f'<a:p><a:pPr algn="{align}">{bu}</a:pPr>'
            f'<a:r><a:rPr lang="ro-RO" sz="{font_size * 100}" dirty="0">'
            f'{"<a:b/>" if bold else ""}<a:solidFill><a:srgbClr val="{color}"/></a:solidFill>'
            f'</a:rPr><a:t>{esc(clean)}</a:t></a:r></a:p>'
        )
    fill_xml = (
        f'<a:solidFill><a:srgbClr val="{fill}"/></a:solidFill>'
        if fill
        else "<a:noFill/>"
    )
    line_xml = (
        f'<a:ln w="9000"><a:solidFill><a:srgbClr val="{line}"/></a:solidFill></a:ln>'
        if line
        else "<a:ln><a:noFill/></a:ln>"
    )
    preset = "roundRect" if radius else "rect"
    return f"""
    <p:sp>
      <p:nvSpPr><p:cNvPr id="{shape_id}" name="TextBox {shape_id}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
      <p:spPr>
        <a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>
        <a:prstGeom prst="{preset}"><a:avLst/></a:prstGeom>
        {fill_xml}
        {line_xml}
      </p:spPr>
      <p:txBody>
        <a:bodyPr wrap="square" anchor="mid"><a:spAutoFit/></a:bodyPr>
        <a:lstStyle/>
        {''.join(body)}
      </p:txBody>
    </p:sp>
    """


def image_box(shape_id: int, rel_id: str, x: int, y: int, cx: int, cy: int) -> str:
    return f"""
    <p:pic>
      <p:nvPicPr><p:cNvPr id="{shape_id}" name="Picture {shape_id}"/><p:cNvPicPr/><p:nvPr/></p:nvPicPr>
      <p:blipFill><a:blip r:embed="{rel_id}"/><a:stretch><a:fillRect/></a:stretch></p:blipFill>
      <p:spPr><a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>
    </p:pic>
    """


def rect(shape_id: int, x: int, y: int, cx: int, cy: int, fill: str, alpha: int | None = None) -> str:
    alpha_xml = f'<a:alpha val="{alpha}"/>' if alpha is not None else ""
    return f"""
    <p:sp>
      <p:nvSpPr><p:cNvPr id="{shape_id}" name="Rect {shape_id}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
      <p:spPr>
        <a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>
        <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
        <a:solidFill><a:srgbClr val="{fill}">{alpha_xml}</a:srgbClr></a:solidFill>
        <a:ln><a:noFill/></a:ln>
      </p:spPr>
      <p:txBody><a:bodyPr/><a:lstStyle/><a:p/></p:txBody>
    </p:sp>
    """


def pill(shape_id: int, x: int, y: int, text: str, fill: str, width: int = 1_500_000) -> str:
    return text_box(shape_id, x, y, width, 380_000, text, 16, COL_TEXT, True, "ctr", fill, True)


def slide_xml(shapes: list[str]) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld {a_ns()}>
  <p:cSld>
    <p:bg><p:bgPr><a:solidFill><a:srgbClr val="{COL_BG}"/></a:solidFill></p:bgPr></p:bg>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
      {''.join(shapes)}
    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sld>"""


def rels_xml(rels: list[tuple[str, str, str]]) -> str:
    parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">',
    ]
    for rid, typ, target in rels:
        parts.append(f'<Relationship Id="{rid}" Type="{typ}" Target="{target}"/>')
    parts.append("</Relationships>")
    return "".join(parts)


def image_ext(path: Path) -> str:
    mime, _ = mimetypes.guess_type(path.name)
    return (mime or "image/png").split("/")[-1]


def build_slides() -> list[dict]:
    img_struct = "Structra.png"
    img_block = "blocheaza.png"
    img_mail = "mail_exemple.png"
    img_dashboard = "Gemini_Generated_Image_hf0q6ihf0q6ihf0q.png"

    slides: list[dict] = []

    slides.append(
        {
            "title": "IDS-RS",
            "images": [img_block],
            "shapes": [
                image_box(2, "rId2", 0, 0, SLIDE_W, SLIDE_H),
                rect(3, 0, 0, SLIDE_W, SLIDE_H, "020617", 25000),
                text_box(4, 650_000, 850_000, 6_400_000, 1_200_000, "IDS-RS", 58, COL_TEXT, True),
                text_box(
                    5,
                    650_000,
                    1_850_000,
                    8_200_000,
                    900_000,
                    "Intrusion Detection System în Rust pentru corelarea log-urilor de firewall",
                    24,
                    COL_MUTED,
                ),
                pill(6, 650_000, 3_050_000, "Rust", COL_BLUE, 1_100_000),
                pill(7, 1_850_000, 3_050_000, "Firewall logs", COL_GREEN, 1_650_000),
                pill(8, 3_600_000, 3_050_000, "SIEM + Email + Web", COL_ORANGE, 2_300_000),
                text_box(9, 650_000, 6_650_000, 5_000_000, 420_000, "Prezentare proiect", 18, COL_MUTED),
            ],
        }
    )

    slides.append(
        {
            "title": "Problema",
            "images": [],
            "shapes": [
                text_box(2, 650_000, 500_000, 6_000_000, 620_000, "Problema: log-uri multe, corelare puțină", 34, COL_TEXT, True),
                text_box(
                    3,
                    750_000,
                    1_500_000,
                    5_800_000,
                    3_900_000,
                    "- Firewall-ul raportează corect fiecare conexiune blocată, dar per eveniment individual.\n- Un IP care încearcă zeci de porturi produce zeci de log-uri separate.\n- Fără corelare automată, scanările și mișcarea laterală sunt observate târziu.\n- Echipa are nevoie de alertare în timp real, nu doar analiză post-factum.",
                    23,
                    COL_TEXT,
                    fill=COL_PANEL,
                    radius=True,
                ),
                text_box(4, 7_250_000, 1_500_000, 2_300_000, 1_450_000, "20+\nlog-uri", 34, COL_YELLOW, True, "ctr", COL_PANEL_2, True),
                text_box(5, 9_850_000, 1_500_000, 2_300_000, 1_450_000, "10 sec\nfereastră", 34, COL_BLUE, True, "ctr", COL_PANEL_2, True),
                text_box(6, 7_250_000, 3_300_000, 4_900_000, 1_400_000, "Semnalul există deja în infrastructură. IDS-RS îl transformă în alertă acționabilă.", 26, COL_TEXT, True, "ctr", COL_PANEL_2, True),
            ],
        }
    )

    slides.append(
        {
            "title": "Soluția",
            "images": [img_block],
            "shapes": [
                text_box(2, 650_000, 450_000, 6_000_000, 560_000, "Soluția: IDS-RS corelează comportamente", 34, COL_TEXT, True),
                image_box(3, "rId2", 500_000, 1_250_000, 12_000_000, 5_250_000),
                text_box(
                    4,
                    7_550_000,
                    5_700_000,
                    4_200_000,
                    700_000,
                    "Firewall-ul blochează conexiuni. IDS-RS detectează tiparul.",
                    22,
                    COL_TEXT,
                    True,
                    "ctr",
                    COL_PANEL,
                    True,
                ),
            ],
        }
    )

    slides.append(
        {
            "title": "Arhitectură",
            "images": [img_struct],
            "shapes": [
                text_box(2, 650_000, 450_000, 5_500_000, 560_000, "Arhitectura fluxului", 34, COL_TEXT, True),
                image_box(3, "rId2", 600_000, 1_190_000, 6_200_000, 5_500_000),
                text_box(
                    4,
                    7_150_000,
                    1_300_000,
                    4_900_000,
                    4_800_000,
                    "- UDP listener pe portul 5555\n- Parser selectabil: Gaia, CEF, Gaia-CEF\n- Detector thread-safe cu DashMap\n- Alertare către ArcSight CEF și SMTP\n- Dashboard web embedded, read-only",
                    24,
                    COL_TEXT,
                    fill=COL_PANEL,
                    radius=True,
                ),
            ],
        }
    )

    slides.append(
        {
            "title": "Detecții",
            "images": [],
            "shapes": [
                text_box(2, 650_000, 450_000, 6_000_000, 560_000, "Ce detectează", 34, COL_TEXT, True),
                text_box(3, 650_000, 1_250_000, 3_800_000, 1_150_000, "Fast Scan\n15 porturi / 10s", 24, COL_TEXT, True, "ctr", COL_PANEL, True),
                text_box(4, 4_650_000, 1_250_000, 3_800_000, 1_150_000, "Slow Scan\n30 porturi / 5 min", 24, COL_TEXT, True, "ctr", COL_PANEL, True),
                text_box(5, 8_650_000, 1_250_000, 3_800_000, 1_150_000, "Accept Scan\n5 porturi acceptate / 30s", 22, COL_TEXT, True, "ctr", COL_PANEL, True),
                text_box(6, 650_000, 2_850_000, 3_800_000, 1_250_000, "Lateral Movement\n1 sursă → N destinații", 23, COL_RED, True, "ctr", COL_PANEL_2, True),
                text_box(7, 4_650_000, 2_850_000, 3_800_000, 1_250_000, "Distributed Scan\nN surse → 1 țintă", 23, COL_ORANGE, True, "ctr", COL_PANEL_2, True),
                text_box(8, 8_650_000, 2_850_000, 3_800_000, 1_250_000, "Beaconing C2\nflow periodic, CV pe intervale", 22, COL_YELLOW, True, "ctr", COL_PANEL_2, True),
                text_box(9, 900_000, 5_250_000, 11_500_000, 780_000, "Pragurile, ferestrele de timp, cooldown-ul și excepțiile sunt configurabile din config.toml.", 25, COL_MUTED, False, "ctr"),
            ],
        }
    )

    slides.append(
        {
            "title": "Alertare",
            "images": [img_mail],
            "shapes": [
                text_box(2, 650_000, 450_000, 5_500_000, 560_000, "Ce primește echipa", 34, COL_TEXT, True),
                text_box(
                    3,
                    650_000,
                    1_250_000,
                    5_300_000,
                    4_900_000,
                    "- Eveniment CEF standard în SIEM\n- Email HTML cu IP sursă, IP destinație, porturi și severitate\n- Comenzi rapide pentru verificare și reacție pe RHEL\n- Cooldown per IP / flow pentru evitarea spamului de alerte",
                    24,
                    COL_TEXT,
                    fill=COL_PANEL,
                    radius=True,
                ),
                image_box(4, "rId2", 6_450_000, 1_050_000, 5_300_000, 5_900_000),
            ],
        }
    )

    slides.append(
        {
            "title": "WebDashboard",
            "images": [img_dashboard],
            "shapes": [
                image_box(2, "rId2", 0, 0, SLIDE_W, SLIDE_H),
                rect(3, 0, 0, SLIDE_W, SLIDE_H, "020617", 42000),
                text_box(4, 650_000, 500_000, 5_200_000, 600_000, "WebDashboard IDS-RS", 36, COL_TEXT, True),
                text_box(
                    5,
                    650_000,
                    1_350_000,
                    5_700_000,
                    3_750_000,
                    "- Hartă live a alertelor: atacatori, ținte și conexiuni\n- Filtre pe severitate și tip de detecție\n- IP dossier pentru investigație rapidă\n- Replay, workspace, triage și export PNG\n- Read-only, local/offline, fără dependență de internet",
                    24,
                    COL_TEXT,
                    fill=COL_PANEL,
                    radius=True,
                ),
                text_box(6, 650_000, 5_650_000, 3_850_000, 580_000, "http://127.0.0.1:8080", 24, COL_BLUE, True, "ctr", COL_PANEL_2, True),
            ],
        }
    )

    slides.append(
        {
            "title": "Securitate",
            "images": [],
            "shapes": [
                text_box(2, 650_000, 450_000, 7_200_000, 560_000, "Securitatea și reziliența sistemului", 34, COL_TEXT, True),
                text_box(3, 650_000, 1_350_000, 3_900_000, 1_300_000, "Flood UDP\nToken Bucket rate limiting", 23, COL_TEXT, True, "ctr", COL_PANEL, True),
                text_box(4, 4_750_000, 1_350_000, 3_900_000, 1_300_000, "Memorie per IP\nMAX_HITS_PER_IP FIFO", 23, COL_TEXT, True, "ctr", COL_PANEL, True),
                text_box(5, 8_850_000, 1_350_000, 3_900_000, 1_300_000, "Memorie globală\nMAX_TRACKED_IPS LRU", 23, COL_TEXT, True, "ctr", COL_PANEL, True),
                text_box(6, 650_000, 3_050_000, 3_900_000, 1_300_000, "SIEM injection\nSanitizare câmpuri CEF", 23, COL_TEXT, True, "ctr", COL_PANEL_2, True),
                text_box(7, 4_750_000, 3_050_000, 3_900_000, 1_300_000, "Config greșit\nValidări semantice la startup", 23, COL_TEXT, True, "ctr", COL_PANEL_2, True),
                text_box(8, 8_850_000, 3_050_000, 3_900_000, 1_300_000, "Operare\nHot reload + graceful shutdown", 23, COL_TEXT, True, "ctr", COL_PANEL_2, True),
                text_box(9, 1_300_000, 5_500_000, 10_700_000, 650_000, "Rezultat verificat în repo: cargo test -> 79 passed, 0 failed.", 27, COL_GREEN, True, "ctr"),
            ],
        }
    )

    slides.append(
        {
            "title": "Stack",
            "images": [],
            "shapes": [
                text_box(2, 650_000, 450_000, 5_000_000, 560_000, "Stack tehnic", 34, COL_TEXT, True),
                text_box(3, 800_000, 1_350_000, 3_700_000, 3_700_000, "Rust\nTokio\nDashMap\nArcSwap", 30, COL_BLUE, True, "ctr", COL_PANEL, True),
                text_box(4, 4_850_000, 1_350_000, 3_700_000, 3_700_000, "Serde + TOML\nRegex\nChrono\nAnyhow", 29, COL_GREEN, True, "ctr", COL_PANEL, True),
                text_box(5, 8_900_000, 1_350_000, 3_700_000, 3_700_000, "Axum\nD3.js local\nLettre SMTP\nCEF UDP", 29, COL_ORANGE, True, "ctr", COL_PANEL, True),
                text_box(6, 1_200_000, 5_700_000, 10_800_000, 550_000, "Un singur binar: ingestie UDP, detecție, alertare și dashboard web.", 25, COL_MUTED, False, "ctr"),
            ],
        }
    )

    slides.append(
        {
            "title": "Demo",
            "images": [],
            "shapes": [
                text_box(2, 650_000, 450_000, 5_000_000, 560_000, "Scenariu de demo", 34, COL_TEXT, True),
                text_box(
                    3,
                    850_000,
                    1_250_000,
                    11_300_000,
                    4_900_000,
                    "1. Pornim IDS-RS cu dashboard-ul activ.\n2. Deschidem http://127.0.0.1:8080.\n3. Rulăm testerul pentru un scenariu fast / lateral / beaconing.\n4. Urmărim alerta în terminal, SIEM/email și graf.\n5. Filtrăm pe severitate, deschidem IP dossier și exportăm imaginea pentru raport.",
                    25,
                    COL_TEXT,
                    fill=COL_PANEL,
                    radius=True,
                ),
                text_box(4, 1_100_000, 6_280_000, 5_100_000, 520_000, "python3 tester/tester.py fast", 22, COL_YELLOW, True, "ctr", COL_PANEL_2, True),
                text_box(5, 6_650_000, 6_280_000, 4_900_000, 520_000, "cargo run --release", 22, COL_GREEN, True, "ctr", COL_PANEL_2, True),
            ],
        }
    )

    slides.append(
        {
            "title": "Valoare",
            "images": [],
            "shapes": [
                text_box(2, 650_000, 450_000, 5_000_000, 560_000, "Valoare pentru echipă", 34, COL_TEXT, True),
                text_box(3, 750_000, 1_350_000, 3_700_000, 3_650_000, "Tehnic\n- Detecție automată 24/7\n- Corelare per IP, țintă și flow\n- Răspuns în secunde", 24, COL_TEXT, True, "ctr", COL_PANEL, True),
                text_box(4, 4_650_000, 1_350_000, 3_700_000, 3_650_000, "Operațional\n- Config centralizat\n- Compatibil Checkpoint + ArcSight\n- Implementare graduală", 24, COL_TEXT, True, "ctr", COL_PANEL, True),
                text_box(5, 8_550_000, 1_350_000, 3_700_000, 3_650_000, "Business\n- Dezvoltat intern\n- Fără licențe recurente\n- Evidență pentru audit", 24, COL_TEXT, True, "ctr", COL_PANEL, True),
            ],
        }
    )

    slides.append(
        {
            "title": "Pași următori",
            "images": [],
            "shapes": [
                text_box(2, 650_000, 450_000, 6_200_000, 560_000, "Pași următori", 34, COL_TEXT, True),
                text_box(
                    3,
                    850_000,
                    1_350_000,
                    11_000_000,
                    4_500_000,
                    "- Rulare operațională pe log-uri firewall reale.\n- Calibrare praguri și whitelist pe traficul normal.\n- Extindere cu parser FortiGate / Cisco ASA / iptables.\n- Export CSV/JSON per sesiune și raport zilnic.\n- Posibilă integrare cu log-uri switching/routing prin modele de evenimente dedicate.",
                    25,
                    COL_TEXT,
                    fill=COL_PANEL,
                    radius=True,
                ),
                text_box(4, 2_300_000, 6_230_000, 8_700_000, 600_000, "IDS-RS: vizibilitate rapidă peste semnale deja existente în rețea.", 25, COL_BLUE, True, "ctr"),
            ],
        }
    )

    return slides


def write_pptx(slides: list[dict]) -> None:
    tmp = ROOT / "target" / "ids_rs_pptx_build"
    if tmp.exists():
        shutil.rmtree(tmp)
    (tmp / "_rels").mkdir(parents=True)
    (tmp / "docProps").mkdir()
    (tmp / "ppt" / "_rels").mkdir(parents=True)
    (tmp / "ppt" / "slideMasters" / "_rels").mkdir(parents=True)
    (tmp / "ppt" / "slideLayouts" / "_rels").mkdir(parents=True)
    (tmp / "ppt" / "slides" / "_rels").mkdir(parents=True)
    (tmp / "ppt" / "media").mkdir(parents=True)
    (tmp / "ppt" / "theme").mkdir(parents=True)

    (tmp / "_rels" / ".rels").write_text(
        rels_xml(
            [
                ("rId1", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument", "ppt/presentation.xml"),
                ("rId2", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", "docProps/core.xml"),
                ("rId3", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties", "docProps/app.xml"),
            ]
        ),
        encoding="utf-8",
    )

    (tmp / "docProps" / "core.xml").write_text(
        """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>IDS-RS - Prezentare proiect</dc:title>
  <dc:creator>IDS-RS</dc:creator>
  <cp:lastModifiedBy>IDS-RS</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">2026-06-02T00:00:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2026-06-02T00:00:00Z</dcterms:modified>
</cp:coreProperties>""",
        encoding="utf-8",
    )

    (tmp / "docProps" / "app.xml").write_text(
        f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>IDS-RS generator</Application>
  <PresentationFormat>Widescreen</PresentationFormat>
  <Slides>{len(slides)}</Slides>
</Properties>""",
        encoding="utf-8",
    )

    pres_rels = []
    slide_ids = []
    media_counter = 1
    content_overrides = [
        '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>',
        '<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>',
        '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>',
        '<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>',
    ]

    for idx, slide in enumerate(slides, start=1):
        (tmp / "ppt" / "slides" / f"slide{idx}.xml").write_text(slide_xml(slide["shapes"]), encoding="utf-8")
        content_overrides.append(
            f'<Override PartName="/ppt/slides/slide{idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        )
        slide_ids.append((255 + idx, idx))
        pres_rels.append(
            (f"rId{idx}", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide", f"slides/slide{idx}.xml")
        )

        slide_rels = [
            (
                "rId1",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout",
                "../slideLayouts/slideLayout1.xml",
            )
        ]
        for img_idx, image_name in enumerate(slide.get("images", []), start=2):
            src = MEDIA_DIR / image_name
            ext = src.suffix.lower().lstrip(".") or "png"
            dst_name = f"image{media_counter}.{ext}"
            shutil.copyfile(src, tmp / "ppt" / "media" / dst_name)
            slide_rels.append(
                (
                    f"rId{img_idx}",
                    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
                    f"../media/{dst_name}",
                )
            )
            media_counter += 1
        (tmp / "ppt" / "slides" / "_rels" / f"slide{idx}.xml.rels").write_text(rels_xml(slide_rels), encoding="utf-8")

    pres_rels.append(
        (
            f"rId{len(slides) + 1}",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster",
            "slideMasters/slideMaster1.xml",
        )
    )
    (tmp / "ppt" / "_rels" / "presentation.xml.rels").write_text(rels_xml(pres_rels), encoding="utf-8")

    (tmp / "ppt" / "slideMasters" / "_rels" / "slideMaster1.xml.rels").write_text(
        rels_xml(
            [
                ("rId1", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout", "../slideLayouts/slideLayout1.xml"),
                ("rId2", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme", "../theme/theme1.xml"),
            ]
        ),
        encoding="utf-8",
    )
    (tmp / "ppt" / "slideLayouts" / "_rels" / "slideLayout1.xml.rels").write_text(
        rels_xml(
            [
                ("rId1", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster", "../slideMasters/slideMaster1.xml"),
            ]
        ),
        encoding="utf-8",
    )

    (tmp / "ppt" / "slideMasters" / "slideMaster1.xml").write_text(
        f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster {a_ns()}>
  <p:cSld>
    <p:bg><p:bgPr><a:solidFill><a:srgbClr val="{COL_BG}"/></a:solidFill></p:bgPr></p:bg>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>
  <p:txStyles><p:titleStyle/><p:bodyStyle/><p:otherStyle/></p:txStyles>
</p:sldMaster>""",
        encoding="utf-8",
    )
    (tmp / "ppt" / "slideLayouts" / "slideLayout1.xml").write_text(
        f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout {a_ns()} type="blank" preserve="1">
  <p:cSld name="Blank">
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sldLayout>""",
        encoding="utf-8",
    )
    (tmp / "ppt" / "theme" / "theme1.xml").write_text(
        f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="IDS-RS">
  <a:themeElements>
    <a:clrScheme name="IDS-RS">
      <a:dk1><a:srgbClr val="{COL_BG}"/></a:dk1><a:lt1><a:srgbClr val="{COL_TEXT}"/></a:lt1>
      <a:dk2><a:srgbClr val="{COL_PANEL}"/></a:dk2><a:lt2><a:srgbClr val="{COL_MUTED}"/></a:lt2>
      <a:accent1><a:srgbClr val="{COL_BLUE}"/></a:accent1><a:accent2><a:srgbClr val="{COL_GREEN}"/></a:accent2>
      <a:accent3><a:srgbClr val="{COL_ORANGE}"/></a:accent3><a:accent4><a:srgbClr val="{COL_RED}"/></a:accent4>
      <a:accent5><a:srgbClr val="{COL_YELLOW}"/></a:accent5><a:accent6><a:srgbClr val="{COL_MUTED}"/></a:accent6>
      <a:hlink><a:srgbClr val="{COL_BLUE}"/></a:hlink><a:folHlink><a:srgbClr val="{COL_GREEN}"/></a:folHlink>
    </a:clrScheme>
    <a:fontScheme name="IDS-RS"><a:majorFont><a:latin typeface="Aptos Display"/></a:majorFont><a:minorFont><a:latin typeface="Aptos"/></a:minorFont></a:fontScheme>
    <a:fmtScheme name="IDS-RS"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme>
  </a:themeElements>
</a:theme>""",
        encoding="utf-8",
    )

    slide_id_xml = "".join(f'<p:sldId id="{sid}" r:id="rId{idx}"/>' for sid, idx in slide_ids)
    (tmp / "ppt" / "presentation.xml").write_text(
        f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId{len(slides) + 1}"/></p:sldMasterIdLst>
  <p:sldIdLst>{slide_id_xml}</p:sldIdLst>
  <p:sldSz cx="{SLIDE_W}" cy="{SLIDE_H}" type="wide"/>
  <p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>""",
        encoding="utf-8",
    )

    defaults = [
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
        '<Default Extension="png" ContentType="image/png"/>',
    ]
    (tmp / "[Content_Types].xml").write_text(
        f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  {''.join(defaults)}
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
  {''.join(content_overrides)}
</Types>""",
        encoding="utf-8",
    )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    if OUT.exists():
        OUT.unlink()
    with zipfile.ZipFile(OUT, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file in sorted(tmp.rglob("*")):
            if file.is_file():
                zf.write(file, file.relative_to(tmp).as_posix())


def main() -> None:
    slides = build_slides()
    write_pptx(slides)
    print(f"Generated {OUT}")


if __name__ == "__main__":
    main()
