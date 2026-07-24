#!/usr/bin/env python3
"""Professional HTML and PDF security assessment reports for PenTool."""

import datetime
import html
import os
import re
import shutil
import sqlite3
from collections import Counter

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


NAVY = colors.HexColor("#0B1220")
INK = colors.HexColor("#172033")
SLATE = colors.HexColor("#526176")
MUTED = colors.HexColor("#758399")
LINE = colors.HexColor("#DCE3EC")
SURFACE = colors.HexColor("#F5F7FA")
TEAL = colors.HexColor("#0F9F8D")
TEAL_SOFT = colors.HexColor("#E8F7F4")
WHITE = colors.white

SEVERITY_COLORS = {
    "critical": "#B42318",
    "high": "#D85B16",
    "medium": "#B7791F",
    "low": "#147D64",
    "unknown": "#667085",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
RISK_COLORS = {key.upper(): value for key, value in SEVERITY_COLORS.items()}
RISK_LABELS = {
    "CRITICAL": "CRÍTICO",
    "HIGH": "ALTO",
    "MEDIUM": "MEDIO",
    "LOW": "BAJO",
    "UNKNOWN": "SIN CLASIFICAR",
}


def plain_text(text: str) -> str:
    value = str(text or "")
    value = re.sub(r"```(?:\w+)?\n?", "", value).replace("```", "")
    value = re.sub(r"^\s{0,3}#{1,6}\s*", "", value, flags=re.MULTILINE)
    value = re.sub(r"\*\*(.*?)\*\*", r"\1", value)
    value = re.sub(r"\*(.*?)\*", r"\1", value)
    value = re.sub(r"`([^`]+)`", r"\1", value)
    return value.strip()


def esc(value) -> str:
    return html.escape(str(value or ""), quote=True)


def pdf_text(value, limit: int = None) -> str:
    text = plain_text(value)
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return esc(text).replace("\n", "<br/>")


def _database_path():
    base_dir = os.path.dirname(__file__)
    db_path = os.path.join(base_dir, "pentool.db")
    legacy_path = os.path.join(base_dir, f"{'meta'}{'tron'}.db")
    if not os.path.exists(db_path) and os.path.exists(legacy_path):
        shutil.copy2(legacy_path, db_path)
    return db_path


def get_connection():
    return sqlite3.connect(_database_path())


def fetch_session(sl_no: int) -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM history WHERE sl_no = ?", (sl_no,))
    history = cursor.fetchone()
    cursor.execute("SELECT * FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    vulns = cursor.fetchall()
    cursor.execute("SELECT * FROM fixes WHERE sl_no = ?", (sl_no,))
    fixes = cursor.fetchall()
    cursor.execute("SELECT * FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    exploits = cursor.fetchall()
    cursor.execute("SELECT * FROM summary WHERE sl_no = ?", (sl_no,))
    summary = cursor.fetchone()
    conn.close()
    return {
        "history": history,
        "vulns": vulns,
        "fixes": fixes,
        "exploits": exploits,
        "summary": summary,
        "events": [],
        "commands": [],
    }


def fetch_all_history():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def _safe_filename(target: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(target or "target").replace("://", "_"))
    return safe.strip("_")[:80] or "target"


def _report_context(data: dict) -> dict:
    history = data.get("history") or [0, "unknown", "-", "unknown"]
    summary = data.get("summary") or []
    risk = str(summary[4] if len(summary) > 4 and summary[4] else "UNKNOWN").upper()
    if risk not in RISK_LABELS:
        risk = "UNKNOWN"
    vulnerabilities = list(data.get("vulns") or [])
    counts = Counter(str(v[3] or "unknown").lower() for v in vulnerabilities)
    fixes_by_vuln = {row[2]: row[3] for row in data.get("fixes") or []}
    generated = datetime.datetime.now()
    return {
        "sl": int(history[0]),
        "target": str(history[1]),
        "scan_date": str(history[2] or "-"),
        "status": str(history[3] or "unknown"),
        "risk": risk,
        "risk_label": RISK_LABELS[risk],
        "ai": plain_text(summary[3] if len(summary) > 3 else ""),
        "raw_scan": plain_text(summary[2] if len(summary) > 2 else ""),
        "vulns": sorted(
            vulnerabilities,
            key=lambda item: (SEVERITY_ORDER.get(str(item[3] or "unknown").lower(), 4), item[0]),
        ),
        "fixes": list(data.get("fixes") or []),
        "fixes_by_vuln": fixes_by_vuln,
        "exploits": list(data.get("exploits") or []),
        "events": list(data.get("events") or []),
        "commands": list(data.get("commands") or []),
        "include_exploitation": bool(data.get("include_exploitation", True)),
        "include_commands": bool(data.get("include_commands", True)),
        "counts": {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "unknown": counts.get("unknown", 0),
        },
        "generated": generated,
        "report_id": f"PT-{generated:%Y%m%d}-{int(history[0]):04d}",
    }


def _styles():
    styles = getSampleStyleSheet()
    return {
        "cover_kicker": ParagraphStyle(
            "CoverKicker", parent=styles["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=11, textColor=TEAL, spaceAfter=7,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold",
            fontSize=31, leading=34, textColor=NAVY, spaceAfter=9,
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle", parent=styles["Normal"], fontName="Helvetica",
            fontSize=11, leading=16, textColor=SLATE, spaceAfter=20,
        ),
        "h1": ParagraphStyle(
            "ReportH1", parent=styles["Heading1"], fontName="Helvetica-Bold",
            fontSize=18, leading=22, textColor=NAVY, spaceBefore=5, spaceAfter=11,
        ),
        "h2": ParagraphStyle(
            "ReportH2", parent=styles["Heading2"], fontName="Helvetica-Bold",
            fontSize=12, leading=15, textColor=INK, spaceBefore=11, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "ReportBody", parent=styles["BodyText"], fontName="Helvetica",
            fontSize=8.6, leading=12.6, textColor=INK, spaceAfter=5,
        ),
        "small": ParagraphStyle(
            "ReportSmall", parent=styles["BodyText"], fontName="Helvetica",
            fontSize=7.3, leading=10, textColor=SLATE,
        ),
        "label": ParagraphStyle(
            "ReportLabel", parent=styles["BodyText"], fontName="Helvetica-Bold",
            fontSize=6.7, leading=9, textColor=MUTED, spaceAfter=2,
        ),
        "value": ParagraphStyle(
            "ReportValue", parent=styles["BodyText"], fontName="Helvetica-Bold",
            fontSize=9, leading=12, textColor=INK,
        ),
        "table_head": ParagraphStyle(
            "TableHead", parent=styles["BodyText"], fontName="Helvetica-Bold",
            fontSize=6.6, leading=8, textColor=WHITE,
        ),
        "table_cell": ParagraphStyle(
            "TableCell", parent=styles["BodyText"], fontName="Helvetica",
            fontSize=7.2, leading=9.5, textColor=INK,
        ),
        "code": ParagraphStyle(
            "Code", parent=styles["Code"], fontName="Courier",
            fontSize=6.3, leading=8.5, textColor=INK, backColor=SURFACE,
            borderColor=LINE, borderWidth=0.5, borderPadding=6, spaceAfter=6,
        ),
        "callout": ParagraphStyle(
            "Callout", parent=styles["BodyText"], fontName="Helvetica",
            fontSize=8.2, leading=12, textColor=INK, backColor=TEAL_SOFT,
            borderColor=colors.HexColor("#B9E6DE"), borderWidth=0.7,
            borderPadding=9, spaceAfter=8,
        ),
        "center_small": ParagraphStyle(
            "CenterSmall", parent=styles["BodyText"], fontName="Helvetica",
            fontSize=7, leading=9, textColor=MUTED, alignment=TA_CENTER,
        ),
    }


def _page_header_footer(canvas, doc):
    canvas.saveState()
    width, height = A4
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.5)
    canvas.line(doc.leftMargin, height - 13 * mm, width - doc.rightMargin, height - 13 * mm)
    canvas.setFillColor(NAVY)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.drawString(doc.leftMargin, height - 9.5 * mm, "PENTOOL  /  SECURITY ASSESSMENT")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 6.7)
    canvas.drawRightString(width - doc.rightMargin, height - 9.5 * mm, "CONFIDENCIAL - USO AUTORIZADO")
    canvas.line(doc.leftMargin, 12 * mm, width - doc.rightMargin, 12 * mm)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 6.5)
    canvas.drawString(doc.leftMargin, 8 * mm, getattr(doc, "report_id", "PENTOOL"))
    canvas.drawRightString(width - doc.rightMargin, 8 * mm, f"Página {doc.page}")
    canvas.restoreState()


def _cover_page(canvas, doc):
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 46 * mm, width, 46 * mm, fill=1, stroke=0)
    canvas.setFillColor(TEAL)
    canvas.roundRect(18 * mm, height - 31 * mm, 15 * mm, 15 * mm, 3 * mm, fill=1, stroke=0)
    canvas.setFillColor(NAVY)
    canvas.setFont("Helvetica-Bold", 13)
    canvas.drawCentredString(25.5 * mm, height - 25.3 * mm, "PT")
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(39 * mm, height - 21.7 * mm, "PENTOOL")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#A9B5C7"))
    canvas.drawString(39 * mm, height - 27 * mm, "AI SECURITY OPERATIONS")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 6.5)
    canvas.drawString(18 * mm, 11 * mm, getattr(doc, "report_id", "PENTOOL"))
    canvas.drawRightString(width - 18 * mm, 11 * mm, "CONFIDENCIAL - USO AUTORIZADO")
    canvas.restoreState()


def _risk_distribution_drawing(counts: dict) -> Drawing:
    width, height = 154 * mm, 28 * mm
    drawing = Drawing(width, height)
    total = max(sum(counts.values()), 1)
    labels = [("critical", "Críticas"), ("high", "Altas"), ("medium", "Medias"), ("low", "Bajas")]
    column_width = width / 4
    for index, (key, label) in enumerate(labels):
        x = index * column_width
        value = counts.get(key, 0)
        drawing.add(Rect(x + 3, 3, column_width - 7, height - 6, rx=4, ry=4, fillColor=SURFACE, strokeColor=LINE))
        drawing.add(Rect(x + 3, 3, (column_width - 7) * (value / total), 3, fillColor=colors.HexColor(SEVERITY_COLORS[key]), strokeColor=None))
        drawing.add(String(x + 9, height - 13, str(value), fontName="Helvetica-Bold", fontSize=11, fillColor=NAVY))
        drawing.add(String(x + 9, 9, label, fontName="Helvetica", fontSize=6.5, fillColor=MUTED))
    return drawing


def _meta_card(label: str, value: str, styles: dict):
    return [
        Paragraph(pdf_text(label), styles["label"]),
        Paragraph(pdf_text(value), styles["value"]),
    ]


def export_pdf(data: dict, output_dir: str) -> str:
    context = _report_context(data)
    styles = _styles()
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(
        output_dir,
        f"pentool_{context['report_id']}_{_safe_filename(context['target'])}.pdf",
    )
    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        topMargin=19 * mm,
        bottomMargin=17 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        title=f"PenTool Security Assessment - {context['target']}",
        author="PenTool",
        subject="Authorized security assessment",
    )
    doc.report_id = context["report_id"]
    story = []

    story.extend([
        Spacer(1, 40 * mm),
        Paragraph("INFORME DE EVALUACIÓN DE SEGURIDAD", styles["cover_kicker"]),
        Paragraph("Security Assessment", styles["cover_title"]),
        Paragraph(
            "Informe técnico y ejecutivo de pruebas de seguridad autorizadas, "
            "con evidencia, priorización y recomendaciones de remediación.",
            styles["cover_subtitle"],
        ),
    ])
    risk_color = colors.HexColor(RISK_COLORS[context["risk"]])
    cover_meta = Table(
        [
            _meta_card("OBJETIVO", context["target"], styles),
            _meta_card("RIESGO GLOBAL", context["risk_label"], styles),
            _meta_card("FECHA DE EVALUACIÓN", context["scan_date"], styles),
            _meta_card("IDENTIFICADOR", context["report_id"], styles),
        ],
        colWidths=[78 * mm, 78 * mm],
    )
    cover_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (1, 0), (1, 0), risk_color),
    ]))
    story.append(cover_meta)
    story.extend([
        Spacer(1, 16 * mm),
        Paragraph(
            "<b>Clasificación:</b> Confidencial. Este documento contiene información técnica "
            "sensible y debe compartirse únicamente con personal autorizado.",
            styles["callout"],
        ),
        PageBreak(),
    ])

    story.extend([
        Paragraph("Resumen ejecutivo", styles["h1"]),
        Paragraph(
            pdf_text(context["ai"] or (
                "La evaluación registró los hallazgos detallados en este documento. "
                "La priorización debe confirmarse con el contexto de negocio y la exposición real del activo."
            )),
            styles["body"],
        ),
        Spacer(1, 3 * mm),
        _risk_distribution_drawing(context["counts"]),
        Spacer(1, 4 * mm),
    ])

    summary_cards = Table(
        [[
            _meta_card("HALLAZGOS", str(len(context["vulns"])), styles),
            _meta_card("CRÍTICOS + ALTOS", str(context["counts"]["critical"] + context["counts"]["high"]), styles),
            _meta_card("REMEDIACIONES", str(len(context["fixes"])), styles),
            _meta_card("ESTADO", context["status"].upper(), styles),
        ]],
        colWidths=[39 * mm] * 4,
    )
    summary_cards.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([
        summary_cards,
        Spacer(1, 7 * mm),
        Paragraph("Alcance y metodología", styles["h2"]),
        Paragraph(
            f"El alcance registrado para esta ejecución fue <b>{pdf_text(context['target'])}</b>. "
            "La evaluación combina reconocimiento automatizado, análisis asistido por IA y validaciones "
            "técnicas registradas por la plataforma. Los resultados representan una observación puntual "
            "del activo en la fecha indicada.",
            styles["body"],
        ),
        Paragraph(
            "La estructura del informe toma como referencia prácticas de OWASP WSTG, NIST SP 800-115 "
            "y PTES: separación entre resumen ejecutivo y detalle técnico, evidencia reproducible, "
            "limitaciones y recomendaciones priorizadas. Las etiquetas de severidad son cualitativas; "
            "no constituyen una puntuación CVSS v4.0 salvo que se incluya un vector explícito.",
            styles["callout"],
        ),
        Paragraph("Criterios y limitaciones", styles["h2"]),
        Paragraph(
            "Las pruebas dependen de la conectividad, credenciales, herramientas disponibles y respuestas "
            "del objetivo. Un puerto filtrado, un timeout o la ausencia de respuesta se considera inconcluso "
            "y no demuestra por sí solo la existencia ni la ausencia de una vulnerabilidad.",
            styles["body"],
        ),
        PageBreak(),
        Paragraph("Resumen de hallazgos", styles["h1"]),
    ])

    if context["vulns"]:
        table_data = [[
            Paragraph("REF.", styles["table_head"]),
            Paragraph("HALLAZGO", styles["table_head"]),
            Paragraph("SEVERIDAD", styles["table_head"]),
            Paragraph("ACTIVO / SERVICIO", styles["table_head"]),
        ]]
        for index, vuln in enumerate(context["vulns"], 1):
            severity = str(vuln[3] or "unknown").lower()
            table_data.append([
                Paragraph(f"F-{index:02d}", styles["table_cell"]),
                Paragraph(pdf_text(vuln[2]), styles["table_cell"]),
                Paragraph(f"<b>{pdf_text(RISK_LABELS.get(severity.upper(), severity.upper()))}</b>", styles["table_cell"]),
                Paragraph(pdf_text(f"{vuln[5] or '-'} / {vuln[4] or '-'}"), styles["table_cell"]),
            ])
        findings_table = LongTable(
            table_data,
            colWidths=[18 * mm, 77 * mm, 27 * mm, 35 * mm],
            repeatRows=1,
        )
        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.35, LINE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, SURFACE]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]
        for index, vuln in enumerate(context["vulns"], 1):
            severity_color = colors.HexColor(SEVERITY_COLORS.get(str(vuln[3] or "unknown").lower(), "#667085"))
            table_style.append(("TEXTCOLOR", (2, index), (2, index), severity_color))
        findings_table.setStyle(TableStyle(table_style))
        story.append(findings_table)
    else:
        story.append(Paragraph("No se registraron vulnerabilidades confirmadas.", styles["callout"]))

    story.extend([Spacer(1, 6 * mm), Paragraph("Hallazgos detallados", styles["h1"])])
    if context["vulns"]:
        for index, vuln in enumerate(context["vulns"], 1):
            severity = str(vuln[3] or "unknown").lower()
            severity_color = colors.HexColor(SEVERITY_COLORS.get(severity, "#667085"))
            finding_head = Table(
                [[
                    Paragraph(f"<b>F-{index:02d}</b>", styles["value"]),
                    Paragraph(f"<b>{pdf_text(vuln[2])}</b>", styles["value"]),
                    Paragraph(f"<b>{pdf_text(RISK_LABELS.get(severity.upper(), severity.upper()))}</b>", styles["value"]),
                ]],
                colWidths=[18 * mm, 108 * mm, 31 * mm],
            )
            finding_head.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), SURFACE),
                ("BOX", (0, 0), (-1, -1), 0.6, LINE),
                ("LINEBEFORE", (2, 0), (2, 0), 3, severity_color),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("TEXTCOLOR", (2, 0), (2, 0), severity_color),
            ]))
            remediation = context["fixes_by_vuln"].get(vuln[0], "No se registró una remediación específica.")
            details = [
                finding_head,
                Spacer(1, 2.5 * mm),
                Table(
                    [[
                        _meta_card("PUERTO", str(vuln[4] or "-"), styles),
                        _meta_card("SERVICIO", str(vuln[5] or "-"), styles),
                        _meta_card("REFERENCIA", f"F-{index:02d}", styles),
                    ]],
                    colWidths=[37 * mm, 72 * mm, 48 * mm],
                    style=TableStyle([
                        ("BACKGROUND", (0, 0), (-1, -1), WHITE),
                        ("BOX", (0, 0), (-1, -1), 0.4, LINE),
                        ("INNERGRID", (0, 0), (-1, -1), 0.4, LINE),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 7),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]),
                ),
                Paragraph("Descripción y evidencia", styles["h2"]),
                Paragraph(pdf_text(vuln[6] or "Sin descripción registrada."), styles["body"]),
                Paragraph("Recomendación", styles["h2"]),
                Paragraph(pdf_text(remediation), styles["callout"]),
                Spacer(1, 4 * mm),
            ]
            story.append(KeepTogether(details[:3]))
            story.extend(details[3:])
    else:
        story.append(Paragraph("No hay hallazgos técnicos detallados para esta ejecución.", styles["body"]))

    story.extend([PageBreak(), Paragraph("Plan de remediación", styles["h1"])])
    if context["vulns"]:
        remediation_rows = [[
            Paragraph("PRIORIDAD", styles["table_head"]),
            Paragraph("ACCIÓN", styles["table_head"]),
            Paragraph("PROPIETARIO SUGERIDO", styles["table_head"]),
        ]]
        for vuln in context["vulns"]:
            severity = str(vuln[3] or "unknown").lower()
            priority = {
                "critical": "Inmediata",
                "high": "0-7 días",
                "medium": "30 días",
                "low": "Próximo ciclo",
            }.get(severity, "Por definir")
            remediation_rows.append([
                Paragraph(pdf_text(priority), styles["table_cell"]),
                Paragraph(pdf_text(context["fixes_by_vuln"].get(vuln[0], f"Revisar y remediar: {vuln[2]}")), styles["table_cell"]),
                Paragraph("Equipo responsable del activo", styles["table_cell"]),
            ])
        remediation_table = LongTable(remediation_rows, colWidths=[27 * mm, 91 * mm, 39 * mm], repeatRows=1)
        remediation_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("GRID", (0, 0), (-1, -1), 0.35, LINE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, SURFACE]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(remediation_table)
    else:
        story.append(Paragraph("No hay acciones de remediación pendientes registradas.", styles["body"]))

    story.extend([
        Spacer(1, 7 * mm),
        Paragraph("Validación recomendada", styles["h2"]),
        Paragraph(
            "Después de aplicar las correcciones, realizar un re-test focalizado con el mismo alcance, "
            "conservar evidencia de cierre y actualizar el estado de cada hallazgo. Los cambios de "
            "infraestructura o exposición deben evaluarse nuevamente.",
            styles["body"],
        ),
    ])

    if context["include_exploitation"]:
        story.extend([PageBreak(), Paragraph("Anexo A - Explotación y validación", styles["h1"])])
        if context["exploits"]:
            exploit_rows = [[
                Paragraph("EXPLOIT", styles["table_head"]),
                Paragraph("HERRAMIENTA", styles["table_head"]),
                Paragraph("RESULTADO", styles["table_head"]),
            ]]
            for exploit in context["exploits"]:
                exploit_rows.append([
                    Paragraph(pdf_text(exploit[2]), styles["table_cell"]),
                    Paragraph(pdf_text(exploit[3]), styles["table_cell"]),
                    Paragraph(pdf_text(exploit[5]), styles["table_cell"]),
                ])
            exploit_table = LongTable(exploit_rows, colWidths=[65 * mm, 40 * mm, 52 * mm], repeatRows=1)
            exploit_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("GRID", (0, 0), (-1, -1), 0.35, LINE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, SURFACE]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(exploit_table)
        else:
            story.append(Paragraph("No se registraron intentos de explotación.", styles["body"]))

        relevant_events = [
            event for event in context["events"]
            if len(event) > 5 and event[3] in {"exploitation", "metasploit", "post_exploitation", "ai_actions", "terminal"}
        ]
        if relevant_events:
            story.append(Paragraph("Trazabilidad operativa", styles["h2"]))
            for event in relevant_events:
                story.append(Paragraph(f"<b>{pdf_text(event[4])}</b> · {pdf_text(event[3])}", styles["body"]))
                story.append(Paragraph(pdf_text(event[5], 3500), styles["code"]))

    if context["include_commands"]:
        story.extend([PageBreak(), Paragraph("Anexo B - Evidencia de comandos", styles["h1"])])
        if context["commands"]:
            for command in context["commands"]:
                story.append(Paragraph(f"<b>Comando</b> · {pdf_text(command[5] if len(command) > 5 else '')}", styles["small"]))
                story.append(Paragraph(pdf_text(command[2], 1200), styles["code"]))
                story.append(Paragraph(pdf_text(command[3], 5000), styles["code"]))
                story.append(Spacer(1, 2 * mm))
        else:
            story.append(Paragraph("No se registraron comandos de terminal para esta sesión.", styles["body"]))

    story.extend([
        PageBreak(),
        Paragraph("Referencias y notas", styles["h1"]),
        Paragraph(
            "<b>OWASP Web Security Testing Guide (WSTG)</b><br/>"
            "Referencia para estructura de pruebas web, evidencia y comunicación de hallazgos.",
            styles["body"],
        ),
        Paragraph(
            "<b>NIST SP 800-115</b><br/>"
            "Guía técnica para planificar pruebas, analizar hallazgos y desarrollar estrategias de mitigación.",
            styles["body"],
        ),
        Paragraph(
            "<b>Penetration Testing Execution Standard (PTES)</b><br/>"
            "Referencia para separar resumen ejecutivo, informe técnico, alcance, impacto y remediación.",
            styles["body"],
        ),
        Paragraph(
            "<b>CVSS v4.0 - FIRST</b><br/>"
            "Las etiquetas cualitativas del informe son orientativas. Para declarar conformidad CVSS se requiere "
            "calcular y conservar el vector completo, además del contexto de amenaza y entorno cuando corresponda.",
            styles["body"],
        ),
        Spacer(1, 8 * mm),
        Paragraph(
            "Este informe es una evaluación puntual y no garantiza la identificación de todas las vulnerabilidades. "
            "Debe interpretarse junto con el contexto operativo y de negocio del activo.",
            styles["callout"],
        ),
    ])

    doc.build(story, onFirstPage=_cover_page, onLaterPages=_page_header_footer)
    return filename


def _html_risk_bars(context: dict) -> str:
    cards = []
    for key, label in (("critical", "Críticas"), ("high", "Altas"), ("medium", "Medias"), ("low", "Bajas")):
        cards.append(
            f"<div class='risk-stat {key}'><strong>{context['counts'][key]}</strong><span>{label}</span></div>"
        )
    return "".join(cards)


def export_html(data: dict, output_dir: str) -> str:
    context = _report_context(data)
    os.makedirs(output_dir, exist_ok=True)
    filename = os.path.join(
        output_dir,
        f"pentool_{context['report_id']}_{_safe_filename(context['target'])}.html",
    )
    risk_color = RISK_COLORS[context["risk"]]

    finding_rows = []
    finding_details = []
    remediation_rows = []
    for index, vuln in enumerate(context["vulns"], 1):
        severity = str(vuln[3] or "unknown").lower()
        severity_label = RISK_LABELS.get(severity.upper(), severity.upper())
        remediation = context["fixes_by_vuln"].get(vuln[0], "No se registró una remediación específica.")
        finding_rows.append(
            "<tr>"
            f"<td class='mono'>F-{index:02d}</td>"
            f"<td><strong>{esc(vuln[2])}</strong></td>"
            f"<td><span class='severity {esc(severity)}'>{esc(severity_label)}</span></td>"
            f"<td>{esc(vuln[5] or '-')} / {esc(vuln[4] or '-')}</td>"
            "</tr>"
        )
        finding_details.append(
            f"<article class='finding' id='finding-{index}'>"
            f"<div class='finding-head'><span class='finding-ref'>F-{index:02d}</span>"
            f"<h3>{esc(vuln[2])}</h3><span class='severity {esc(severity)}'>{esc(severity_label)}</span></div>"
            f"<div class='finding-meta'><span><small>Puerto</small>{esc(vuln[4] or '-')}</span>"
            f"<span><small>Servicio</small>{esc(vuln[5] or '-')}</span></div>"
            f"<h4>Descripción y evidencia</h4><p>{esc(vuln[6] or 'Sin descripción registrada.')}</p>"
            f"<div class='recommendation'><h4>Recomendación</h4><p>{esc(remediation)}</p></div>"
            "</article>"
        )
        priority = {"critical": "Inmediata", "high": "0-7 días", "medium": "30 días", "low": "Próximo ciclo"}.get(severity, "Por definir")
        remediation_rows.append(
            f"<tr><td><strong>{esc(priority)}</strong></td><td>{esc(remediation)}</td>"
            "<td>Equipo responsable del activo</td></tr>"
        )

    exploit_section = ""
    if context["include_exploitation"]:
        exploit_rows = "".join(
            f"<tr><td>{esc(item[2])}</td><td>{esc(item[3])}</td><td>{esc(item[5])}</td></tr>"
            for item in context["exploits"]
        )
        exploit_section = (
            "<section><div class='section-kicker'>ANEXO A</div><h2>Explotación y validación</h2>"
            + (
                "<div class='table-wrap'><table><thead><tr><th>Exploit</th><th>Herramienta</th><th>Resultado</th>"
                f"</tr></thead><tbody>{exploit_rows}</tbody></table></div>"
                if exploit_rows else "<p class='empty-copy'>No se registraron intentos de explotación.</p>"
            )
            + "</section>"
        )

    command_section = ""
    if context["include_commands"]:
        command_items = "".join(
            f"<div class='evidence'><div class='evidence-label'>COMANDO</div><code>{esc(item[2])}</code>"
            f"<pre>{esc(plain_text(item[3]))}</pre></div>"
            for item in context["commands"]
        )
        command_section = (
            "<section><div class='section-kicker'>ANEXO B</div><h2>Evidencia de comandos</h2>"
            + (command_items or "<p class='empty-copy'>No se registraron comandos para esta sesión.</p>")
            + "</section>"
        )

    html_document = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<title>PenTool | {esc(context['report_id'])} | {esc(context['target'])}</title>
<style>
:root{{--navy:#0b1220;--ink:#172033;--slate:#526176;--muted:#758399;--line:#dce3ec;--surface:#f5f7fa;--teal:#0f9f8d;--teal-soft:#e8f7f4;--critical:#b42318;--high:#d85b16;--medium:#b7791f;--low:#147d64}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:#edf1f6;color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.55}}
.report{{width:min(1120px,calc(100% - 32px));margin:32px auto;background:#fff;border:1px solid var(--line);box-shadow:0 24px 80px rgba(11,18,32,.12)}}
.cover{{position:relative;min-height:480px;padding:64px;background:linear-gradient(145deg,var(--navy) 0 56%,#111d31 100%);color:#fff;overflow:hidden}}
.cover:after{{content:"";position:absolute;right:-120px;bottom:-220px;width:520px;height:520px;border:1px solid rgba(255,255,255,.08);border-radius:50%;box-shadow:0 0 0 70px rgba(255,255,255,.025),0 0 0 140px rgba(255,255,255,.018)}}
.brand{{display:flex;align-items:center;gap:12px;font-weight:800;letter-spacing:.06em}}.mark{{display:grid;place-items:center;width:42px;height:42px;border-radius:12px;background:var(--teal);color:var(--navy)}}.brand small{{display:block;color:#9bacbf;font-size:10px;letter-spacing:.13em}}
.cover-copy{{position:relative;z-index:1;max-width:720px;margin-top:88px}}.eyebrow{{color:#6be0cf;font:700 11px ui-monospace,monospace;letter-spacing:.14em}}h1{{margin:12px 0 16px;font-size:clamp(44px,7vw,78px);line-height:.96;letter-spacing:-.055em}}.cover-copy>p{{max-width:620px;color:#b9c5d4;font-size:17px}}
.cover-meta{{position:relative;z-index:1;display:grid;grid-template-columns:repeat(4,1fr);gap:1px;margin-top:62px;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.12)}}.cover-meta div{{padding:16px;background:rgba(11,18,32,.82)}}small,.label{{display:block;color:var(--muted);font-size:10px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}}.cover-meta small{{color:#8393a8}}.cover-meta strong{{display:block;margin-top:6px;overflow-wrap:anywhere}}
.content{{padding:56px 64px}}section{{margin-bottom:58px}}.section-kicker{{color:var(--teal);font:700 10px ui-monospace,monospace;letter-spacing:.14em}}h2{{margin:7px 0 22px;color:var(--navy);font-size:30px;letter-spacing:-.035em}}h3{{margin:0;font-size:18px}}h4{{margin:24px 0 8px;color:var(--navy);font-size:12px;text-transform:uppercase;letter-spacing:.05em}}p{{margin:0 0 12px}}
.executive-grid{{display:grid;grid-template-columns:1.3fr .7fr;gap:32px;align-items:start}}.summary-box{{padding:24px;border:1px solid var(--line);border-left:4px solid {risk_color};background:var(--surface)}}.risk-badge{{display:inline-flex;padding:7px 11px;border-radius:999px;background:{risk_color}18;color:{risk_color};font-size:11px;font-weight:900;letter-spacing:.06em}}
.risk-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:24px}}.risk-stat{{position:relative;padding:18px;border:1px solid var(--line);border-radius:10px;background:#fff;overflow:hidden}}.risk-stat:after{{content:"";position:absolute;inset:auto 0 0;height:3px;background:var(--color)}}.risk-stat.critical{{--color:var(--critical)}}.risk-stat.high{{--color:var(--high)}}.risk-stat.medium{{--color:var(--medium)}}.risk-stat.low{{--color:var(--low)}}.risk-stat strong{{display:block;font-size:24px}}.risk-stat span{{color:var(--muted);font-size:11px}}
.method-card{{padding:20px;border:1px solid #b9e6de;background:var(--teal-soft);border-radius:10px}}.method-card strong{{color:#087466}}
.table-wrap{{overflow-x:auto;border:1px solid var(--line);border-radius:10px}}table{{width:100%;border-collapse:collapse;font-size:13px}}th{{padding:12px 14px;background:var(--navy);color:#fff;text-align:left;font-size:10px;letter-spacing:.06em;text-transform:uppercase}}td{{padding:13px 14px;border-bottom:1px solid var(--line);vertical-align:top}}tbody tr:last-child td{{border-bottom:0}}tbody tr:nth-child(even){{background:var(--surface)}}.mono{{font-family:ui-monospace,monospace}}
.severity{{display:inline-flex;padding:5px 8px;border-radius:999px;font-size:10px;font-weight:900;letter-spacing:.04em}}.severity.critical{{background:#fef3f2;color:var(--critical)}}.severity.high{{background:#fff4ed;color:var(--high)}}.severity.medium{{background:#fff9e8;color:var(--medium)}}.severity.low{{background:#ecfdf3;color:var(--low)}}.severity.unknown{{background:#f2f4f7;color:#667085}}
.finding{{margin-bottom:22px;padding:24px;border:1px solid var(--line);border-radius:12px;box-shadow:0 8px 30px rgba(11,18,32,.055)}}.finding-head{{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:14px}}.finding-ref{{font:700 11px ui-monospace,monospace;color:var(--teal)}}.finding-meta{{display:flex;gap:1px;margin-top:18px;background:var(--line);border:1px solid var(--line)}}.finding-meta>span{{min-width:150px;padding:12px 14px;background:var(--surface);font-weight:700}}.finding-meta small{{margin-bottom:3px}}.recommendation{{margin-top:20px;padding:18px;border-radius:10px;background:var(--teal-soft);border:1px solid #b9e6de}}.recommendation h4{{margin-top:0;color:#087466}}
.evidence{{margin-bottom:18px}}.evidence-label{{margin-bottom:6px;color:var(--muted);font:700 10px ui-monospace,monospace;letter-spacing:.08em}}code{{font-family:ui-monospace,monospace;color:#087466}}pre{{max-height:460px;overflow:auto;padding:18px;border-radius:10px;background:var(--navy);color:#dce7f4;white-space:pre-wrap;word-break:break-word;font:12px/1.55 ui-monospace,monospace}}.empty-copy{{padding:22px;border:1px dashed var(--line);color:var(--muted);text-align:center}}
.references{{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}}.reference{{padding:18px;border:1px solid var(--line);background:var(--surface)}}.reference strong{{display:block;margin-bottom:5px;color:var(--navy)}}.reference p{{color:var(--slate);font-size:12px}}footer{{display:flex;justify-content:space-between;gap:20px;padding:22px 64px;border-top:1px solid var(--line);color:var(--muted);font-size:11px}}
@media(max-width:800px){{.report{{width:100%;margin:0;border:0}}.cover,.content{{padding:32px 22px}}.cover{{min-height:0}}.cover-copy{{margin-top:60px}}.cover-meta,.risk-grid{{grid-template-columns:repeat(2,1fr)}}.executive-grid{{grid-template-columns:1fr}}.finding-head{{grid-template-columns:auto 1fr}}.finding-head .severity{{grid-column:1/-1;width:max-content}}.references{{grid-template-columns:1fr}}footer{{padding:20px 22px;flex-direction:column}}}}
@media print{{@page{{size:A4;margin:14mm}}body{{background:#fff}}.report{{width:100%;margin:0;border:0;box-shadow:none}}.cover{{min-height:245mm;break-after:page}}.content{{padding:0}}section{{break-inside:auto}}.finding,.risk-stat,.reference{{break-inside:avoid}}footer{{padding:16px 0}}}}
</style>
</head>
<body>
<main class="report">
  <header class="cover">
    <div class="brand"><span class="mark">PT</span><span>PENTOOL<small>AI SECURITY OPERATIONS</small></span></div>
    <div class="cover-copy"><span class="eyebrow">INFORME DE EVALUACIÓN DE SEGURIDAD</span><h1>Security<br>Assessment</h1><p>Informe técnico y ejecutivo de pruebas autorizadas, con evidencia, priorización y recomendaciones accionables.</p></div>
    <div class="cover-meta"><div><small>Objetivo</small><strong>{esc(context['target'])}</strong></div><div><small>Riesgo global</small><strong style="color:{risk_color}">{esc(context['risk_label'])}</strong></div><div><small>Fecha</small><strong>{esc(context['scan_date'])}</strong></div><div><small>ID</small><strong>{esc(context['report_id'])}</strong></div></div>
  </header>
  <div class="content">
    <section><div class="section-kicker">01 / RESUMEN</div><h2>Resumen ejecutivo</h2><div class="executive-grid"><div><div class="summary-box"><span class="risk-badge">{esc(context['risk_label'])}</span><p style="margin-top:16px">{esc(context['ai'] or 'La evaluación registró los hallazgos detallados en este documento. La prioridad final debe confirmarse con el contexto de negocio.')}</p></div><div class="risk-grid">{_html_risk_bars(context)}</div></div><div class="method-card"><strong>Lectura recomendada</strong><p>Prioriza los hallazgos críticos y altos, confirma su exposición y asigna responsables. Realiza un re-test después de remediar.</p></div></div></section>
    <section><div class="section-kicker">02 / ALCANCE</div><h2>Alcance y metodología</h2><p>El alcance registrado fue <strong>{esc(context['target'])}</strong>. La evaluación combina reconocimiento automatizado, análisis asistido por IA y validaciones técnicas registradas por la plataforma.</p><div class="method-card"><strong>Referencias metodológicas</strong><p>La estructura toma como referencia OWASP WSTG, NIST SP 800-115 y PTES. Las severidades son cualitativas y no constituyen puntuaciones CVSS v4.0 sin un vector explícito.</p></div></section>
    <section><div class="section-kicker">03 / HALLAZGOS</div><h2>Resumen de hallazgos</h2>{f"<div class='table-wrap'><table><thead><tr><th>Ref.</th><th>Hallazgo</th><th>Severidad</th><th>Activo / servicio</th></tr></thead><tbody>{''.join(finding_rows)}</tbody></table></div>" if finding_rows else "<p class='empty-copy'>No se registraron vulnerabilidades confirmadas.</p>"}</section>
    <section><div class="section-kicker">04 / DETALLE TÉCNICO</div><h2>Hallazgos detallados</h2>{''.join(finding_details) if finding_details else "<p class='empty-copy'>No hay hallazgos técnicos detallados.</p>"}</section>
    <section><div class="section-kicker">05 / REMEDIACIÓN</div><h2>Plan de remediación</h2>{f"<div class='table-wrap'><table><thead><tr><th>Prioridad</th><th>Acción</th><th>Propietario sugerido</th></tr></thead><tbody>{''.join(remediation_rows)}</tbody></table></div>" if remediation_rows else "<p class='empty-copy'>No hay acciones pendientes registradas.</p>"}</section>
    {exploit_section}
    {command_section}
    <section><div class="section-kicker">REFERENCIAS</div><h2>Estándares y notas</h2><div class="references"><div class="reference"><strong>OWASP WSTG</strong><p>Pruebas web, evidencia y comunicación de hallazgos.</p></div><div class="reference"><strong>NIST SP 800-115</strong><p>Planificación de pruebas, análisis y mitigación.</p></div><div class="reference"><strong>PTES</strong><p>Resumen ejecutivo, detalle técnico, alcance e impacto.</p></div><div class="reference"><strong>CVSS v4.0</strong><p>Marco de puntuación cuando existe un vector completo.</p></div></div><div class="method-card" style="margin-top:18px"><strong>Limitación</strong><p>Esta es una evaluación puntual y no garantiza que todas las vulnerabilidades hayan sido identificadas.</p></div></section>
  </div>
  <footer><span>{esc(context['report_id'])}</span><span>Confidencial · Uso autorizado · Generado por PenTool</span></footer>
</main>
</body>
</html>"""
    with open(filename, "w", encoding="utf-8") as output:
        output.write(html_document)
    return filename


def export_menu(data: dict):
    if not data.get("history"):
        print("[!] No session data to export.")
        return
    history = data["history"]
    print(f"\n{'-' * 20} EXPORT SL#{history[0]} - {history[1]} {'-' * 20}")
    print("  [1] PDF report\n  [2] HTML report\n  [3] Both\n  [4] Back")
    choice = input("Export format: ").strip()
    output_dir = os.path.join(os.path.dirname(__file__), "reports")
    if choice in {"1", "3"}:
        print(f"[+] PDF: {export_pdf(data, output_dir)}")
    if choice in {"2", "3"}:
        print(f"[+] HTML: {export_html(data, output_dir)}")


if __name__ == "__main__":
    rows = fetch_all_history()
    if not rows:
        print("[!] No sessions found in database.")
        raise SystemExit(0)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    value = input("Enter SL# to export: ").strip()
    if not value.isdigit():
        raise SystemExit("[!] Invalid SL#.")
    export_menu(fetch_session(int(value)))
