from io import BytesIO
from typing import Any
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def build_scan_pdf(scan: dict[str, Any]) -> bytes:
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=letter,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        title=f"ARGUS security scan {scan['scan_id']}",
        author="ARGUS",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17324d"),
    )
    body_style = styles["BodyText"]
    small_style = ParagraphStyle("Small", parent=body_style, fontSize=8, leading=10)
    story = [
        Paragraph("ARGUS Security Scan Report", title_style),
        Spacer(1, 12),
        Paragraph(f"<b>Project:</b> {escape(str(scan.get('project_name', 'Unknown')))}", body_style),
        Paragraph(f"<b>Scan ID:</b> {escape(str(scan.get('scan_id', '')))}", body_style),
        Paragraph(f"<b>Status:</b> {escape(str(scan.get('status', 'unknown')))}", body_style),
        Paragraph(f"<b>Scanners:</b> {escape(str(scan.get('scanner', 'None')))}", body_style),
        Paragraph(f"<b>Findings:</b> {int(scan.get('total_findings', 0))}", body_style),
        Spacer(1, 14),
    ]

    coverage = scan.get("scanner_results") or {}
    if coverage:
        rows = [["Scanner", "Status", "Findings"]]
        for name, result in sorted(coverage.items()):
            rows.append([name, result.get("status", "unknown"), str(result.get("findings", 0))])
        table = Table(rows, colWidths=[2.5 * inch, 1.5 * inch, 1.0 * inch], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbe8ef")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#17324d")),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#aab8c2")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.extend([Paragraph("Scanner coverage", styles["Heading2"]), table, Spacer(1, 14)])

    story.append(Paragraph("Findings", styles["Heading2"]))
    for index, finding in enumerate(scan.get("findings", []), start=1):
        title = escape(str(finding.get("title") or "Untitled finding"))
        file_name = escape(str(finding.get("file") or "unknown"))
        scanner = escape(str(finding.get("scanner") or "unknown"))
        severity = escape(str(finding.get("severity") or "unknown"))
        explanation = escape(str(finding.get("explanation") or "No explanation generated."))
        story.extend(
            [
                Paragraph(f"{index}. {title}", styles["Heading3"]),
                Paragraph(
                    f"<b>Severity:</b> {severity} &nbsp; <b>Scanner:</b> {scanner} &nbsp; "
                    f"<b>Location:</b> {file_name}:{int(finding.get('line') or 1)}",
                    small_style,
                ),
                Paragraph(explanation, body_style),
                Spacer(1, 8),
            ]
        )
    if not scan.get("findings"):
        story.append(Paragraph("No findings were recorded for this scan.", body_style))

    document.build(story)
    return output.getvalue()