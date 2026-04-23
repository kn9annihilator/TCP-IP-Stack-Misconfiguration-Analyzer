# reporter/pdf_report.py

import os
import platform
import socket
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


# ---------------------------------------------------------------------------
# Safe Helpers
# ---------------------------------------------------------------------------
def _safe(value, default="N/A"):
    if value is None or value == "":
        return default
    return str(value)


def _safe_dict(value):
    return value if isinstance(value, dict) else {}


def _safe_list(value):
    return value if isinstance(value, list) else []


def _dict_to_table_rows(data):
    rows = [["Field", "Value"]]
    if not isinstance(data, dict):
        rows.append(["Data", _safe(data)])
        return rows

    for k, v in data.items():
        rows.append([str(k), _safe(v)])
    return rows


def _make_table(data, col_widths=None):
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E78")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.75, colors.black),
            ("BOX", (0, 0), (-1, -1), 1.0, colors.black),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    return table


def _draw_page_border(canvas, doc):
    canvas.saveState()
    width, height = A4

    # Header
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(30, height - 15, "Security Assessment Report")
    canvas.drawRightString(width - 30, height - 15, datetime.now().strftime("%Y-%m-%d"))

    # Page border
    canvas.setStrokeColor(colors.black)
    canvas.setLineWidth(1)
    canvas.rect(20, 20, width - 40, height - 40)

    # Footer
    canvas.setFont("Helvetica", 8)
    canvas.drawString(20, 15, "TCP/IP Stack Misconfiguration Analyzer Report")
    canvas.drawRightString(width - 30, 15, f"Page {canvas.getPageNumber()}")

    canvas.restoreState()


# ---------------------------------------------------------------------------
# Main PDF Generator
# ---------------------------------------------------------------------------
def generate_pdf_report(
    target,
    tcp_results=None,
    icmp_results=None,
    fingerprint_results=None,
    analysis=None,
    score_data=None,
    investigator="",
    output_path=None,
):
    tcp_results = _safe_dict(tcp_results)
    icmp_results = _safe_dict(icmp_results)
    fingerprint_results = _safe_dict(fingerprint_results)
    analysis = _safe_dict(analysis)
    score_data = _safe_dict(score_data)

    # Safe output path
    if not output_path:
        os.makedirs("reports", exist_ok=True)
        safe_target = str(target).replace(":", "_").replace("/", "_").replace("\\", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join("reports", f"{safe_target}_assessment_{timestamp}.pdf")
    else:
        out_dir = os.path.dirname(output_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=35,
        leftMargin=35,
        topMargin=35,
        bottomMargin=35,
    )

    styles = getSampleStyleSheet()

    # Use unique style names so ReportLab doesn't cry about duplicates
    if "CustomTitleCenter" not in styles:
        styles.add(ParagraphStyle(
            name="CustomTitleCenter",
            parent=styles["Title"],
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            spaceAfter=12,
        ))

    if "CustomSectionHeader" not in styles:
        styles.add(ParagraphStyle(
            name="CustomSectionHeader",
            parent=styles["Heading2"],
            alignment=TA_LEFT,
            fontName="Helvetica-Bold",
            fontSize=13,
            textColor=colors.HexColor("#1F1F1F"),
            spaceBefore=8,
            spaceAfter=6,
        ))

    if "CustomBodySmall" not in styles:
        styles.add(ParagraphStyle(
            name="CustomBodySmall",
            parent=styles["BodyText"],
            fontSize=9,
            leading=12,
            spaceAfter=6,
        ))

    if "CoverTitle" not in styles:
        styles.add(ParagraphStyle(
            name="CoverTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=28,
            spaceAfter=6,
            textColor=colors.HexColor("#1F4E78"),
        ))

    if "CoverSubtitle" not in styles:
        styles.add(ParagraphStyle(
            name="CoverSubtitle",
            alignment=TA_CENTER,
            fontName="Helvetica",
            fontSize=12,
            leading=16,
            spaceAfter=4,
            textColor=colors.HexColor("#444444"),
        ))

    if "CoverLabel" not in styles:
        styles.add(ParagraphStyle(
            name="CoverLabel",
            alignment=TA_CENTER,
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#888888"),
        ))

    # -----------------------------------------------------------------------
    # Collect system environment details for the cover page
    # -----------------------------------------------------------------------
    now = datetime.now()
    generated_at   = now.strftime("%Y-%m-%d  %H:%M:%S")
    analyst_name   = investigator.strip() if investigator and investigator.strip() else "Automated Analyzer"
    risk_level     = _safe(score_data.get("risk_level",       score_data.get("severity", "N/A")))
    risk_score     = _safe(score_data.get("normalized_score", score_data.get("overall_score", "N/A")))

    try:
        analyst_host = socket.gethostname()
    except Exception:
        analyst_host = "Unknown Host"

    try:
        analyst_ip = socket.gethostbyname(analyst_host)
    except Exception:
        analyst_ip = "Unknown"

    sys_os      = f"{platform.system()} {platform.release()} ({platform.machine()})"
    sys_python  = platform.python_version()

    story = []

    # -----------------------------------------------------------------------
    # Cover Page
    # -----------------------------------------------------------------------
    story.append(Spacer(1, 1.2 * inch))

    story.append(Paragraph("TCP/IP Stack Misconfiguration Analyzer", styles["CoverTitle"]))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("Structured Security Assessment Report", styles["CoverSubtitle"]))
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph("For authorized use only", styles["CoverLabel"]))
    story.append(Spacer(1, 0.5 * inch))

    # Horizontal rule
    rule_table = Table([[""]], colWidths=[6.5 * inch], rowHeights=[2])
    rule_table.setStyle(TableStyle([
        ("LINEABOVE",  (0, 0), (-1, 0), 1.5, colors.HexColor("#1F4E78")),
        ("LINEBELOW",  (0, 0), (-1, 0), 0.5, colors.HexColor("#AAAAAA")),
    ]))
    story.append(rule_table)
    story.append(Spacer(1, 0.35 * inch))

    cover_rows = [
        ["Field",                  "Details"],
        ["Target IP / Host",       _safe(target)],
        ["Risk Level",             f"{risk_level}  (Score: {risk_score} / 10)"],
        ["Report Generated On",    generated_at],
        ["Investigator / Analyst", analyst_name],
        ["Analyst Workstation",    analyst_host],
        ["Analyst IP",             analyst_ip],
        ["Operating System",       sys_os],
        ["Python Version",         sys_python],
        ["Report Classification",  "Confidential — Authorized Testing Only"],
    ]
    story.append(_make_table(cover_rows, col_widths=[2.3 * inch, 4.2 * inch]))
    story.append(Spacer(1, 0.5 * inch))

    story.append(rule_table)
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        "This document is generated automatically by the TCP/IP Stack Misconfiguration Analyzer. "
        "All findings are based on live network probe responses. "
        "Distribution of this report outside authorized personnel is prohibited.",
        styles["CoverLabel"],
    ))

    story.append(PageBreak())

    # -----------------------------------------------------------------------
    # Executive Summary
    # -----------------------------------------------------------------------
    story.append(Paragraph("1. Executive Summary", styles["CustomSectionHeader"]))

    severity = _safe(score_data.get("severity", "Unknown"))
    overall_score = _safe(score_data.get("overall_score", "N/A"))

    executive_summary = (
        f"This report summarizes observed TCP/IP stack behavior for target "
        f"<b>{_safe(target)}</b>. The assessment evaluates TCP probe responses, "
        f"ICMP behavior, fingerprint leakage, malformed packet handling, and "
        f"potential attack-enabling misconfigurations. "
        f"The current overall risk posture is assessed as "
        f"<b>{severity}</b> with a score of <b>{overall_score}</b>."
    )
    story.append(Paragraph(executive_summary, styles["BodyText"]))
    story.append(Spacer(1, 0.15 * inch))

    # Plain Text Explanation (Risk Narrative)
    risk_narrative = analysis.get("risk_narrative")
    if risk_narrative:
        story.append(Paragraph("<b>Analysis & Risk Narrative:</b>", styles["CustomBodySmall"]))
        story.append(Paragraph(_safe(risk_narrative), styles["CustomBodySmall"]))
    story.append(Spacer(1, 0.15 * inch))

    # -----------------------------------------------------------------------
    # Score Summary
    # -----------------------------------------------------------------------
    story.append(Paragraph("2. Risk Score Summary", styles["CustomSectionHeader"]))

    score_rows = [
        ["Metric", "Value"],
        ["Overall Score", _safe(score_data.get("overall_score"))],
        ["Severity", _safe(score_data.get("severity"))],
        ["Exposure Rating", _safe(score_data.get("exposure_rating"))],
        ["Confidence", _safe(score_data.get("confidence"))],
    ]
    story.append(_make_table(score_rows, col_widths=[2.5 * inch, 4.0 * inch]))
    story.append(Spacer(1, 0.2 * inch))

    # -----------------------------------------------------------------------
    # TCP Results
    # -----------------------------------------------------------------------
    story.append(Paragraph("3. TCP Probe Results", styles["CustomSectionHeader"]))

    tcp_table = [["Probe", "Port", "Status", "Flags", "TTL", "Window", "Summary"]]

    if tcp_results:
        for probe_name, results_item in tcp_results.items():
            if isinstance(results_item, dict):
                items = [results_item]
            elif isinstance(results_item, list):
                items = results_item
            else:
                items = []

            for result in items:
                result = _safe_dict(result)
                tcp_table.append([
                    _safe(probe_name),
                    _safe(result.get("port")),
                    _safe(result.get("status")),
                    _safe(result.get("flags")),
                    _safe(result.get("ttl")),
                    _safe(result.get("window_size")),
                    _safe(result.get("response_summary")),
                ])
    else:
        tcp_table.append(["No TCP probe data available", "-", "-", "-", "-", "-", "-"])

    story.append(_make_table(
        tcp_table,
        col_widths=[1.0 * inch, 0.6 * inch, 1.0 * inch, 0.8 * inch, 0.5 * inch, 0.8 * inch, 2.5 * inch]
    ))
    story.append(Spacer(1, 0.2 * inch))

    # -----------------------------------------------------------------------
    # ICMP Results
    # -----------------------------------------------------------------------
    story.append(Paragraph("4. ICMP Analysis", styles["CustomSectionHeader"]))

    icmp_table = [["Probe", "Status / Verdict", "TTL", "RTT (ms)", "Summary"]]

    if icmp_results:
        for probe_name, results_item in icmp_results.items():
            if isinstance(results_item, dict):
                items = [results_item]
            elif isinstance(results_item, list):
                items = results_item
            else:
                items = []

            for result in items:
                result = _safe_dict(result)
                icmp_table.append([
                    _safe(probe_name),
                    _safe(result.get("status") or result.get("verdict")),
                    _safe(result.get("ttl")),
                    _safe(result.get("response_time_ms") or result.get("avg_rtt_ms")),
                    _safe(result.get("response_summary")),
                ])
    else:
        icmp_table.append(["No ICMP probe data available", "-", "-", "-", "-"])

    story.append(_make_table(
        icmp_table,
        col_widths=[1.2 * inch, 1.4 * inch, 0.6 * inch, 0.8 * inch, 2.8 * inch]
    ))
    story.append(Spacer(1, 0.2 * inch))

    # -----------------------------------------------------------------------
    # Fingerprinting
    # -----------------------------------------------------------------------
    story.append(Paragraph("5. Fingerprinting & Stack Behavior", styles["CustomSectionHeader"]))

    if fingerprint_results:
        fp_rows = _dict_to_table_rows(fingerprint_results)
        story.append(_make_table(fp_rows, col_widths=[2.2 * inch, 4.3 * inch]))
    else:
        story.append(Paragraph("No fingerprinting results available.", styles["BodyText"]))

    story.append(Spacer(1, 0.2 * inch))

    # -----------------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------------
    story.append(Paragraph("6. Key Findings", styles["CustomSectionHeader"]))

    findings = _safe_list(analysis.get("findings", []))
    if findings:
        findings_rows = [["Finding", "Severity", "Description"]]
        for finding in findings:
            finding = _safe_dict(finding)
            findings_rows.append([
                _safe(finding.get("title")),
                _safe(finding.get("severity")),
                _safe(finding.get("description")),
            ])
        story.append(_make_table(findings_rows, col_widths=[1.8 * inch, 0.9 * inch, 3.8 * inch]))
    else:
        story.append(Paragraph("No structured findings were provided.", styles["BodyText"]))

    story.append(Spacer(1, 0.2 * inch))

    # -----------------------------------------------------------------------
    # Attack Vector Mapping
    # -----------------------------------------------------------------------
    story.append(Paragraph("7. Attack Vector Mapping", styles["CustomSectionHeader"]))

    attack_vectors = _safe_list(analysis.get("attack_vectors", []))
    if attack_vectors:
        attack_rows = [["Finding", "Attack Relevance", "Impact"]]
        for item in attack_vectors:
            item = _safe_dict(item)
            attack_rows.append([
                _safe(item.get("finding")),
                _safe(item.get("attack_relevance")),
                _safe(item.get("impact")),
            ])
        story.append(_make_table(attack_rows, col_widths=[2.0 * inch, 2.2 * inch, 2.3 * inch]))
    else:
        story.append(Paragraph("No attack vector mapping data available.", styles["BodyText"]))

    story.append(Spacer(1, 0.2 * inch))

    # -----------------------------------------------------------------------
    # Recommendations
    # -----------------------------------------------------------------------
    story.append(Paragraph("8. Recommendations", styles["CustomSectionHeader"]))

    recommendations = _safe_list(analysis.get("recommendations", []))
    if recommendations:
        for i, rec in enumerate(recommendations, start=1):
            story.append(Paragraph(f"<b>{i}.</b> {_safe(rec)}", styles["BodyText"]))
    else:
        story.append(Paragraph("No recommendations available.", styles["BodyText"]))

    # -----------------------------------------------------------------------
    # Appendix
    # -----------------------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("Appendix A — Raw Structured Data", styles["CustomSectionHeader"]))

    story.append(Paragraph("TCP Raw Results", styles["Heading3"]))
    if tcp_results:
        for name, results_item in tcp_results.items():
            story.append(Paragraph(f"<b>{_safe(name)}</b>", styles["CustomBodySmall"]))
            if isinstance(results_item, list):
                for res in results_item:
                    story.append(_make_table(_dict_to_table_rows(_safe_dict(res)), col_widths=[2.2 * inch, 4.2 * inch]))
                    story.append(Spacer(1, 0.05 * inch))
            else:
                story.append(_make_table(_dict_to_table_rows(_safe_dict(results_item)), col_widths=[2.2 * inch, 4.2 * inch]))
            story.append(Spacer(1, 0.12 * inch))
    else:
        story.append(Paragraph("No TCP raw data available.", styles["CustomBodySmall"]))

    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("ICMP Raw Results", styles["Heading3"]))
    if icmp_results:
        for name, results_item in icmp_results.items():
            story.append(Paragraph(f"<b>{_safe(name)}</b>", styles["CustomBodySmall"]))
            if isinstance(results_item, list):
                for res in results_item:
                    story.append(_make_table(_dict_to_table_rows(_safe_dict(res)), col_widths=[2.2 * inch, 4.2 * inch]))
                    story.append(Spacer(1, 0.05 * inch))
            else:
                story.append(_make_table(_dict_to_table_rows(_safe_dict(results_item)), col_widths=[2.2 * inch, 4.2 * inch]))
            story.append(Spacer(1, 0.12 * inch))
    else:
        story.append(Paragraph("No ICMP raw data available.", styles["CustomBodySmall"]))

    doc.build(story, onFirstPage=_draw_page_border, onLaterPages=_draw_page_border)
    return output_path