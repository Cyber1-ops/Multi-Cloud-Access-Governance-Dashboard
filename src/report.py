"""
Findings export (CSV + PDF)
===========================

Turns analysis results into an auditor-friendly findings report. CSV is the
machine-readable evidence trail; the PDF is the executive summary a GRC lead
would take into an access-review meeting.
"""

from __future__ import annotations

import csv
import io
from datetime import date


def findings_to_csv(results: list[dict]) -> str:
    """Flatten to one row per (identity, finding); return CSV text."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "risk_score", "severity", "identity_id", "name", "email", "department",
        "status", "is_service_account", "providers", "rule_id", "finding",
        "finding_severity", "evidence", "remediation",
    ])
    for r in results:
        if not r["findings"]:
            continue
        for f in r["findings"]:
            w.writerow([
                r["risk_score"], r["severity"], r["identity_id"], r["name"],
                r["email"], r["department"], r["status"], r["is_service_account"],
                "|".join(r["providers"]), f.rule_id, f.title, f.severity,
                f.evidence, f.remediation,
            ])
    return buf.getvalue()


def summary_csv(results: list[dict]) -> str:
    """One row per identity with its aggregate risk (no finding breakdown)."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "risk_score", "severity", "name", "email", "department", "status",
        "providers", "cloud_count", "finding_count", "rules_triggered",
    ])
    for r in results:
        w.writerow([
            r["risk_score"], r["severity"], r["name"], r["email"],
            r["department"], r["status"], "|".join(r["providers"]),
            r["clouds"], r["finding_count"],
            "|".join(f.rule_id for f in r["findings"]),
        ])
    return buf.getvalue()


def findings_to_pdf(results: list[dict], ref: date, top_n: int = 25) -> bytes:
    """Executive PDF: KPIs + the top-N riskiest identities with evidence."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="Access Governance Findings",
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm)
    styles = getSampleStyleSheet()
    small = ParagraphStyle("small", parent=styles["Normal"], fontSize=8, leading=10)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], spaceBefore=8)
    flow = []

    flagged = [r for r in results if r["risk_score"] > 0]
    sev = {s: sum(1 for r in results if r["severity"] == s)
           for s in ("Critical", "High", "Medium", "Low")}

    flow.append(Paragraph("Multi-Cloud Access Governance - Findings Report", styles["Title"]))
    flow.append(Paragraph(f"Estate snapshot as of {ref.isoformat()} &bull; "
                          f"{len(results)} identities analysed &bull; "
                          f"{len(flagged)} flagged", styles["Normal"]))
    flow.append(Spacer(1, 6 * mm))

    kpi = Table([
        ["Critical", "High", "Medium", "Low"],
        [sev["Critical"], sev["High"], sev["Medium"], sev["Low"]],
    ], colWidths=[40 * mm] * 4)
    kpi.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("TEXTCOLOR", (0, 1), (0, 1), colors.HexColor("#b91c1c")),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("TOPPADDING", (0, 1), (-1, 1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
    ]))
    flow.append(kpi)
    flow.append(Spacer(1, 6 * mm))

    flow.append(Paragraph(f"Top {top_n} identities by risk", h2))
    data = [["Risk", "Severity", "Identity", "Dept", "Clouds", "Findings"]]
    for r in flagged[:top_n]:
        data.append([
            str(r["risk_score"]), r["severity"],
            Paragraph(f"{r['name']}<br/><font size=6>{r['email']}</font>", small),
            Paragraph(r["department"], small),
            ",".join(p.upper() for p in r["providers"]),
            Paragraph(", ".join(f.title for f in r["findings"]), small),
        ])
    t = Table(data, colWidths=[12 * mm, 18 * mm, 42 * mm, 24 * mm, 20 * mm, 58 * mm],
              repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
    ]))
    flow.append(t)
    flow.append(Spacer(1, 5 * mm))
    flow.append(Paragraph(
        "Generated by the Multi-Cloud Access Governance Dashboard (OPSEC). "
        "Full machine-readable evidence available via CSV export.", small))

    doc.build(flow)
    return buf.getvalue()
