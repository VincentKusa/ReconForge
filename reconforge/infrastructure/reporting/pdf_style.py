"""Shared ReportLab building blocks for ReconForge PDF reports.

Both the Discovery technical report and the Assessment final assessment report
previously duplicated the same palette, style definitions and table
styling; they now render through these helpers.
"""

from __future__ import annotations

from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import LongTable, Paragraph, TableStyle

PALETTE = {
    "navy": "#17365D",
    "blue": "#24527A",
    "grid": "#B7C9D6",
    "zebra": "#F2F6FA",
    "callout_bg": "#EEF4F8",
    "footer": "#536779",
    "alert": "#A33A3A",
    "alert_bg": "#FBEFEF",
    "alert_text": "#7A2020",
}


def color(name: str) -> colors.Color:
    """Return a palette color by key."""
    return colors.HexColor(PALETTE[name])


def build_styles(prefix: str, small_leading: float = 10.0) -> Any:
    """Register the ReconForge paragraph styles under a report prefix."""
    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name=f"{prefix}Title",
            parent=styles["Title"],
            fontSize=23,
            leading=28,
            textColor=color("navy"),
            alignment=1,  # TA_CENTER
            spaceAfter=12,
        )
    )
    styles.add(
        ParagraphStyle(
            name=f"{prefix}H1",
            parent=styles["Heading1"],
            fontSize=15,
            leading=19,
            textColor=color("navy"),
            spaceBefore=12,
            spaceAfter=7,
        )
    )
    styles.add(
        ParagraphStyle(
            name=f"{prefix}H2",
            parent=styles["Heading2"],
            fontSize=10,
            leading=13,
            textColor=color("blue"),
            spaceBefore=8,
            spaceAfter=4,
        )
    )
    styles.add(
        ParagraphStyle(
            name=f"{prefix}Small",
            parent=styles["BodyText"],
            fontSize=7.5,
            leading=small_leading,
        )
    )
    styles.add(
        ParagraphStyle(
            name=f"{prefix}Cell",
            parent=styles["BodyText"],
            fontSize=6.5,
            leading=8,
            wordWrap="CJK",
        )
    )
    styles.add(
        ParagraphStyle(
            name=f"{prefix}Callout",
            parent=styles["BodyText"],
            fontSize=9,
            leading=13,
            backColor=color("callout_bg"),
            borderPadding=7,
            spaceBefore=5,
            spaceAfter=8,
        )
    )

    return styles


def pdf_text(value: Any) -> str:
    """Escape a value for ReportLab paragraphs; None/empty becomes a dash."""
    if value is None or value == "":
        value = "-"
    return escape(str(value)).replace("\n", "<br/>")


def para(text: Any, styles: Any, style_name: str) -> Paragraph:
    """Build an escaped paragraph in one of the registered styles."""
    return Paragraph(pdf_text(text), styles[style_name])


def make_table(
    rows: list[list[Any]],
    widths: list[float],
    font: int = 7,
    repeat: int = 1,
) -> LongTable:
    """Build the shared header-styled, zebra-striped long table."""
    table = LongTable(
        rows,
        colWidths=widths,
        repeatRows=repeat,
        hAlign="LEFT",
        splitByRow=1,
        splitInRow=1,
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), color("navy")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), font),
                ("LEADING", (0, 0), (-1, -1), font + 2),
                ("GRID", (0, 0), (-1, -1), 0.35, color("grid")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, color("zebra")],
                ),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )

    return table


def footer_text(canvas: Any, document: Any, page_width: float, left: str) -> None:
    """Draw the standard confidential footer line."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(color("footer"))
    canvas.drawString(18 * mm, 10 * mm, left)
    canvas.drawRightString(page_width - 18 * mm, 10 * mm, f"Page {document.page}")
    canvas.restoreState()
