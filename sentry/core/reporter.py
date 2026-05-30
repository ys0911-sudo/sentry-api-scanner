"""
reporter.py

Handles all report saving for every scan mode. After each scan completes,
the reporter creates a timestamped subdirectory under ~/sentry-reports/ (or a
user-specified override path), writes a structured JSON report and a plain-text
mirror of the terminal output, then prints the absolute path to the console.

The save location follows this pattern:
    ~/sentry-reports/{YYYY-MM-DD}_{HH-MM-SS}_{target}/

Where 'target' is:
    - The sanitised domain name for single-URL scans (e.g. api.github.com)
    - batch_{n}urls for file-based batch scans (e.g. batch_15urls)
    - passive_session for passive capture sessions

Saving happens regardless of the --output flag. The --output flag controls
what is rendered to the terminal AND which extra file format is written:
    table / json  → report.json + report.txt only
    html          → report.json + report.txt + report.html
    pdf           → report.json + report.txt + report.pdf

The --save flag overrides the default ~/sentry-reports/ root only.

Classes:
    ReportWriter: Manages the lifecycle of a single scan's report directory.

Functions:
    build_report_dir: Compute and create the timestamped report directory path.
    sanitise_target: Convert a URL or description string into a safe directory name.
    save_report: Top-level convenience function called by each mode runner.
    render_html: Render scan results as a self-contained HTML string.
    save_html_report: Write report.html into the given report directory.
    save_pdf_report: Write report.pdf into the given report directory.
"""

from __future__ import annotations

import html as _html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


_DEFAULT_ROOT = Path.home() / "sentry-reports"


def sanitise_target(target: str) -> str:
    """
    Convert a URL or description string into a safe filesystem directory name.

    Extracts the hostname from a URL, or passes a pre-formatted string (such as
    'batch_15urls' or 'passive_session') through with unsafe characters removed.

    Args:
        target (str): A full URL, domain name, or descriptive label.

    Returns:
        str: A filename-safe string containing only alphanumerics, dots, and
             hyphens. Maximum 64 characters to stay within common filesystem limits.

    Example:
        sanitise_target("https://api.github.com/repos")  ->  "api.github.com"
        sanitise_target("batch_15urls")                  ->  "batch_15urls"
    """
    parsed = urlparse(target)
    # Use netloc when available (i.e. target is a full URL), otherwise use as-is
    name = parsed.netloc if parsed.netloc else target
    # Strip port number — irrelevant for directory naming
    name = name.split(":")[0]
    # Replace any character that is not alphanumeric, dot, or hyphen
    name = re.sub(r"[^a-zA-Z0-9.\-]", "_", name)
    return name[:64]


def build_report_dir(
    target: str,
    save_root: Optional[Path] = None,
) -> Path:
    """
    Compute, create, and return the timestamped directory for this scan's report.

    The directory name embeds the scan start time so that multiple scans of the
    same target produce distinct directories without overwriting previous results.

    Args:
        target (str): URL, batch label, or 'passive_session' describing the scan.
        save_root (Optional[Path]): Override the default ~/sentry-reports/ root.
                                    Created if it does not exist.

    Returns:
        Path: The absolute path to the newly created report directory.

    Raises:
        OSError: If the directory cannot be created due to permissions or disk space.

    Example:
        build_report_dir("https://api.example.com")
        # -> ~/sentry-reports/2026-05-29_14-30-00_api.example.com/
    """
    root = save_root or _DEFAULT_ROOT
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_target = sanitise_target(target)
    report_dir = root / f"{timestamp}_{safe_target}"
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


class ReportWriter:
    """
    Manages the creation and population of a single scan's report directory.

    Instantiated by each mode runner at scan start; .save() is called after
    the scan completes. Both report.json and report.txt are written atomically
    so a partial scan still produces valid (possibly incomplete) output files.

    Attributes:
        report_dir (Path): Absolute path to the timestamped report directory.
        target (str): The original target string used to name the directory.

    Example:
        writer = ReportWriter(target="https://api.example.com")
        writer.save(results=scan_results, text_output="...")
        # Prints: Report saved to: /home/user/sentry-reports/2026-05-29_...
    """

    def __init__(
        self,
        target: str,
        save_root: Optional[Path] = None,
    ) -> None:
        """
        Initialise the writer and create the report directory immediately.

        Creating the directory at init time (rather than at .save() time) means
        the directory exists for the entire scan duration, which allows future
        phases to stream intermediate results into it.

        Args:
            target (str): URL, batch label, or 'passive_session'.
            save_root (Optional[Path]): Override the default ~/sentry-reports/ root.
        """
        self.target = target
        self.report_dir: Path = build_report_dir(target, save_root)

    def save(self, results: dict, text_output: str) -> Path:
        """
        Write report.json and report.txt into the report directory, then print
        the save path to the terminal.

        Called by each mode runner after the scan finishes. The text_output
        argument should be the plain-text equivalent of whatever was rendered to
        the terminal (Rich markup stripped).

        Args:
            results (dict): Structured scan results to serialise as JSON.
            text_output (str): Plain-text mirror of terminal output (no markup).

        Returns:
            Path: The report directory path, so callers can reference it.

        Raises:
            OSError: If either report file cannot be written.
        """
        json_path = self.report_dir / "report.json"
        txt_path = self.report_dir / "report.txt"

        with open(json_path, "w") as fh:
            json.dump(results, fh, indent=2, default=str)

        with open(txt_path, "w") as fh:
            fh.write(text_output)

        # Always print the save location after terminal output
        print(f"\nReport saved to: {self.report_dir.resolve()}")
        return self.report_dir


def save_report(
    target: str,
    results: dict,
    text_output: str,
    save_root: Optional[Path] = None,
) -> Path:
    """
    Convenience wrapper that creates a ReportWriter and saves in one call.

    Intended for mode runners that do not need to hold a persistent writer
    reference during the scan (i.e. single-shot active and spider modes).

    Args:
        target (str): URL, batch label, or 'passive_session'.
        results (dict): Structured scan results.
        text_output (str): Plain-text mirror of terminal output.
        save_root (Optional[Path]): Override the default ~/sentry-reports/ root.

    Returns:
        Path: The report directory path.
    """
    writer = ReportWriter(target=target, save_root=save_root)
    return writer.save(results=results, text_output=text_output)


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

# Severity and status colour mappings used in the HTML report.
_HTML_STATUS_COLORS = {"PASS": "#2ecc71", "WARN": "#f39c12", "FAIL": "#e74c3c"}
_HTML_SEVERITY_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH": "#e74c3c",
    "MEDIUM": "#f39c12",
    "LOW": "#3498db",
}
_HTML_GRADE_COLORS = {
    "A": "#2ecc71",
    "B": "#27ae60",
    "C": "#f39c12",
    "D": "#e67e22",
    "F": "#e74c3c",
}

_HTML_STYLE = """
body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e0e0e0;
       margin: 0; padding: 24px; }
h1   { color: #00d4ff; font-size: 1.6em; margin-bottom: 4px; }
h2   { color: #00d4ff; font-size: 1.1em; margin: 28px 0 6px; border-bottom: 1px solid #2a2d3a;
       padding-bottom: 6px; }
h3   { color: #aaa; font-size: 0.95em; margin: 18px 0 4px; }
.meta { color: #888; font-size: 0.85em; margin-bottom: 24px; }
.summary-box { background: #1a1d2e; border: 1px solid #2a2d3a; border-radius: 6px;
               padding: 14px 20px; display: inline-block; margin-bottom: 28px; }
.grade { font-size: 2em; font-weight: bold; }
.score { font-size: 1.1em; color: #aaa; margin-left: 10px; }
.endpoint { background: #1a1d2e; border: 1px solid #2a2d3a; border-radius: 6px;
            padding: 16px 20px; margin-bottom: 20px; }
.endpoint-meta { font-size: 0.85em; color: #888; margin-bottom: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 0.88em; margin-bottom: 10px; }
th    { background: #252836; color: #aaa; padding: 7px 10px; text-align: left;
        font-weight: 600; border-bottom: 1px solid #2a2d3a; }
td    { padding: 6px 10px; border-bottom: 1px solid #1e2130; vertical-align: top; }
tr:last-child td { border-bottom: none; }
.tag  { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.82em;
        font-weight: bold; color: #fff; }
.footer { color: #555; font-size: 0.78em; margin-top: 36px; border-top: 1px solid #2a2d3a;
          padding-top: 12px; }
"""


def render_html(results_dict: dict) -> str:
    """
    Render scan results as a self-contained HTML string.

    Produces a dark-themed, offline-capable HTML report with per-endpoint
    header findings tables and authentication/CORS findings. No external
    CSS or JavaScript dependencies — the report can be shared as a single file.

    Args:
        results_dict (dict): Structured scan results as produced by
                             _build_results_dict() in active.py or passive.py.

    Returns:
        str: Complete HTML document as a string, ready to write to a file.
    """
    scan_type = results_dict.get("scan_type", "scan").capitalize()
    timestamp = results_dict.get("timestamp", "")
    version = results_dict.get("version", results_dict.get("sentry_version", ""))
    target = results_dict.get("target", "")
    endpoint_results = results_dict.get("results", [])
    errors = results_dict.get("errors", {})

    avg_score = (
        sum(r["score"] for r in endpoint_results) // len(endpoint_results)
        if endpoint_results else 0
    )

    def _grade(score: int) -> str:
        if score >= 80: return "A"
        if score >= 65: return "B"
        if score >= 50: return "C"
        if score >= 30: return "D"
        return "F"

    def _e(v: object) -> str:
        """Escape server-supplied values before inserting into HTML — prevents XSS."""
        return _html.escape(str(v) if v is not None else "")

    def _tag(text: str, color: str) -> str:
        return f'<span class="tag" style="background:{color}">{text}</span>'

    def _findings_table(findings: list) -> str:
        if not findings:
            return "<p style='color:#888;font-size:0.85em'>No findings.</p>"
        rows = ""
        for f in findings:
            sc = _HTML_STATUS_COLORS.get(f.get("status", ""), "#888")
            sevc = _HTML_SEVERITY_COLORS.get(f.get("severity", ""), "#888")
            detail = f.get("actual_value") or f.get("description", "")
            rows += (
                f"<tr>"
                f"<td>{_e(f.get('name',''))}</td>"
                f"<td>{_tag(_e(f.get('status','')), sc)}</td>"
                f"<td><span style='color:{sevc}'>{_e(f.get('severity',''))}</span></td>"
                f"<td style='color:#ccc'>{_e(detail)}</td>"
                f"</tr>"
            )
        return (
            "<table><tr><th>Header</th><th>Status</th>"
            "<th>Severity</th><th>Detail</th></tr>"
            f"{rows}</table>"
        )

    def _auth_table(auth_findings: list) -> str:
        if not auth_findings:
            return "<p style='color:#888;font-size:0.85em'>No authentication findings.</p>"
        rows = ""
        for af in auth_findings:
            if af.get("flags"):
                for flag in af["flags"]:
                    rows += (
                        f"<tr><td>{_e(af.get('auth_type',''))}</td>"
                        f"<td>{_tag('WARN', '#f39c12')}</td>"
                        f"<td style='color:#ccc'>{_e(af.get('details',''))}"
                        f" <em style='color:#888'>({_e(flag)})</em></td></tr>"
                    )
            else:
                rows += (
                    f"<tr><td>{_e(af.get('auth_type',''))}</td>"
                    f"<td>{_tag('PASS', '#2ecc71')}</td>"
                    f"<td style='color:#ccc'>{_e(af.get('details',''))}</td></tr>"
                )
        return (
            "<table><tr><th>Mechanism</th><th>Status</th><th>Detail</th></tr>"
            f"{rows}</table>"
        )

    # Build per-endpoint sections
    endpoint_html = ""
    for r in endpoint_results:
        score = r.get("score", 0)
        grade = r.get("grade", _grade(score))
        gc = _HTML_GRADE_COLORS.get(grade, "#888")
        endpoint_html += f"""
        <div class="endpoint">
          <h2>{_e(r.get('url', ''))}</h2>
          <div class="endpoint-meta">
            API Type: <strong>{_e(r.get('api_type','unknown'))}</strong>
            &nbsp;&nbsp;|&nbsp;&nbsp;
            Score: <strong style="color:{gc}">{score}/100</strong>
            &nbsp;&nbsp;|&nbsp;&nbsp;
            Grade: <strong style="color:{gc}">{grade}</strong>
          </div>
          <h3>Security Headers</h3>
          {_findings_table(r.get('findings', []))}
          <h3>Authentication &amp; CORS</h3>
          {_auth_table(r.get('auth_findings', []))}
        </div>
        """

    # Errors section
    errors_html = ""
    if errors:
        rows = "".join(
            f"<tr><td>{url}</td><td style='color:#e74c3c'>{msg}</td></tr>"
            for url, msg in errors.items()
        )
        errors_html = (
            "<h2>Failed Requests</h2>"
            "<table><tr><th>URL</th><th>Error</th></tr>"
            f"{rows}</table>"
        )

    overall_grade = _grade(avg_score)
    gc = _HTML_GRADE_COLORS.get(overall_grade, "#888")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentry Report — {_e(target)}</title>
  <style>{_HTML_STYLE}</style>
</head>
<body>
  <h1>Sentry API Security Report</h1>
  <div class="meta">
    Mode: {_e(scan_type)} &nbsp;|&nbsp; Target: {_e(target)}
    &nbsp;|&nbsp; {_e(timestamp)} &nbsp;|&nbsp; Sentry {_e(version)}
  </div>
  <div class="summary-box">
    <span class="grade" style="color:{gc}">{overall_grade}</span>
    <span class="score">Avg score: {avg_score}/100
      &nbsp;|&nbsp; {len(endpoint_results)} endpoint(s) scanned
      {f"&nbsp;|&nbsp; {len(errors)} error(s)" if errors else ""}
    </span>
  </div>
  {endpoint_html}
  {errors_html}
  <div class="footer">Generated by Sentry {version} &mdash; API Security Header Scanner</div>
</body>
</html>"""


def save_html_report(results_dict: dict, report_dir: Path) -> Path:
    """
    Write report.html into the given report directory.

    Args:
        results_dict (dict): Structured scan results from the mode runner.
        report_dir (Path): Directory created by ReportWriter or build_report_dir.

    Returns:
        Path: Absolute path to the written report.html file.

    Raises:
        OSError: If the file cannot be written.
    """
    html_path = report_dir / "report.html"
    html_path.write_text(render_html(results_dict), encoding="utf-8")
    print(f"HTML report saved to: {html_path.resolve()}")
    return html_path


# ---------------------------------------------------------------------------
# PDF rendering
# ---------------------------------------------------------------------------

def save_pdf_report(results_dict: dict, report_dir: Path) -> Path:
    """
    Write report.pdf into the given report directory using ReportLab.

    ReportLab is a required dependency installed automatically with the package.
    The ImportError guard is kept as a defensive fallback in case of unusual
    environments; under normal install it will never trigger.

    Args:
        results_dict (dict): Structured scan results from the mode runner.
        report_dir (Path): Directory created by ReportWriter or build_report_dir.

    Returns:
        Path: Absolute path to the written report.pdf file, or the directory
              path if PDF generation was skipped due to missing dependencies.

    Raises:
        OSError: If the file cannot be written.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        )
    except ImportError:
        print(
            "[FAIL] PDF output requires reportlab. "
            "Try: pip install reportlab pillow"
        )
        return report_dir

    pdf_path = report_dir / "report.pdf"

    scan_type = results_dict.get("scan_type", "scan").capitalize()
    timestamp = results_dict.get("timestamp", "")
    version = results_dict.get("version", results_dict.get("sentry_version", ""))
    target = results_dict.get("target", "")
    endpoint_results = results_dict.get("results", [])
    errors = results_dict.get("errors", {})

    avg_score = (
        sum(r["score"] for r in endpoint_results) // len(endpoint_results)
        if endpoint_results else 0
    )

    # Colour palette matching the HTML report
    _C_BG      = colors.HexColor("#1a1d2e")
    _C_HEADER  = colors.HexColor("#252836")
    _C_PASS    = colors.HexColor("#2ecc71")
    _C_WARN    = colors.HexColor("#f39c12")
    _C_FAIL    = colors.HexColor("#e74c3c")
    _C_HIGH    = colors.HexColor("#e74c3c")
    _C_MEDIUM  = colors.HexColor("#f39c12")
    _C_LOW     = colors.HexColor("#3498db")
    _C_CRIT    = colors.HexColor("#c0392b")
    _C_TEXT    = colors.HexColor("#e0e0e0")
    _C_SUBTEXT = colors.HexColor("#888888")
    _C_BORDER  = colors.HexColor("#2a2d3a")
    _C_PAGE_BG = colors.HexColor("#0f1117")

    styles = getSampleStyleSheet()
    style_normal = ParagraphStyle(
        "normal", parent=styles["Normal"],
        textColor=_C_TEXT, fontSize=8, leading=11,
    )
    style_heading = ParagraphStyle(
        "heading", parent=styles["Heading2"],
        textColor=colors.HexColor("#00d4ff"), fontSize=11, spaceAfter=4,
    )
    style_sub = ParagraphStyle(
        "sub", parent=styles["Normal"],
        textColor=_C_SUBTEXT, fontSize=7.5, leading=10,
    )
    style_url = ParagraphStyle(
        "url", parent=styles["Heading3"],
        textColor=colors.HexColor("#00d4ff"), fontSize=9, spaceBefore=12, spaceAfter=2,
    )

    def _sev_color(sev: str) -> colors.Color:
        return {"CRITICAL": _C_CRIT, "HIGH": _C_HIGH,
                "MEDIUM": _C_MEDIUM, "LOW": _C_LOW}.get(sev, _C_SUBTEXT)

    def _status_color(status: str) -> colors.Color:
        return {"PASS": _C_PASS, "WARN": _C_WARN, "FAIL": _C_FAIL}.get(status, _C_SUBTEXT)

    def _pe(value: object) -> str:
        """Escape server-supplied values for ReportLab XML — prevents tag injection and SSRF."""
        return _html.escape(str(value) if value is not None else "", quote=True)

    def _findings_table_pdf(findings: list) -> Table:
        header = [
            Paragraph("<b>Header</b>", style_sub),
            Paragraph("<b>Status</b>", style_sub),
            Paragraph("<b>Severity</b>", style_sub),
            Paragraph("<b>Detail</b>", style_sub),
        ]
        rows = [header]
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), _C_HEADER),
            ("GRID", (0, 0), (-1, -1), 0.3, _C_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_C_BG, _C_PAGE_BG]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for i, f in enumerate(findings, start=1):
            sc = _status_color(f.get("status", ""))
            sevc = _sev_color(f.get("severity", ""))
            detail = f.get("actual_value") or f.get("description", "")
            rows.append([
                Paragraph(_pe(f.get("name", "")), style_normal),
                Paragraph(
                    f'<font color="{sc.hexval()}">[{_pe(f.get("status",""))}]</font>',
                    style_normal
                ),
                Paragraph(
                    f'<font color="{sevc.hexval()}">{_pe(f.get("severity",""))}</font>',
                    style_normal
                ),
                Paragraph(_pe(detail)[:120], style_normal),
            ])
            if f.get("recommendation"):
                rows.append([
                    Paragraph("", style_sub),
                    Paragraph("", style_sub),
                    Paragraph("Fix:", style_sub),
                    Paragraph(_pe(f.get("recommendation", ""))[:120], style_sub),
                ])
                style_cmds.append(("SPAN", (2, len(rows) - 1), (3, len(rows) - 1)))
        t = Table(rows, colWidths=[48*mm, 16*mm, 18*mm, 88*mm])
        t.setStyle(TableStyle(style_cmds))
        return t

    def _auth_table_pdf(auth_findings: list) -> Table:
        header = [
            Paragraph("<b>Mechanism</b>", style_sub),
            Paragraph("<b>Status</b>", style_sub),
            Paragraph("<b>Detail</b>", style_sub),
        ]
        rows = [header]
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), _C_HEADER),
            ("GRID", (0, 0), (-1, -1), 0.3, _C_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_C_BG, _C_PAGE_BG]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for af in auth_findings:
            sc = _C_WARN if af.get("flags") else _C_PASS
            label = "[WARN]" if af.get("flags") else "[PASS]"
            rows.append([
                Paragraph(_pe(af.get("auth_type", "")), style_normal),
                Paragraph(f'<font color="{sc.hexval()}">{label}</font>', style_normal),
                Paragraph(_pe(af.get("details", ""))[:160], style_normal),
            ])
        t = Table(rows, colWidths=[30*mm, 18*mm, 122*mm])
        t.setStyle(TableStyle(style_cmds))
        return t

    # Build document elements
    story = []
    story.append(Paragraph("Sentry API Security Report", ParagraphStyle(
        "title", parent=styles["Title"],
        textColor=colors.HexColor("#00d4ff"), fontSize=18,
    )))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        f"Mode: {scan_type} &nbsp;|&nbsp; Target: {target} "
        f"&nbsp;|&nbsp; {timestamp} &nbsp;|&nbsp; Sentry {version}",
        style_sub,
    ))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        f"Avg Score: {avg_score}/100 &nbsp;|&nbsp; "
        f"{len(endpoint_results)} endpoint(s) scanned"
        + (f" &nbsp;|&nbsp; {len(errors)} error(s)" if errors else ""),
        style_normal,
    ))
    story.append(Spacer(1, 6*mm))

    for r in endpoint_results:
        score = r.get("score", 0)
        grade = r.get("grade", "F")
        story.append(Paragraph(_pe(r.get("url", "")), style_url))
        story.append(Paragraph(
            f"API Type: {r.get('api_type','unknown')} &nbsp;|&nbsp; "
            f"Score: {score}/100 &nbsp;|&nbsp; Grade: {grade}",
            style_sub,
        ))
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph("Security Headers", style_heading))
        story.append(_findings_table_pdf(r.get("findings", [])))
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph("Authentication & CORS", style_heading))
        story.append(_auth_table_pdf(r.get("auth_findings", [])))
        story.append(Spacer(1, 6*mm))

    if errors:
        story.append(Paragraph("Failed Requests", style_heading))
        err_rows = [[
            Paragraph("<b>URL</b>", style_sub),
            Paragraph("<b>Error</b>", style_sub),
        ]]
        for url, msg in errors.items():
            err_rows.append([
                Paragraph(url, style_normal),
                Paragraph(f'<font color="{_C_FAIL.hexval()}">{msg}</font>', style_normal),
            ])
        t = Table(err_rows, colWidths=[80*mm, 90*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _C_HEADER),
            ("GRID", (0, 0), (-1, -1), 0.3, _C_BORDER),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_C_BG, _C_PAGE_BG]),
        ]))
        story.append(t)

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=15*mm, rightMargin=15*mm,
        topMargin=15*mm, bottomMargin=15*mm,
    )

    def _page_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(_C_PAGE_BG)
        canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
        canvas.restoreState()

    doc.build(story, onFirstPage=_page_bg, onLaterPages=_page_bg)
    print(f"PDF report saved to: {pdf_path.resolve()}")
    return pdf_path
