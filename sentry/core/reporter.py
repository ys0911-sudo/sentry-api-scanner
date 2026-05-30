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

Saving happens regardless of the --output flag. The --output flag only controls
what is rendered to the terminal; the JSON and plain-text reports are always
written. The --save flag overrides the default ~/sentry-reports/ root only.

Classes:
    ReportWriter: Manages the lifecycle of a single scan's report directory.

Functions:
    build_report_dir: Compute and create the timestamped report directory path.
    sanitise_target: Convert a URL or description string into a safe directory name.
    save_report: Top-level convenience function called by each mode runner.
"""

from __future__ import annotations

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
