"""
passive.py

Implements the passive scan mode. Launches a Chromium browser instance via
Playwright routed through an in-process mitmproxy, navigates to the target URL,
and captures every API response header as the browser makes requests naturally.

Unlike active mode, passive mode observes real browser traffic including
authenticated requests, dynamically loaded API calls, and third-party API
endpoints that would not be discoverable from the base URL alone.

This module is only importable and callable when is_passive_available() is True.
On headless installations it is never imported because the --passive flag is not
registered in sentry/main.py.

Classes:
    PassiveScanner: Manages the browser session and proxy lifecycle.

Functions:
    run: Entry point called by sentry/main.py for passive-mode scans.
"""

from __future__ import annotations

from typing import Any, Optional


class PassiveScanner:
    """
    Manages the Playwright browser session and mitmproxy lifecycle for passive mode.

    Starts the in-process mitmproxy (core.interceptor.run_proxy), configures
    Playwright to route all traffic through it, opens the target URL, waits for
    the user or a timeout to signal that browsing is complete, then shuts down the
    proxy and passes captured headers to the analyzer.

    Attributes:
        url (str): The base URL to open in the browser.
        timeout (int): Maximum seconds to wait for user browsing before auto-closing.
        verbose (bool): When True, log each captured response URL to the terminal.
        store: CaptureStore instance shared between the proxy addon and this class.

    Example:
        scanner = PassiveScanner(url="https://example.com", timeout=120)
        results = scanner.scan()
    """

    def __init__(
        self,
        url: str,
        timeout: int = 120,
        verbose: bool = False,
    ) -> None:
        """
        Initialise the passive scanner with a target URL and session options.

        Args:
            url (str): The URL to open in Chromium at session start.
            timeout (int): Seconds to keep the browser open before auto-closing.
                           Gives the user time to navigate and trigger API calls.
            verbose (bool): Echo captured response URLs to the terminal when True.
        """
        self.url = url
        self.timeout = timeout
        self.verbose = verbose
        self.store: Any = None  # CaptureStore created in scan()

    def scan(self) -> list:
        """
        Run the passive capture session and return analysis results.

        Starts mitmproxy, launches Chromium, opens the target URL, waits for
        the session to end (timeout or user closes window), shuts the proxy
        down, then analyses all captured responses and returns results.

        Returns:
            list[core.analyzer.EndpointResult]: Results for every captured API
                                                 endpoint.

        Raises:
            NotImplementedError: Implementation added in the passive-mode phase.
        """
        raise NotImplementedError("PassiveScanner.scan is not yet implemented.")


def run(config: dict) -> None:
    """
    Entry point for passive-mode scans called by sentry/main.py.

    Instantiates PassiveScanner, runs the browser session, renders results to
    the terminal in the requested format, and saves the report via
    core.reporter.save_report() with target='passive_session'.

    Args:
        config (dict): Scan configuration dict from sentry/main.py._run(),
                       containing keys: url, output, save, timeout, verbose.
                       Passive mode always uses a single URL; file-based batch
                       input is not supported in this mode.
    """
    raise NotImplementedError("passive.run is not yet implemented.")
