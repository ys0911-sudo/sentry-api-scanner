"""
spider.py

Implements the spider scan mode. Starting from a base URL, crawls the site by
following internal links up to a configurable depth, collects all discovered
API endpoint URLs, then runs an active-style header scan against each one.

The spider distinguishes API endpoints from navigation pages using the same
content-type heuristics as core.detector. Navigation HTML is followed for link
extraction but is not included in the header analysis report.

Unlike passive mode, the spider never requires a browser or proxy — it uses
the requests library for both crawling and scanning, so it works on headless
server installations.

Classes:
    Spider: Crawls a website and collects URLs up to a depth limit.

Functions:
    run: Entry point called by sentry/main.py for spider-mode scans.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


class Spider:
    """
    Breadth-first web crawler that collects internal URLs for header scanning.

    Starts from a seed URL and follows <a href> links on each page, staying
    within the same domain. Stops when the depth limit or URL count cap is
    reached. Discovered URLs are deduplicated and filtered for API endpoints
    before being passed to the active scanner.

    Attributes:
        seed_url (str): The starting URL for the crawl.
        max_depth (int): Maximum link-follow depth from the seed URL.
        max_urls (int): Hard cap on total URLs to collect across all depths.
        timeout (int): Per-request timeout in seconds.
        verify_ssl (bool): Whether to verify TLS certificates.
        verbose (bool): When True, print each URL as it is discovered.

    Example:
        spider = Spider(seed_url="https://example.com", max_depth=3)
        discovered_urls = spider.crawl()
    """

    def __init__(
        self,
        seed_url: str,
        max_depth: int = 3,
        max_urls: int = 100,
        timeout: int = 30,
        verify_ssl: bool = True,
        verbose: bool = False,
    ) -> None:
        """
        Initialise the spider with a seed URL and crawl limits.

        Args:
            seed_url (str): URL to start the crawl from.
            max_depth (int): Maximum depth of links to follow from the seed.
            max_urls (int): Maximum total URLs to collect before stopping.
            timeout (int): Per-request timeout in seconds.
            verify_ssl (bool): Verify TLS certificates when True.
            verbose (bool): Echo each discovered URL to the terminal when True.
        """
        self.seed_url = seed_url
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose

    def crawl(self) -> list[str]:
        """
        Execute the breadth-first crawl and return all discovered URLs.

        Follows links from the seed URL up to max_depth levels deep. Only
        follows links whose host matches the seed URL's host (stays on-domain).
        Stops early if max_urls is reached.

        Returns:
            list[str]: Deduplicated list of discovered URLs in discovery order.

        Raises:
            NotImplementedError: Implementation added in the spider-mode phase.
        """
        raise NotImplementedError("Spider.crawl is not yet implemented.")


def run(config: dict) -> None:
    """
    Entry point for spider-mode scans called by sentry/main.py.

    Crawls the target URL with Spider, passes discovered API endpoints to an
    ActiveScanner for header analysis, renders results to the terminal, and
    saves the report via core.reporter.save_report().

    The report target name for batch spider results follows the convention:
    'batch_{n}urls' where n is the count of discovered endpoints.

    Args:
        config (dict): Scan configuration dict from sentry/main.py._run(),
                       containing keys: url, output, save, timeout, depth,
                       verify_ssl, verbose.
    """
    raise NotImplementedError("spider.run is not yet implemented.")
