"""
sentry/modes/__init__.py

Package initialiser for the sentry.modes subpackage. This package contains one
module per scan mode. Each module exposes a single run(config) entry point that
is called by sentry/main.py after argument parsing. Shared analysis logic lives
in sentry/core/ and is imported by each mode module as needed.

Modules:
    active: Direct HTTP request scanning — available on all installation types.
    passive: Browser-based traffic capture — available on desktop installations only.
    spider: Crawl-then-scan workflow — available on all installation types.
"""
