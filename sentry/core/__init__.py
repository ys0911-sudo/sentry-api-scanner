"""
sentry/core/__init__.py

Package initialiser for the sentry.core subpackage. This package contains the
scan-mode-agnostic processing pipeline: header analysis, API type detection,
passive traffic interception, in-memory response storage, and report writing.
Mode-specific orchestration lives in sentry/modes/ instead.

Modules:
    analyzer: Evaluates HTTP headers against security rules and produces scored results.
    detector: Identifies API protocol type (REST/gRPC/GraphQL/SOAP) from response signals.
    interceptor: mitmproxy addon that captures API responses during passive scan sessions.
    reporter: Creates timestamped report directories and writes JSON + plain-text reports.
    storage: Thread-safe in-memory store for responses captured by the proxy interceptor.
"""
