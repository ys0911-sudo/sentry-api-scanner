"""
interceptor.py

Implements the mitmproxy addon that captures HTTP responses during a passive
scan session. Runs as an in-process mitmproxy addon so that Playwright-driven
browser traffic passes through the local proxy and every API response is
available for header analysis without modifying the browser or the target server.

The interceptor filters responses to API endpoints only (JSON, XML, gRPC content
types) and discards static asset traffic (images, fonts, JS bundles) to keep the
scan focused and the report free of noise.

Captured responses are stored in the session-scoped CaptureStore provided by
sentry/core/storage.py so that the passive mode runner can retrieve them after
the browser session ends.

Classes:
    SentryAddon: mitmproxy addon class registered with the in-process proxy.

Functions:
    build_proxy_options: Construct mitmproxy Options for the in-process server.
    run_proxy: Start the mitmproxy master in a background thread and return it.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from sentry.core.storage import CapturedResponse, CaptureStore

# Content-type prefixes that identify API responses worth capturing.
_API_CONTENT_TYPES: tuple[str, ...] = (
    "application/json",
    "application/vnd.api+json",
    "application/hal+json",
    "application/graphql",
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/grpc",
    "application/grpc+proto",
    "application/grpc+json",
    "application/grpc-web",
    "application/grpc-web+proto",
    "application/json-rpc",
    "application/atom+xml",
)

# Content-type prefixes for static assets that are silently discarded.
_STATIC_PREFIXES: tuple[str, ...] = (
    "image/",
    "font/",
    "text/css",
    "application/javascript",
    "text/javascript",
    "audio/",
    "video/",
)


class SentryAddon:
    """
    mitmproxy addon that filters and stores API response headers.

    Registered with mitmproxy's in-process master so it receives every HTTP
    response flowing through the local proxy during a passive scan session.
    Non-API responses (static assets, navigation HTML) are silently discarded.

    Attributes:
        store: CaptureStore instance shared with the passive mode runner.
        target_host (str): Hostname filter — only responses from this host are kept.

    Example:
        addon = SentryAddon(store=my_store, target_host="api.example.com")
        # Registered via mitmproxy's addons list
    """

    def __init__(self, store: CaptureStore, target_host: str) -> None:
        """
        Initialise the addon with a shared capture store and host filter.

        Args:
            store: CaptureStore instance (type imported lazily to avoid circular deps).
            target_host (str): Responses not matching this hostname are discarded.
        """
        self.store = store
        self.target_host = target_host

    def response(self, flow: Any) -> None:
        """
        Handle each HTTP response flowing through the proxy.

        Called by mitmproxy for every completed response. Checks the host filter
        and content type before forwarding headers to the capture store.

        Args:
            flow: mitmproxy HTTPFlow object containing request/response data.
        """
        if flow.request.host != self.target_host:
            return

        content_type = flow.response.headers.get("content-type", "").lower()

        for prefix in _STATIC_PREFIXES:
            if content_type.startswith(prefix):
                return

        if not any(content_type.startswith(ct) for ct in _API_CONTENT_TYPES):
            return

        headers = {k.lower(): v for k, v in flow.response.headers.items()}
        self.store.add(CapturedResponse(
            url=flow.request.pretty_url,
            status_code=flow.response.status_code,
            headers=headers,
            content_type=content_type,
        ))


def build_proxy_options(host: str = "127.0.0.1", port: int = 8080) -> Any:
    """
    Construct a mitmproxy Options object for the in-process proxy server.

    Sets the listening address, disables upstream certificate verification
    (required for TLS interception), and configures the addon list.

    Args:
        host (str): IP address to bind the proxy to. Defaults to loopback.
        port (int): TCP port to listen on. Defaults to 8080.

    Returns:
        mitmproxy.options.Options: Configured options object ready for DumpMaster.
    """
    from mitmproxy.options import Options

    return Options(
        listen_host=host,
        listen_port=port,
        ssl_insecure=True,
    )


def run_proxy(
    store: Any,
    target_host: str,
    host: str = "127.0.0.1",
    port: int = 8080,
) -> Any:
    """
    Start the mitmproxy master in a daemon thread and return the master object.

    The proxy runs until the caller calls master.shutdown(), which the passive
    mode runner does after the browser session ends.

    Args:
        store: CaptureStore to pass to SentryAddon for writing captured headers.
        target_host (str): Hostname to filter API responses by.
        host (str): Proxy bind address.
        port (int): Proxy listen port.

    Returns:
        mitmproxy DumpMaster instance running in a background thread.
    """
    from mitmproxy.tools.dump import DumpMaster

    opts = build_proxy_options(host=host, port=port)

    # mitmproxy 12.x calls asyncio.get_event_loop() during DumpMaster.__init__,
    # which raises RuntimeError when called from a non-async context with no
    # current loop. Create and register a loop before constructing the master.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    master.addons.add(SentryAddon(store=store, target_host=target_host))

    def _run() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(master.run())

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return master
