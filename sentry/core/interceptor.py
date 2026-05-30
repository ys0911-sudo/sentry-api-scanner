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
        Request headers and a response body sample are also captured so that
        auth detection and CORS analysis have full context in passive mode.

        Args:
            flow: mitmproxy HTTPFlow object containing request/response data.
        """
        if flow.request.host != self.target_host:
            return

        content_type = flow.response.headers.get("content-type", "").lower()

        for prefix in _STATIC_PREFIXES:
            if content_type.startswith(prefix):
                return

        is_api = any(content_type.startswith(ct) for ct in _API_CONTENT_TYPES)
        is_error = flow.response.status_code >= 400

        # Capture API responses and all error responses. Non-API success
        # responses (HTML pages, etc.) are skipped as noise.
        if not is_api and not is_error:
            return

        headers = {k.lower(): v for k, v in flow.response.headers.items()}
        request_headers = {k.lower(): v for k, v in flow.request.headers.items()}

        # Capture up to 2 KB of response body for error analysis and body-based
        # API type detection. Decode with replace so binary payloads don't crash.
        try:
            raw = flow.response.get_content()
            body_sample = raw[:2048].decode("utf-8", errors="replace") if raw else ""
        except Exception:
            body_sample = ""

        self.store.add(CapturedResponse(
            url=flow.request.pretty_url,
            status_code=flow.response.status_code,
            headers=headers,
            content_type=content_type,
            request_headers=request_headers,
            body_sample=body_sample,
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

    mitmproxy 12.x requires the event loop to be *running* (not just set) when
    DumpMaster is instantiated because Master.__init__ calls
    asyncio.get_running_loop(). This function therefore creates the DumpMaster
    inside a coroutine that runs on the dedicated background loop, signals a
    threading.Event when the master is ready, and then awaits master.run().
    The caller blocks on that event before returning the master reference.

    Args:
        store: CaptureStore to pass to SentryAddon for writing captured headers.
        target_host (str): Hostname to filter API responses by.
        host (str): Proxy bind address.
        port (int): Proxy listen port.

    Returns:
        mitmproxy DumpMaster instance running in a background thread.

    Raises:
        RuntimeError: If the proxy fails to start within 5 seconds.
    """
    from mitmproxy.tools.dump import DumpMaster

    opts = build_proxy_options(host=host, port=port)
    loop = asyncio.new_event_loop()

    _holder: list[Any] = []
    _ready = threading.Event()

    async def _start() -> None:
        # DumpMaster must be created here — inside the running loop — because
        # Master.__init__ calls asyncio.get_running_loop().
        master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
        master.addons.add(SentryAddon(store=store, target_host=target_host))
        _holder.append(master)
        _ready.set()
        await master.run()

    def _thread() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_start())

    thread = threading.Thread(target=_thread, daemon=True)
    thread.start()

    if not _ready.wait(timeout=5):
        raise RuntimeError("mitmproxy failed to start within 5 seconds")

    return _holder[0]
