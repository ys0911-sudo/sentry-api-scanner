"""
tests/test_interceptor.py

Unit tests for sentry/core/interceptor.py.

Covers:
  - SentryAddon.response() host filtering
  - SentryAddon.response() content-type filtering (API pass, static discard, unknown discard)
  - SentryAddon.response() correct storage of CapturedResponse fields
  - build_proxy_options() returns correctly configured Options object
  - run_proxy() starts a background thread and returns a DumpMaster
"""

from __future__ import annotations

import asyncio
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from sentry.core.interceptor import (
    SentryAddon,
    _API_CONTENT_TYPES,
    _STATIC_PREFIXES,
    build_proxy_options,
    run_proxy,
)
from sentry.core.storage import CaptureStore, CapturedResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_flow(
    host: str,
    content_type: str,
    url: str = "https://api.example.com/v1/users",
    status_code: int = 200,
    extra_headers: dict | None = None,
) -> MagicMock:
    """Build a minimal mitmproxy HTTPFlow mock."""
    flow = MagicMock()
    flow.request.host = host
    flow.request.pretty_url = url
    flow.response.status_code = status_code
    headers = {"content-type": content_type}
    if extra_headers:
        headers.update(extra_headers)
    # Use a MagicMock for headers so we can set .get and .items without
    # hitting the read-only restriction on built-in dict methods.
    headers_mock = MagicMock()
    headers_mock.get = lambda k, d="": headers.get(k, d)
    headers_mock.items = headers.items
    flow.response.headers = headers_mock
    return flow


# ---------------------------------------------------------------------------
# Host filtering
# ---------------------------------------------------------------------------

class TestHostFilter:
    def test_matching_host_is_captured(self):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        flow = _make_flow(host="api.example.com", content_type="application/json")
        addon.response(flow)
        assert store.count() == 1

    def test_non_matching_host_is_discarded(self):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        flow = _make_flow(host="static.other.com", content_type="application/json")
        addon.response(flow)
        assert store.count() == 0

    def test_subdomain_mismatch_is_discarded(self):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        flow = _make_flow(host="cdn.example.com", content_type="application/json")
        addon.response(flow)
        assert store.count() == 0


# ---------------------------------------------------------------------------
# Content-type filtering — API types that should be captured
# ---------------------------------------------------------------------------

class TestApiContentTypes:
    @pytest.mark.parametrize("content_type", [
        "application/json",
        "application/json; charset=utf-8",
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
    ])
    def test_api_content_type_is_captured(self, content_type):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        flow = _make_flow(host="api.example.com", content_type=content_type)
        addon.response(flow)
        assert store.count() == 1, f"Expected capture for content-type: {content_type}"


# ---------------------------------------------------------------------------
# Content-type filtering — static assets that should be discarded
# ---------------------------------------------------------------------------

class TestStaticContentTypes:
    @pytest.mark.parametrize("content_type", [
        "image/png",
        "image/jpeg",
        "image/svg+xml",
        "font/woff2",
        "font/ttf",
        "text/css",
        "application/javascript",
        "text/javascript",
        "audio/mpeg",
        "video/mp4",
    ])
    def test_static_content_type_is_discarded(self, content_type):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        flow = _make_flow(host="api.example.com", content_type=content_type)
        addon.response(flow)
        assert store.count() == 0, f"Expected discard for content-type: {content_type}"


# ---------------------------------------------------------------------------
# Content-type filtering — unknown / ambiguous types
# ---------------------------------------------------------------------------

class TestUnknownContentTypes:
    @pytest.mark.parametrize("content_type", [
        "text/html",
        "text/plain",
        "multipart/form-data",
        "",
    ])
    def test_unknown_content_type_is_discarded(self, content_type):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        flow = _make_flow(host="api.example.com", content_type=content_type)
        addon.response(flow)
        assert store.count() == 0, f"Expected discard for content-type: '{content_type}'"


# ---------------------------------------------------------------------------
# Stored CapturedResponse field correctness
# ---------------------------------------------------------------------------

class TestCapturedResponseFields:
    def test_url_is_stored_correctly(self):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        url = "https://api.example.com/v1/orders?status=open"
        flow = _make_flow(host="api.example.com", content_type="application/json", url=url)
        addon.response(flow)
        assert store.all()[0].url == url

    def test_status_code_is_stored_correctly(self):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        flow = _make_flow(host="api.example.com", content_type="application/json", status_code=201)
        addon.response(flow)
        assert store.all()[0].status_code == 201

    def test_content_type_is_stored_correctly(self):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        flow = _make_flow(host="api.example.com", content_type="application/json; charset=utf-8")
        addon.response(flow)
        assert store.all()[0].content_type == "application/json; charset=utf-8"

    def test_headers_are_lowercased(self):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        flow = _make_flow(
            host="api.example.com",
            content_type="application/json",
            extra_headers={"X-Frame-Options": "DENY", "Strict-Transport-Security": "max-age=31536000"},
        )
        addon.response(flow)
        stored_headers = store.all()[0].headers
        assert "x-frame-options" in stored_headers
        assert "strict-transport-security" in stored_headers
        assert "X-Frame-Options" not in stored_headers

    def test_multiple_responses_accumulate(self):
        store = CaptureStore()
        addon = SentryAddon(store=store, target_host="api.example.com")
        for path in ("/users", "/orders", "/products"):
            flow = _make_flow(
                host="api.example.com",
                content_type="application/json",
                url=f"https://api.example.com{path}",
            )
            addon.response(flow)
        assert store.count() == 3


# ---------------------------------------------------------------------------
# build_proxy_options
# ---------------------------------------------------------------------------

class TestBuildProxyOptions:
    def test_default_host_and_port(self):
        opts = build_proxy_options()
        assert opts.listen_host == "127.0.0.1"
        assert opts.listen_port == 8080

    def test_custom_host_and_port(self):
        opts = build_proxy_options(host="0.0.0.0", port=9090)
        assert opts.listen_host == "0.0.0.0"
        assert opts.listen_port == 9090

    def test_ssl_insecure_is_enabled(self):
        opts = build_proxy_options()
        assert opts.ssl_insecure is True


# ---------------------------------------------------------------------------
# run_proxy
# ---------------------------------------------------------------------------

class TestRunProxy:
    def _make_mock_master(self):
        """Return a MagicMock master whose .run() is a no-op async function."""
        mock_master = MagicMock()
        async def _noop(): pass
        mock_master.run = _noop
        return mock_master

    def test_returns_dump_master(self):
        # run_proxy builds the DumpMaster inside a coroutine on a real background
        # event loop and signals readiness via a threading.Event. We let that real
        # loop run and only mock DumpMaster (whose run() is an async no-op), so the
        # coroutine completes immediately and the ready event fires.
        mock_master = self._make_mock_master()

        with patch("mitmproxy.tools.dump.DumpMaster", return_value=mock_master):
            store = CaptureStore()
            result = run_proxy(store=store, target_host="api.example.com", port=18080)

        assert result is mock_master

    def test_dump_master_created_with_correct_options(self):
        mock_master = self._make_mock_master()

        with patch("mitmproxy.tools.dump.DumpMaster", return_value=mock_master) as MockDM, \
             patch("sentry.core.interceptor.build_proxy_options") as mock_opts:
            store = CaptureStore()
            run_proxy(store=store, target_host="api.example.com", host="127.0.0.1", port=18081)

        mock_opts.assert_called_once_with(host="127.0.0.1", port=18081)
        MockDM.assert_called_once()
        args, kwargs = MockDM.call_args
        assert args[0] is mock_opts.return_value
        assert kwargs["with_termlog"] is False
        assert kwargs["with_dumper"] is False
        # DumpMaster is bound to the dedicated background loop created in run_proxy.
        assert "loop" in kwargs

    def test_sentry_addon_is_added(self):
        mock_master = self._make_mock_master()

        with patch("mitmproxy.tools.dump.DumpMaster", return_value=mock_master):
            store = CaptureStore()
            run_proxy(store=store, target_host="api.example.com", port=18082)

        added = mock_master.addons.add.call_args[0][0]
        assert isinstance(added, SentryAddon)
        assert added.target_host == "api.example.com"
        assert added.store is store

    def test_proxy_runs_in_daemon_thread(self):
        mock_master = self._make_mock_master()

        # Wrap the real Thread so the startup coroutine still runs (and the ready
        # event fires, avoiding the 5s timeout) while we capture its kwargs.
        real_thread_cls = threading.Thread
        captured: dict = {}

        def _capture_thread(*args, **kwargs):
            captured.update(kwargs)
            return real_thread_cls(*args, **kwargs)

        with patch("mitmproxy.tools.dump.DumpMaster", return_value=mock_master), \
             patch("sentry.core.interceptor.threading.Thread", side_effect=_capture_thread):
            store = CaptureStore()
            run_proxy(store=store, target_host="api.example.com", port=18083)

        assert captured.get("daemon") is True
