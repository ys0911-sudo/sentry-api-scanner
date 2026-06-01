"""
tests/conftest.py

Shared pytest fixtures for the Sentry test suite.

The active scanner issues a best-effort OPTIONS preflight (for CORS detection)
and, on GraphQL/JSON-RPC paths, a read-only POST probe. Unit tests mock the GET
response but never intend to touch the network for these auxiliary requests. The
autouse fixture below stubs Session.options and Session.post to raise a benign
ConnectionError, which the scanner already handles as a no-op, keeping the suite
deterministic and offline. Tests that specifically exercise the POST probe
override Session.post locally inside their own patch context.
"""

from __future__ import annotations

import pytest
import requests


@pytest.fixture(autouse=True)
def _no_network_aux_requests(request):
    """Stub the auxiliary OPTIONS/POST requests so unit tests stay offline.

    Skipped for any test marked with @pytest.mark.allow_aux_network, which lets
    POST-probe tests install their own Session.post behaviour.
    """
    if request.node.get_closest_marker("allow_aux_network"):
        yield
        return

    def _refuse(*_args, **_kwargs):
        raise requests.exceptions.ConnectionError("aux request stubbed in tests")

    from unittest.mock import patch

    with patch.object(requests.Session, "options", side_effect=_refuse), \
         patch.object(requests.Session, "post", side_effect=_refuse):
        yield


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "allow_aux_network: allow the active scanner's OPTIONS/POST auxiliary "
        "requests (test installs its own mocks).",
    )
