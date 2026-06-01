"""
storage.py

Provides in-memory storage for HTTP responses captured during a passive scan
session. The CaptureStore accumulates (url, headers) pairs as the mitmproxy
addon intercepts them, then makes the full collection available to the passive
mode runner after the browser session ends.

Thread safety is required because the mitmproxy addon writes from the proxy's
event loop thread while the mode runner reads from the main thread after the
session completes.

Classes:
    CapturedResponse: Lightweight dataclass holding one intercepted response.
    CaptureStore: Thread-safe accumulator for captured API responses.

Functions:
    None
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class CapturedResponse:
    """
    Lightweight record of a single HTTP response intercepted by the proxy.

    Attributes:
        url (str): Full URL of the request that produced this response.
        status_code (int): HTTP status code.
        headers (dict[str, str]): Response headers as a plain dict (lowercased keys).
        content_type (str): Convenience copy of the Content-Type header value.
        request_headers (dict[str, str]): Request headers sent by the browser
            (lowercased keys). Used for auth detection and CORS analysis in
            passive mode. Empty dict when not captured.
        body_sample (str): First 2 KB of the response body decoded as UTF-8.
            Populated for error responses (4xx/5xx) and all API responses.
            Empty string when not captured.

    Example:
        r = CapturedResponse(
            url="https://api.example.com/users",
            status_code=200,
            headers={"content-type": "application/json"},
            content_type="application/json",
            request_headers={"authorization": "Bearer eyJ..."},
            body_sample='{"id": 1}',
        )
    """

    url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    body_sample: str = ""


class CaptureStore:
    """
    Thread-safe accumulator for HTTP responses intercepted during a passive session.

    The mitmproxy addon calls .add() from its event loop thread; the mode runner
    calls .all() from the main thread after proxy shutdown. A threading.Lock
    guards both operations.

    Attributes:
        _lock (threading.Lock): Protects _responses against concurrent access.
        _responses (list[CapturedResponse]): Accumulated captured responses.

    Example:
        store = CaptureStore()
        store.add(CapturedResponse(url="...", status_code=200, headers={...}))
        results = store.all()  # called after browser session ends
    """

    def __init__(self) -> None:
        """
        Initialise an empty store with a fresh lock.
        """
        self._lock = threading.Lock()
        self._responses: list[CapturedResponse] = []

    def add(self, response: CapturedResponse) -> None:
        """
        Append a captured response to the store.

        Safe to call from any thread; acquires the lock before writing.

        Args:
            response (CapturedResponse): The intercepted response to store.
        """
        with self._lock:
            self._responses.append(response)

    def all(self) -> list[CapturedResponse]:
        """
        Return a snapshot of all captured responses accumulated so far.

        Returns a copy so that the caller cannot mutate the store's internal list.

        Returns:
            list[CapturedResponse]: All captured responses in insertion order.
        """
        with self._lock:
            return list(self._responses)

    def count(self) -> int:
        """
        Return the number of responses captured so far.

        Returns:
            int: Number of CapturedResponse objects in the store.
        """
        with self._lock:
            return len(self._responses)

    def clear(self) -> None:
        """
        Remove all stored responses.

        Intended for test teardown. Not called during normal scan operation.
        """
        with self._lock:
            self._responses.clear()
