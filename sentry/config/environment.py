"""
environment.py

Detects whether a graphical display environment is available on the host
system and writes the result to ~/.sentry/environment.json. This detection
runs once at install time (debian/postinst, pyproject post-install script, or
Dockerfile RUN step) so that the CLI can read the cached result on every
subsequent invocation without probing the environment again.

The module is also imported by sentry/main.py at startup to decide whether
--passive should be registered as a valid CLI option. On headless systems the
flag is omitted entirely, so it neither appears in --help nor accepts input.

Classes:
    None

Functions:
    detect_environment: Probe the system for display availability and return a result dict.
    save_environment: Write a detection result dict to ~/.sentry/environment.json.
    detect_and_save: Run detection and persist the result in one call (install-time entry point).
    is_passive_available: Read the cached result and return whether passive mode can run.
"""

import json
import os
import platform
from pathlib import Path


# Canonical location for the cached environment config written at install time
_ENV_FILE = Path.home() / ".sentry" / "environment.json"


def detect_environment() -> dict:
    """
    Probe the running system for graphical display environment variables.

    Checks DISPLAY (X11), WAYLAND_DISPLAY, WSL kernel release string, and
    /proc/1/environ as a fallback for container or service environments that
    inherit a display without propagating it to the current process.

    Returns:
        dict: {"passive_available": bool} — True means a graphical display was
              detected and Playwright-based passive mode can be launched.
    """
    # X11 display set — covers most desktop Linux and XQuartz on macOS
    if os.environ.get("DISPLAY"):
        return {"passive_available": True}

    # Wayland compositor present — modern desktop Linux (GNOME, KDE on Wayland)
    if os.environ.get("WAYLAND_DISPLAY"):
        return {"passive_available": True}

    # WSL without a forwarded DISPLAY has no graphical environment even though
    # its kernel release contains 'microsoft-standard'
    release = platform.uname().release
    if "microsoft-standard" in release:
        return {"passive_available": False}

    # Some process supervisors launch services with DISPLAY set on PID 1 but
    # not exported to child processes — read /proc/1/environ to catch these
    try:
        if os.path.exists("/proc/1/environ"):
            with open("/proc/1/environ", "rb") as fh:
                # Pairs are separated by null bytes: b"KEY=VALUE\x00KEY=VALUE\x00..."
                for pair in fh.read().split(b"\x00"):
                    if pair.startswith(b"DISPLAY=") and len(pair) > len(b"DISPLAY="):
                        return {"passive_available": True}
    except (PermissionError, OSError):
        # Unreadable inside some container configurations — continue without it
        pass

    return {"passive_available": False}


def save_environment(result: dict) -> None:
    """
    Persist a detection result dict to ~/.sentry/environment.json.

    Creates ~/.sentry/ if it does not exist. Overwrites any previous result so
    that running the detection again after a display change picks up new state.

    Args:
        result (dict): Detection result, e.g. {"passive_available": True}.

    Raises:
        OSError: If the directory cannot be created or the file cannot be written.
    """
    _ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(_ENV_FILE, "w") as fh:
        json.dump(result, fh, indent=2)


def detect_and_save() -> dict:
    """
    Run display detection and write the result to disk in a single call.

    This is the function called by debian/postinst, the pyproject post-install
    script, and the Dockerfile RUN step. It is idempotent — safe to run more
    than once and will overwrite any previous cached result.

    Returns:
        dict: The detection result that was saved, e.g. {"passive_available": False}.
    """
    result = detect_environment()
    save_environment(result)
    return result


def is_passive_available() -> bool:
    """
    Return whether passive mode is available on this installation.

    Reads ~/.sentry/environment.json written at install time. Falls back to a
    live detection call when the file is missing or malformed so that the CLI
    degrades gracefully when the post-install hook did not run (e.g. when
    running directly from a source checkout during development).

    Returns:
        bool: True if a graphical display was detected at install time (or now,
              if the cached file does not exist).
    """
    try:
        with open(_ENV_FILE) as fh:
            data = json.load(fh)
            return bool(data.get("passive_available", False))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        # Cache file absent — detect live so the CLI still works correctly
        return bool(detect_environment().get("passive_available", False))
