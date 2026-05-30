"""
main.py

Entry point for the Sentry CLI. Builds the Click command object dynamically at
module import time so that --passive is registered only when a graphical display
was detected at install time. On headless or server installations --passive is
absent from the command entirely: it does not appear in --help output and
produces Click's standard "No such option: --passive" error if typed.

The environment check reads ~/.sentry/environment.json written by
sentry/config/environment.py during post-install. If that file is absent (e.g.
during development from source), a live detection is performed instead.

Classes:
    None

Functions:
    _build_params: Construct the Click parameter list for the current environment.
    _version_callback: Eager callback that prints the version string and exits.
    _run: Primary CLI callback — validates inputs and dispatches to the right mode.
    _run_active: Dispatch an active-mode scan (skeleton — logic added in later phase).
    _run_passive: Dispatch a passive-mode scan (skeleton — logic added in later phase).
    _run_spider: Dispatch a spider-mode scan (skeleton — logic added in later phase).
"""

from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console

from sentry import __version__
from sentry.config.environment import is_passive_available

console = Console()

# Evaluated once at import time so the entire params list is stable for the
# lifetime of the process; repeated invocations see the same option set.
_PASSIVE_AVAILABLE: bool = is_passive_available()

_HELP_TEXT = """\
Sentry -- API Security Header Scanner.

Scans HTTP APIs for missing or misconfigured security headers and produces a
structured report. Choose a scan mode, supply a target URL or URL list, and
optionally control output format and report save location.

Examples:

  sentry --active --url https://api.example.com

  sentry --spider --url https://example.com --depth 5

  sentry --active --file urls.txt --output json

  sentry --active --url https://api.example.com --save /tmp/my-reports
"""


def _build_params() -> list[click.Parameter]:
    """
    Construct the complete Click parameter list for the current environment.

    Reads the module-level _PASSIVE_AVAILABLE flag (set at import time from the
    install-time environment cache) and conditionally prepends --passive to the
    mode-flag group. All other parameters are always registered.

    Returns:
        list[click.Parameter]: Ordered list of Click Parameter objects attached
                               to the sentry command.
    """
    params: list[click.Parameter] = []

    # --- Mode flags -------------------------------------------------------
    # Passive is only added when a display was detected at install time.
    # The three flags are independent booleans; mutual exclusion is enforced
    # in _run() so the help output stays clean without hidden constraints.
    if _PASSIVE_AVAILABLE:
        params.append(
            click.Option(
                ["--passive"],
                is_flag=True,
                default=False,
                help="Launch browser and capture API traffic passively.",
            )
        )

    params.extend(
        [
            click.Option(
                ["--active"],
                is_flag=True,
                default=False,
                help="Scan known API URLs directly with HTTP requests.",
            ),
            click.Option(
                ["--spider"],
                is_flag=True,
                default=False,
                help="Auto-discover and scan endpoints from a base URL.",
            ),
        ]
    )

    # --- Target input -----------------------------------------------------
    params.extend(
        [
            click.Option(
                ["--url", "-u"],
                metavar="URL",
                default=None,
                help="Single target URL to scan.",
            ),
            click.Option(
                ["--file", "-f"],
                type=click.Path(exists=True, readable=True, path_type=Path),
                default=None,
                metavar="FILE",
                help="File containing one URL per line for batch scanning.",
            ),
        ]
    )

    # --- Output control ---------------------------------------------------
    params.extend(
        [
            click.Option(
                ["--output", "-o"],
                type=click.Choice(["table", "json", "html", "pdf"], case_sensitive=False),
                default="table",
                show_default=True,
                help="Terminal output format. Does not affect the saved report.",
            ),
            click.Option(
                ["--save", "-s"],
                type=click.Path(path_type=Path),
                default=None,
                metavar="DIR",
                help="Override default report save location (~/sentry-reports/).",
            ),
        ]
    )

    # --- Scan behaviour ---------------------------------------------------
    params.extend(
        [
            click.Option(
                ["--timeout", "-t"],
                type=int,
                default=30,
                show_default=True,
                metavar="SECONDS",
                help="Per-request timeout in seconds.",
            ),
            click.Option(
                ["--depth", "-d"],
                type=int,
                default=3,
                show_default=True,
                metavar="DEPTH",
                help="Maximum crawl depth for --spider mode.",
            ),
            click.Option(
                ["--insecure", "-k"],
                is_flag=True,
                default=False,
                help="Disable SSL certificate verification.",
            ),
            click.Option(
                ["--verbose", "-v"],
                is_flag=True,
                default=False,
                help="Print each request as it is made.",
            ),
        ]
    )

    # --- Meta flags -------------------------------------------------------
    params.append(
        click.Option(
            ["--version", "-V"],
            is_flag=True,
            is_eager=True,
            expose_value=False,
            callback=_version_callback,
            help="Show version and exit.",
        )
    )

    return params


def _version_callback(
    ctx: click.Context,
    _param: click.Parameter,
    value: bool,
) -> None:
    """
    Print the version string and exit when --version or -V is passed.

    Registered as an eager callback so it fires before argument validation,
    which allows 'sentry --version' without requiring --url or a mode flag.

    Args:
        ctx (click.Context): The active Click context.
        _param (click.Parameter): The triggering parameter (not used directly).
        value (bool): True when --version was supplied on the command line.
    """
    if not value or ctx.resilient_parsing:
        return
    click.echo(f"Sentry {__version__}")
    ctx.exit()


def _run(
    active: bool,
    spider: bool,
    url: Optional[str],
    file: Optional[Path],
    output: str,
    save: Optional[Path],
    timeout: int,
    depth: int,
    insecure: bool,
    verbose: bool,
    **kwargs: Any,
) -> None:
    """
    Primary CLI callback invoked by Click after all arguments are parsed.

    Resolves the active scan mode from the three mode flags, enforces mutual
    exclusion, validates that exactly one target source is provided, then
    dispatches to the appropriate mode runner. **kwargs absorbs 'passive' when
    passive mode is registered in the current environment, avoiding a signature
    mismatch between headless and desktop installations.

    Args:
        active (bool): True when --active was passed.
        spider (bool): True when --spider was passed.
        url (Optional[str]): Single target URL, or None if --file was used.
        file (Optional[Path]): Path to URL list file, or None if --url was used.
        output (str): Terminal output format from Click.Choice.
        save (Optional[Path]): Override directory for saved reports, or None.
        timeout (int): Per-request timeout in seconds.
        depth (int): Spider crawl depth limit.
        insecure (bool): When True, SSL verification is disabled.
        verbose (bool): When True, each request is echoed to the terminal.
        **kwargs: Absorbs 'passive' (bool) when registered in this environment.

    Raises:
        click.UsageError: When more than one mode flag is given, when no target
                          is provided, or when both --url and --file are given.
    """
    # **kwargs carries 'passive' only when _PASSIVE_AVAILABLE is True
    passive: bool = kwargs.get("passive", False)

    # Exactly one mode flag must be set; default to active when none is given
    modes_selected = sum([passive, active, spider])
    if modes_selected > 1:
        raise click.UsageError(
            "Specify only one mode flag: "
            + (
                "--passive, --active, or --spider."
                if _PASSIVE_AVAILABLE
                else "--active or --spider."
            )
        )

    if passive:
        mode = "passive"
    elif spider:
        mode = "spider"
    else:
        # --active or no flag — active is the default mode
        mode = "active"

    # Require exactly one target source
    if url is None and file is None:
        raise click.UsageError("Provide a target with --url URL or --file FILE.")
    if url is not None and file is not None:
        raise click.UsageError("Use --url or --file, not both.")

    scan_config: dict = {
        "url": url,
        "file": file,
        "output": output,
        "save": save,
        "timeout": timeout,
        "depth": depth,
        "verify_ssl": not insecure,
        "verbose": verbose,
    }

    if mode == "passive":
        _run_passive(scan_config)
    elif mode == "spider":
        _run_spider(scan_config)
    else:
        _run_active(scan_config)


def _run_active(config: dict) -> None:
    """
    Dispatch an active-mode scan and print results.

    Imports modes.active lazily so that import-time errors in other unimplemented
    modules do not break the CLI on those code paths.

    Args:
        config (dict): Scan configuration dict built by _run.
    """
    from sentry.modes.active import run as _active_run

    _active_run(config)


def _run_passive(config: dict) -> None:
    """
    Dispatch a passive-mode scan via browser interception and print results.

    Skeleton implementation — Playwright + mitmproxy logic is added in the
    passive-mode phase. This function is only reachable when _PASSIVE_AVAILABLE
    is True (i.e. --passive was registered and the user passed it), so no
    additional display check is needed here.

    Args:
        config (dict): Scan configuration dict built by _run.
    """
    from sentry.modes import passive as _passive_module  # noqa: F401

    console.print("[bold cyan][[INFO]][/bold cyan] Passive scan not yet implemented.")


def _run_spider(config: dict) -> None:
    """
    Dispatch a spider-mode scan and print results.

    Skeleton implementation — crawl and scan logic is added in the spider-mode
    phase. Imports modes.spider lazily for the same reason as _run_active.

    Args:
        config (dict): Scan configuration dict built by _run.
    """
    from sentry.modes import spider as _spider_module  # noqa: F401

    console.print("[bold cyan][[INFO]][/bold cyan] Spider scan not yet implemented.")


# Build the Click command at module import time. _build_params() reads the
# environment cache so the params list is fixed before any invocation occurs.
cli = click.Command(
    name="sentry",
    callback=_run,
    params=_build_params(),
    help=_HELP_TEXT,
    context_settings={
        "help_option_names": ["--help", "-h"],
        "max_content_width": 100,
    },
)
