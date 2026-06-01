"""
test_detector_priority.py

Priority and edge-case tests for sentry.core.detector.detect_api_type.

Tests the 10 scenarios that exercise detection priority handling: cases where
multiple types have overlapping signals and the detector must pick the correct
winner. Run as a diagnostic script (python tests/test_detector_priority.py)
or as a pytest module (pytest tests/test_detector_priority.py).

Functions:
    run_scenario: Execute one detection and return a pass/fail result dict.
    print_scenario: Print formatted output for one scenario result.
    main: Run all 10 scenarios, print results, and exit with code 1 on any failure.
"""

import sys
from pathlib import Path

# Allow running directly from the project root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentry.core.detector import ApiType, detect_api_type


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------

SCENARIOS = [
    {
        "number": 1,
        "name": "GraphQL with only application/json",
        "url": "https://api.example.com/graphql",
        "status_code": 200,
        "request_headers": {"content-type": "application/json"},
        "response_headers": {"content-type": "application/json"},
        "body": '{"data": {"user": {"name": "test"}}}',
        "expected": ApiType.GRAPHQL,
        "reason": "/graphql path pattern should dominate",
    },
    {
        "number": 2,
        "name": "REST with application/json and no API path",
        "url": "https://api.example.com/v1/users",
        "status_code": 200,
        "request_headers": {"content-type": "application/json"},
        "response_headers": {"content-type": "application/json"},
        "body": '{"users": [{"id": 1, "name": "test"}]}',
        "expected": ApiType.REST,
        "reason": "Generic JSON path with no type-specific signals — REST fallback",
    },
    {
        "number": 3,
        "name": "GraphQL introspection query",
        "url": "https://api.example.com/query",
        "status_code": 200,
        "request_headers": {"content-type": "application/json"},
        "response_headers": {"content-type": "application/json"},
        "body": '{"query": "{ __schema { types { name } } }"}',
        "expected": ApiType.GRAPHQL,
        "reason": "__schema body signal is definitive GraphQL",
    },
    {
        "number": 4,
        "name": "GraphQL mutation with no path hint",
        "url": "https://api.example.com/api",
        "status_code": 200,
        "request_headers": {"content-type": "application/json"},
        "response_headers": {"content-type": "application/json"},
        "body": '{"mutation": "createUser(input: {name: \\"test\\"})"}',
        "expected": ApiType.GRAPHQL,
        "reason": "mutation body key is a GraphQL-specific signal",
    },
    {
        "number": 5,
        "name": "gRPC vs REST conflict",
        "url": "https://api.example.com/v1/users",
        "status_code": 200,
        "request_headers": {
            "content-type": "application/grpc",
            "te": "trailers",
        },
        "response_headers": {
            "content-type": "application/grpc",
            "grpc-status": "0",
        },
        "body": "",
        "expected": ApiType.GRPC,
        "reason": "grpc-status response header + application/grpc content-type dominate REST path",
    },
    {
        "number": 6,
        "name": "SOAP with JSON path conflict",
        "url": "https://api.example.com/soap/service",
        "status_code": 200,
        "request_headers": {"content-type": "text/xml"},
        "response_headers": {"content-type": "text/xml"},
        "body": (
            "<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'>"
            "<soap:Body></soap:Body></soap:Envelope>"
        ),
        "expected": ApiType.SOAP,
        "reason": "soap:Envelope body + text/xml + /soap/ path are unambiguous",
    },
    {
        "number": 7,
        "name": "Apollo GraphQL client headers",
        "url": "https://api.example.com/api/data",
        "status_code": 200,
        "request_headers": {
            "content-type": "application/json",
            "x-apollo-operation-name": "GetUser",
            "x-apollo-operation-type": "query",
        },
        "response_headers": {"content-type": "application/json"},
        "body": '{"data": {"user": {"id": 1}}}',
        "expected": ApiType.GRAPHQL,
        "reason": "Apollo operation headers are definitive GraphQL signals",
    },
    {
        "number": 8,
        "name": "OData with JSON response",
        "url": "https://api.example.com/odata/v4/Products",
        "status_code": 200,
        "request_headers": {"accept": "application/json"},
        "response_headers": {
            "content-type": "application/json",
            "odata-version": "4.0",
        },
        "body": '{"value": [{"ProductID": 1}]}',
        "expected": ApiType.ODATA,
        "reason": "odata-version response header + /odata/ path dominate",
    },
    {
        "number": 9,
        "name": "Webhook with GitHub event headers",
        "url": "https://api.example.com/webhook",
        "status_code": 200,
        "request_headers": {
            "content-type": "application/json",
            "x-github-event": "push",
            "x-hub-signature-256": "sha256=abc123",
        },
        "response_headers": {"content-type": "application/json"},
        "body": '{"ref": "refs/heads/main"}',
        "expected": ApiType.WEBHOOK,
        "reason": "GitHub event headers dominate",
    },
    {
        "number": 10,
        "name": "Ambiguous REST vs JSON-RPC",
        "url": "https://api.example.com/api/rpc",
        "status_code": 200,
        "request_headers": {"content-type": "application/json"},
        "response_headers": {"content-type": "application/json"},
        "body": '{"jsonrpc": "2.0", "method": "getUser", "id": 1}',
        "expected": ApiType.JSONRPC,
        "reason": '"jsonrpc" body key is definitive JSON-RPC',
    },
]


# ---------------------------------------------------------------------------
# Diagnostic runner (used by main() and by pytest via individual functions)
# ---------------------------------------------------------------------------

def run_scenario(scenario: dict) -> dict:
    """
    Execute one detection scenario and return a result dict with pass/fail state.

    Args:
        scenario (dict): One entry from SCENARIOS containing url, headers, body,
                         expected type, and metadata.

    Returns:
        dict: Result containing 'passed' bool, 'result' DetectionResult, and
              the original scenario dict for reporting.
    """
    result = detect_api_type(
        url=scenario["url"],
        status_code=scenario["status_code"],
        response_headers=scenario["response_headers"],
        body_sample=scenario["body"],
        request_headers=scenario["request_headers"],
    )
    return {
        "scenario": scenario,
        "result": result,
        "passed": result.api_type == scenario["expected"],
    }


def print_scenario(run_result: dict) -> None:
    """
    Print a formatted diagnostic block for one scenario run result.

    Args:
        run_result (dict): Output of run_scenario.
    """
    sc = run_result["scenario"]
    result = run_result["result"]
    passed = run_result["passed"]
    label = "[PASS]" if passed else "[FAIL]"

    print(f"{label}  Scenario {sc['number']}: {sc['name']}")
    print(f"       Detected : {result.api_type.value}  (score={result.score})")
    print(f"       Expected : {sc['expected'].value}")

    if result.matched_signals:
        print("       Signals  :")
        for sig in result.matched_signals:
            print(f"                  {sig}")
    else:
        print("       Signals  : (none)")

    if not passed:
        print(f"  [!]  MISMATCH — got '{result.api_type.value}' expected '{sc['expected'].value}'")
        print(f"       Reason   : {sc['reason']}")

    print()


# ---------------------------------------------------------------------------
# pytest-compatible individual test functions
# ---------------------------------------------------------------------------

def test_scenario_1_graphql_path_only():
    """GraphQL detected from /graphql path with generic JSON content-type."""
    r = run_scenario(SCENARIOS[0])
    assert r["passed"], (
        f"Expected {SCENARIOS[0]['expected'].value}, "
        f"got {r['result'].api_type.value} (score={r['result'].score})\n"
        f"Signals: {r['result'].matched_signals}"
    )


def test_scenario_2_rest_no_api_path():
    """REST returned as fallback when no type-specific signals present."""
    r = run_scenario(SCENARIOS[1])
    assert r["passed"], (
        f"Expected {SCENARIOS[1]['expected'].value}, "
        f"got {r['result'].api_type.value} (score={r['result'].score})\n"
        f"Signals: {r['result'].matched_signals}"
    )


def test_scenario_3_graphql_introspection():
    """GraphQL detected from __schema in body even without a /graphql path."""
    r = run_scenario(SCENARIOS[2])
    assert r["passed"], (
        f"Expected {SCENARIOS[2]['expected'].value}, "
        f"got {r['result'].api_type.value} (score={r['result'].score})\n"
        f"Signals: {r['result'].matched_signals}"
    )


def test_scenario_4_graphql_mutation_no_path():
    """GraphQL detected from mutation body key with no path or header hints."""
    r = run_scenario(SCENARIOS[3])
    assert r["passed"], (
        f"Expected {SCENARIOS[3]['expected'].value}, "
        f"got {r['result'].api_type.value} (score={r['result'].score})\n"
        f"Signals: {r['result'].matched_signals}"
    )


def test_scenario_5_grpc_beats_rest_path():
    """gRPC wins over REST path pattern when grpc-status header is present."""
    r = run_scenario(SCENARIOS[4])
    assert r["passed"], (
        f"Expected {SCENARIOS[4]['expected'].value}, "
        f"got {r['result'].api_type.value} (score={r['result'].score})\n"
        f"Signals: {r['result'].matched_signals}"
    )


def test_scenario_6_soap_with_json_path():
    """SOAP detected despite JSON in URL path; body + content-type dominate."""
    r = run_scenario(SCENARIOS[5])
    assert r["passed"], (
        f"Expected {SCENARIOS[5]['expected'].value}, "
        f"got {r['result'].api_type.value} (score={r['result'].score})\n"
        f"Signals: {r['result'].matched_signals}"
    )


def test_scenario_7_apollo_graphql_headers():
    """GraphQL detected from Apollo operation headers with no path hint."""
    r = run_scenario(SCENARIOS[6])
    assert r["passed"], (
        f"Expected {SCENARIOS[6]['expected'].value}, "
        f"got {r['result'].api_type.value} (score={r['result'].score})\n"
        f"Signals: {r['result'].matched_signals}"
    )


def test_scenario_8_odata_json_response():
    """OData detected from odata-version response header + /odata/ path."""
    r = run_scenario(SCENARIOS[7])
    assert r["passed"], (
        f"Expected {SCENARIOS[7]['expected'].value}, "
        f"got {r['result'].api_type.value} (score={r['result'].score})\n"
        f"Signals: {r['result'].matched_signals}"
    )


def test_scenario_9_webhook_github_headers():
    """Webhook detected from GitHub event headers."""
    r = run_scenario(SCENARIOS[8])
    assert r["passed"], (
        f"Expected {SCENARIOS[8]['expected'].value}, "
        f"got {r['result'].api_type.value} (score={r['result'].score})\n"
        f"Signals: {r['result'].matched_signals}"
    )


def test_scenario_10_jsonrpc_vs_rest():
    """JSON-RPC wins over REST when jsonrpc body key is present."""
    r = run_scenario(SCENARIOS[9])
    assert r["passed"], (
        f"Expected {SCENARIOS[9]['expected'].value}, "
        f"got {r['result'].api_type.value} (score={r['result'].score})\n"
        f"Signals: {r['result'].matched_signals}"
    )


# ---------------------------------------------------------------------------
# Diagnostic entry point
# ---------------------------------------------------------------------------

def main() -> int:
    """
    Run all scenarios diagnostically, print per-scenario output, and return
    an exit code (0 = all passed, 1 = one or more failed).

    Returns:
        int: 0 if all scenarios passed, 1 otherwise.
    """
    print("=" * 60)
    print("Sentry — Detector Priority Test Suite")
    print("=" * 60)
    print()

    results = [run_scenario(sc) for sc in SCENARIOS]
    for r in results:
        print_scenario(r)

    passed = sum(1 for r in results if r["passed"])
    failed = len(results) - passed

    print("=" * 60)
    print(f"  Passed: {passed}/{len(results)}")
    print(f"  Failed: {failed}/{len(results)}")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
