import json

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

OUTPUT_DIR = (
    BASE_DIR
    / "output"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "api_analysis_expectations.json"
)

NORMALIZED_FILE = (
    OUTPUT_DIR
    / "normalized_api_events.json"
)

FINDINGS_FILE = (
    OUTPUT_DIR
    / "api_findings.json"
)

USER_SUMMARY_FILE = (
    OUTPUT_DIR
    / "user_activity_summary.json"
)

TOKEN_SUMMARY_FILE = (
    OUTPUT_DIR
    / "token_activity_summary.json"
)

VALIDATION_OUTPUT = (
    OUTPUT_DIR
    / "api_validation_results.json"
)


def load_json(path):
    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def add_check(
    checks,
    name,
    passed,
    details
):
    checks.append({
        "check": name,
        "passed": passed,
        "details": details
    })


def finding_lookup(
    findings
):
    return {
        finding[
            "finding_id"
        ]: finding
        for finding in findings
    }


def user_lookup(
    users
):
    return {
        user[
            "user"
        ]: user
        for user in users
    }


def token_lookup(
    tokens
):
    return {
        token[
            "token_id"
        ]: token
        for token in tokens
    }


def main():
    expectations = load_json(
        EXPECTATIONS_FILE
    )

    normalized = load_json(
        NORMALIZED_FILE
    )

    findings_report = load_json(
        FINDINGS_FILE
    )

    user_summary = load_json(
        USER_SUMMARY_FILE
    )

    token_summary = load_json(
        TOKEN_SUMMARY_FILE
    )

    checks = []

    events = normalized[
        "events"
    ]

    findings = findings_report[
        "findings"
    ]

    add_check(
        checks,
        "Normalized API event count",
        (
            len(events)
            == expectations[
                "normalized_event_count"
            ]
        ),
        "Expected exactly 27 normalized API events."
    )

    add_check(
        checks,
        "Security finding count",
        (
            len(findings)
            == expectations[
                "finding_count"
            ]
        ),
        "Expected exactly 6 API security findings."
    )

    actual_findings = finding_lookup(
        findings
    )

    finding_metadata_passed = True

    for finding_id, expected in (
        expectations[
            "findings"
        ].items()
    ):
        actual = actual_findings.get(
            finding_id
        )

        if actual is None:
            finding_metadata_passed = False
            break

        if not (
            actual["title"]
            == expected["title"]
            and actual["severity"]
            == expected["severity"]
            and actual["user"]
            == expected["user"]
            and actual[
                "supporting_event_count"
            ]
            == expected[
                "supporting_event_count"
            ]
        ):
            finding_metadata_passed = False
            break

    add_check(
        checks,
        "Finding metadata and severity",
        finding_metadata_passed,
        (
            "All six findings must match "
            "expected title, severity, user, "
            "and evidence counts."
        )
    )

    evidence_passed = True

    for finding_id, expected_ids in (
        expectations[
            "expected_request_evidence"
        ].items()
    ):
        actual = actual_findings.get(
            finding_id
        )

        if actual is None:
            evidence_passed = False
            break

        if actual[
            "supporting_request_ids"
        ] != expected_ids:
            evidence_passed = False
            break

    add_check(
        checks,
        "Critical finding evidence mapping",
        evidence_passed,
        (
            "Authentication, enumeration, and "
            "administrative findings must map "
            "to the expected request IDs."
        )
    )

    unexpected_source_events = sum(
        1
        for event in events
        if (
            event["user"]
            and not event[
                "source_ip_expected"
            ]
        )
    )

    add_check(
        checks,
        "Unexpected source enrichment",
        (
            unexpected_source_events
            == expectations[
                "enrichment_expectations"
            ][
                "unexpected_source_events"
            ]
        ),
        "Expected 2 events from unexpected source IPs."
    )

    out_of_scope_events = sum(
        1
        for event in events
        if event[
            "object_in_expected_scope"
        ] is False
    )

    add_check(
        checks,
        "Object authorization enrichment",
        (
            out_of_scope_events
            == expectations[
                "enrichment_expectations"
            ][
                "out_of_scope_object_events"
            ]
        ),
        "Expected 7 out-of-scope object requests."
    )

    users = user_lookup(
        user_summary[
            "users"
        ]
    )

    contractor = users.get(
        "contractor.user"
    )

    contractor_expected = (
        expectations[
            "user_summary_expectations"
        ][
            "contractor.user"
        ]
    )

    add_check(
        checks,
        "Contractor activity summary",
        (
            contractor is not None
            and contractor[
                "request_count"
            ]
            == contractor_expected[
                "request_count"
            ]
            and contractor[
                "failed_authentication_count"
            ]
            == contractor_expected[
                "failed_authentication_count"
            ]
            and contractor[
                "authorization_denied_count"
            ]
            == contractor_expected[
                "authorization_denied_count"
            ]
            and contractor[
                "out_of_scope_object_count"
            ]
            == contractor_expected[
                "out_of_scope_object_count"
            ]
        ),
        (
            "Contractor summary must match "
            "expected authentication and "
            "authorization activity."
        )
    )

    finance = users.get(
        "finance.user"
    )

    finance_expected = (
        expectations[
            "user_summary_expectations"
        ][
            "finance.user"
        ]
    )

    add_check(
        checks,
        "Finance unexpected-source summary",
        (
            finance is not None
            and finance[
                "request_count"
            ]
            == finance_expected[
                "request_count"
            ]
            and finance[
                "unexpected_source_count"
            ]
            == finance_expected[
                "unexpected_source_count"
            ]
        ),
        (
            "Finance user must show 7 requests "
            "with 2 from unexpected addresses."
        )
    )

    tokens = token_lookup(
        token_summary[
            "tokens"
        ]
    )

    finance_token = tokens.get(
        "TOK-FIN-001"
    )

    token_expected = (
        expectations[
            "token_expectations"
        ][
            "TOK-FIN-001"
        ]
    )

    add_check(
        checks,
        "Finance token reuse summary",
        (
            finance_token is not None
            and finance_token[
                "request_count"
            ]
            == token_expected[
                "request_count"
            ]
            and len(
                finance_token[
                    "source_ips"
                ]
            )
            == token_expected[
                "distinct_source_ips"
            ]
            and finance_token[
                "unexpected_source_event_count"
            ]
            == token_expected[
                "unexpected_source_event_count"
            ]
        ),
        (
            "TOK-FIN-001 must show 7 requests, "
            "2 source IPs, and 2 unexpected "
            "source events."
        )
    )

    guardrails_present = all(
        bool(
            finding.get(
                "guardrail"
            )
        )
        for finding in findings
    )

    add_check(
        checks,
        "Analyst guardrails present",
        guardrails_present,
        (
            "Every finding must preserve an "
            "analyst guardrail against "
            "overstating conclusions."
        )
    )

    expected_ids = {
        "API-001",
        "API-002",
        "API-003",
        "API-004",
        "API-005",
        "API-006"
    }

    add_check(
        checks,
        "Expected finding ID set",
        (
            set(
                actual_findings.keys()
            )
            == expected_ids
        ),
        (
            "Finding IDs must be exactly "
            "API-001 through API-006."
        )
    )

    passed = sum(
        1
        for check in checks
        if check[
            "passed"
        ]
    )

    failed = (
        len(checks)
        - passed
    )

    report = {
        "validation_status": (
            "PASS"
            if failed == 0
            else "REVIEW"
        ),
        "checks_run": len(
            checks
        ),
        "checks_passed": passed,
        "checks_failed": failed,
        "checks": checks
    }

    with open(
        VALIDATION_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )

    print()
    print("=" * 82)
    print(
        "API SECURITY ANALYSIS "
        "VALIDATION"
    )
    print("=" * 82)

    for check in checks:
        status = (
            "PASS"
            if check[
                "passed"
            ]
            else "REVIEW"
        )

        print(
            f"{status:<7} "
            f"{check['check']}"
        )

    print("=" * 82)

    print(
        f"Checks run:     "
        f"{len(checks)}"
    )

    print(
        f"Checks passed:  "
        f"{passed}"
    )

    print(
        f"Checks failed:  "
        f"{failed}"
    )

    print(
        f"Overall:        "
        f"{report['validation_status']}"
    )

    print("=" * 82)

    print(
        f"Validation report: "
        f"{VALIDATION_OUTPUT}"
    )

    print("=" * 82)


if __name__ == "__main__":
    main()
