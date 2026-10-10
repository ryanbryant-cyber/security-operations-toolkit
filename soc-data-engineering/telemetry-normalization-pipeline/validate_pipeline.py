import csv
import json
import math

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

OUTPUT_DIR = (
    BASE_DIR
    / "output"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "pipeline_expectations.json"
)

QUALITY_REPORT_FILE = (
    OUTPUT_DIR
    / "telemetry_quality_report.json"
)

NORMALIZED_JSON_FILE = (
    OUTPUT_DIR
    / "normalized_events.json"
)

NORMALIZED_CSV_FILE = (
    OUTPUT_DIR
    / "normalized_events.csv"
)

INVALID_FILE = (
    OUTPUT_DIR
    / "invalid_events.json"
)

DUPLICATE_FILE = (
    OUTPUT_DIR
    / "duplicate_events.json"
)

VALIDATION_OUTPUT = (
    OUTPUT_DIR
    / "pipeline_validation_results.json"
)


def load_json(file_path):
    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def load_csv(file_path):
    with open(
        file_path,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        return list(
            csv.DictReader(
                file
            )
        )


def numbers_match(
    actual,
    expected
):
    return math.isclose(
        float(actual),
        float(expected),
        rel_tol=1e-9,
        abs_tol=1e-9
    )


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


def source_lookup(report):
    return {
        source["source"]: source
        for source in report[
            "sources"
        ]
    }


def find_event(
    events,
    raw_event_id
):
    for event in events:
        if (
            event.get(
                "raw_event_id"
            )
            == raw_event_id
        ):
            return event

    return None


def find_invalid_record(
    invalid_events,
    source_file,
    source_event_number
):
    for result in invalid_events:
        if (
            result.get(
                "source_file"
            )
            == source_file
            and result.get(
                "source_event_number"
            )
            == source_event_number
        ):
            return result

    return None


def issue_exists(
    result,
    issue_type,
    field
):
    if result is None:
        return False

    return any(
        issue.get(
            "issue_type"
        )
        == issue_type
        and issue.get(
            "field"
        )
        == field
        for issue in result.get(
            "issues",
            []
        )
    )


def main():
    expectations = load_json(
        EXPECTATIONS_FILE
    )

    quality_report = load_json(
        QUALITY_REPORT_FILE
    )

    normalized_json = load_json(
        NORMALIZED_JSON_FILE
    )

    normalized_csv = load_csv(
        NORMALIZED_CSV_FILE
    )

    invalid_report = load_json(
        INVALID_FILE
    )

    duplicate_report = load_json(
        DUPLICATE_FILE
    )

    checks = []

    expected_overall = expectations[
        "overall"
    ]

    actual_overall = quality_report[
        "overall"
    ]

    add_check(
        checks,
        "Overall event counts",
        (
            actual_overall[
                "raw_events"
            ]
            == expected_overall[
                "raw_events"
            ]
            and actual_overall[
                "normalized_events"
            ]
            == expected_overall[
                "normalized_events"
            ]
            and actual_overall[
                "duplicate_events"
            ]
            == expected_overall[
                "duplicate_events"
            ]
            and actual_overall[
                "invalid_events"
            ]
            == expected_overall[
                "invalid_events"
            ]
        ),
        (
            "Expected 25 raw, 21 clean, "
            "1 duplicate, and 3 invalid events."
        )
    )

    add_check(
        checks,
        "Overall quality scoring",
        (
            numbers_match(
                actual_overall[
                    "average_event_score"
                ],
                expected_overall[
                    "average_event_score"
                ]
            )
            and numbers_match(
                actual_overall[
                    "accepted_event_rate"
                ],
                expected_overall[
                    "accepted_event_rate"
                ]
            )
            and numbers_match(
                actual_overall[
                    "overall_quality_score"
                ],
                expected_overall[
                    "overall_quality_score"
                ]
            )
            and actual_overall[
                "quality_label"
            ]
            == expected_overall[
                "quality_label"
            ]
        ),
        (
            "Expected overall quality score "
            "92.96 with GOOD rating."
        )
    )

    add_check(
        checks,
        "Quality issue counts",
        (
            quality_report[
                "issue_counts"
            ]
            == expectations[
                "issue_counts"
            ]
        ),
        (
            "Expected 1 duplicate, "
            "1 invalid IP, and "
            "2 missing required fields."
        )
    )

    expected_sources = (
        expectations[
            "sources"
        ]
    )

    actual_sources = source_lookup(
        quality_report
    )

    source_checks_passed = True

    for source_name, expected in (
        expected_sources.items()
    ):
        actual = actual_sources.get(
            source_name
        )

        if actual is None:
            source_checks_passed = False
            break

        if not (
            actual[
                "total_events"
            ]
            == expected[
                "total_events"
            ]
            and actual[
                "normalized_events"
            ]
            == expected[
                "normalized_events"
            ]
            and actual[
                "duplicate_events"
            ]
            == expected[
                "duplicate_events"
            ]
            and actual[
                "invalid_events"
            ]
            == expected[
                "invalid_events"
            ]
            and numbers_match(
                actual[
                    "source_quality_score"
                ],
                expected[
                    "source_quality_score"
                ]
            )
            and actual[
                "quality_label"
            ]
            == expected[
                "quality_label"
            ]
        ):
            source_checks_passed = False
            break

    add_check(
        checks,
        "Source-level quality metrics",
        source_checks_passed,
        (
            "All five telemetry sources must "
            "match expected counts, scores, "
            "and quality labels."
        )
    )

    normalized_events = (
        normalized_json[
            "events"
        ]
    )

    add_check(
        checks,
        "Normalized JSON output count",
        (
            normalized_json[
                "event_count"
            ]
            == 21
            and len(
                normalized_events
            )
            == 21
        ),
        (
            "Clean normalized JSON must "
            "contain exactly 21 events."
        )
    )

    add_check(
        checks,
        "Normalized CSV output count",
        (
            len(
                normalized_csv
            )
            == 21
        ),
        (
            "Normalized CSV must contain "
            "21 data rows."
        )
    )

    duplicate_events = (
        duplicate_report[
            "events"
        ]
    )

    expected_duplicate = (
        expectations[
            "expected_duplicate"
        ]
    )

    duplicate_valid = False

    if len(
        duplicate_events
    ) == 1:
        duplicate = (
            duplicate_events[0]
        )

        duplicate_event = (
            duplicate[
                "normalized_event"
            ]
        )

        duplicate_valid = (
            duplicate_event[
                "event_source"
            ]
            == expected_duplicate[
                "event_source"
            ]
            and duplicate_event[
                "raw_event_id"
            ]
            == expected_duplicate[
                "raw_event_id"
            ]
            and duplicate[
                "quality_score"
            ]
            == expected_duplicate[
                "quality_score"
            ]
            and issue_exists(
                duplicate,
                "duplicate_event",
                (
                    "event_source"
                    "+raw_event_id"
                )
            )
        )

    add_check(
        checks,
        "Duplicate event identification",
        duplicate_valid,
        (
            "WIN-1002 must be identified "
            "as the single duplicate event."
        )
    )

    win_1002_count = sum(
        1
        for event in normalized_events
        if event.get(
            "event_source"
        )
        == "Windows Security"
        and event.get(
            "raw_event_id"
        )
        == "WIN-1002"
    )

    add_check(
        checks,
        "Duplicate excluded from clean dataset",
        (
            win_1002_count
            == 1
        ),
        (
            "The original WIN-1002 should "
            "remain once while its duplicate "
            "copy is excluded."
        )
    )

    invalid_events = (
        invalid_report[
            "events"
        ]
    )

    add_check(
        checks,
        "Invalid event output count",
        (
            invalid_report[
                "invalid_event_count"
            ]
            == 3
            and len(
                invalid_events
            )
            == 3
        ),
        (
            "Invalid event report must "
            "contain exactly three records."
        )
    )

    entra_invalid = (
        find_invalid_record(
            invalid_events,
            "entra_signins.json",
            5
        )
    )

    add_check(
        checks,
        "Entra missing-host detection",
        (
            entra_invalid
            is not None
            and entra_invalid[
                "normalized_event"
            ].get(
                "raw_event_id"
            )
            == "ENTRA-2005"
            and entra_invalid[
                "quality_score"
            ]
            == 75
            and issue_exists(
                entra_invalid,
                "missing_required_field",
                "host"
            )
        ),
        (
            "ENTRA-2005 must fail because "
            "the required host is missing."
        )
    )

    firewall_bad_ip = (
        find_invalid_record(
            invalid_events,
            "firewall_events.json",
            4
        )
    )

    add_check(
        checks,
        "Firewall invalid-IP detection",
        (
            firewall_bad_ip
            is not None
            and firewall_bad_ip[
                "normalized_event"
            ].get(
                "raw_event_id"
            )
            == "FW-4004"
            and firewall_bad_ip[
                "quality_score"
            ]
            == 80
            and issue_exists(
                firewall_bad_ip,
                "invalid_ip_address",
                "source_ip"
            )
        ),
        (
            "FW-4004 must fail because "
            "999.10.20.15 is not a valid IP."
        )
    )

    firewall_missing_id = (
        find_invalid_record(
            invalid_events,
            "firewall_events.json",
            5
        )
    )

    add_check(
        checks,
        "Firewall missing-ID detection",
        (
            firewall_missing_id
            is not None
            and firewall_missing_id[
                "normalized_event"
            ].get(
                "raw_event_id"
            )
            is None
            and firewall_missing_id[
                "quality_score"
            ]
            == 75
            and issue_exists(
                firewall_missing_id,
                "missing_required_field",
                "raw_event_id"
            )
        ),
        (
            "The fifth firewall event must "
            "fail because its event ID "
            "is missing."
        )
    )

    entra_2002 = find_event(
        normalized_events,
        "ENTRA-2002"
    )

    add_check(
        checks,
        "Identity and hostname normalization",
        (
            entra_2002
            is not None
            and entra_2002[
                "user"
            ]
            == "finance.user"
            and entra_2002[
                "host"
            ]
            == "NFG-FIN-WS07"
        ),
        (
            "Entra UPN must normalize to "
            "finance.user and hostname must "
            "remain standardized uppercase."
        )
    )

    win_1001 = find_event(
        normalized_events,
        "WIN-1001"
    )

    add_check(
        checks,
        "Severity value normalization",
        (
            win_1001
            is not None
            and win_1001[
                "severity"
            ]
            == "Medium"
        ),
        (
            "Windows Warning severity must "
            "normalize to Medium."
        )
    )

    dns_5001 = find_event(
        normalized_events,
        "DNS-5001"
    )

    add_check(
        checks,
        "Optional DNS user field handling",
        (
            dns_5001
            is not None
            and dns_5001[
                "user"
            ]
            is None
        ),
        (
            "DNS event should remain valid "
            "even though the user field "
            "does not apply."
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
        len(
            checks
        )
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

        "checks_passed": (
            passed
        ),

        "checks_failed": (
            failed
        ),

        "checks": (
            checks
        )
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
    print("=" * 78)

    print(
        "SOC TELEMETRY PIPELINE "
        "VALIDATION"
    )

    print("=" * 78)

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

    print("=" * 78)

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

    print("=" * 78)

    print(
        f"Validation report: "
        f"{VALIDATION_OUTPUT}"
    )

    print("=" * 78)


if __name__ == "__main__":
    main()
