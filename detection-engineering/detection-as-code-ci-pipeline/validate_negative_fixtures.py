import csv
import json

from pathlib import Path

import yaml

from validate_detections import (
    add_finding,
    determine_rule_status,
    load_json,
    parse_yaml_rule,
    validate_attack_tags,
    validate_date,
    validate_detection,
    validate_documentation,
    validate_level,
    validate_logsource,
    validate_required_fields,
    validate_status,
    validate_uuid
)

from run_rule_tests import (
    evaluate_condition
)


BASE_DIR = Path(__file__).resolve().parent

DETECTIONS_DIR = (
    BASE_DIR
    / "detections"
)

FIXTURE_DIR = (
    BASE_DIR
    / "tests"
    / "fixtures"
    / "invalid-rules"
)

POLICY_FILE = (
    BASE_DIR
    / "config"
    / "validation_policy.json"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "invalid_fixture_expectations.json"
)

OUTPUT_DIR = (
    BASE_DIR
    / "output"
)

RESULTS_JSON = (
    OUTPUT_DIR
    / "negative_fixture_results.json"
)

RESULTS_CSV = (
    OUTPUT_DIR
    / "negative_fixture_summary.csv"
)


def load_deployed_rule_ids():
    deployed_ids = {}

    for file_path in sorted(
        DETECTIONS_DIR.glob("*.yml")
    ):
        try:
            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as file:
                rule = yaml.safe_load(
                    file
                )

        except yaml.YAMLError:
            continue

        if not isinstance(
            rule,
            dict
        ):
            continue

        rule_id = rule.get(
            "id"
        )

        if rule_id:
            deployed_ids[
                rule_id
            ] = file_path.name

    return deployed_ids


def validate_fixture_static(
    file_path,
    policy,
    deployed_ids
):
    rule, findings = parse_yaml_rule(
        file_path,
        policy
    )

    if rule is None:
        return {
            "rule": None,
            "result": "FAIL",
            "findings": findings
        }

    validate_required_fields(
        rule,
        findings,
        policy
    )

    validate_uuid(
        rule,
        findings,
        policy
    )

    validate_status(
        rule,
        findings,
        policy
    )

    validate_level(
        rule,
        findings,
        policy
    )

    validate_date(
        rule,
        findings,
        policy
    )

    validate_attack_tags(
        rule,
        findings,
        policy
    )

    validate_logsource(
        rule,
        findings,
        policy
    )

    validate_detection(
        rule,
        findings,
        policy
    )

    validate_documentation(
        rule,
        findings,
        policy
    )

    rule_id = rule.get(
        "id"
    )

    if (
        rule_id
        and rule_id
        in deployed_ids
    ):
        add_finding(
            findings,
            "duplicate_rule_id",
            "id",
            (
                f"Fixture rule ID "
                f"'{rule_id}' conflicts "
                f"with deployed rule "
                f"{deployed_ids[rule_id]}."
            ),
            policy
        )

    return {
        "rule": rule,
        "result": (
            determine_rule_status(
                findings
            )
        ),
        "findings": findings
    }


def compare_static_result(
    actual_result,
    findings,
    expectation
):
    actual_findings = sorted({
        finding[
            "finding_type"
        ]
        for finding in findings
    })

    expected_findings = sorted(
        expectation[
            "expected_findings"
        ]
    )

    return (
        actual_result
        == expectation[
            "expected_static_result"
        ]
        and actual_findings
        == expected_findings
    )


def evaluate_behavioral_fixture(
    rule,
    behavioral_test
):
    if rule is None:
        return {
            "tested": False,
            "expected_match": None,
            "actual_match": None,
            "passed": False
        }

    detection = rule.get(
        "detection",
        {}
    )

    actual_match = evaluate_condition(
        detection,
        behavioral_test[
            "event"
        ]
    )

    expected_match = behavioral_test[
        "expected_match"
    ]

    expected_actual = behavioral_test[
        "expected_actual_match"
    ]

    passed = (
        actual_match
        == expected_actual
        and actual_match
        != expected_match
    )

    return {
        "tested": True,
        "expected_match": (
            expected_match
        ),
        "actual_match": (
            actual_match
        ),
        "passed": passed
    }


def validate_fixtures(
    policy,
    expectations
):
    deployed_ids = (
        load_deployed_rule_ids()
    )

    results = []

    for file_name, expectation in (
        expectations.items()
    ):
        file_path = (
            FIXTURE_DIR
            / file_name
        )

        if not file_path.exists():
            results.append({
                "file_name": file_name,
                "fixture_result": "FAIL",
                "static_expected": (
                    expectation[
                        "expected_static_result"
                    ]
                ),
                "static_actual": (
                    "MISSING"
                ),
                "expected_findings": (
                    expectation[
                        "expected_findings"
                    ]
                ),
                "actual_findings": [],
                "behavioral_tested": False,
                "expected_match": None,
                "actual_match": None,
                "details": (
                    "Expected fixture file "
                    "was not found."
                )
            })

            continue

        static_result = (
            validate_fixture_static(
                file_path,
                policy,
                deployed_ids
            )
        )

        findings = static_result[
            "findings"
        ]

        static_passed = (
            compare_static_result(
                static_result[
                    "result"
                ],
                findings,
                expectation
            )
        )

        behavioral = {
            "tested": False,
            "expected_match": None,
            "actual_match": None,
            "passed": True
        }

        if "behavioral_test" in expectation:
            behavioral = (
                evaluate_behavioral_fixture(
                    static_result[
                        "rule"
                    ],
                    expectation[
                        "behavioral_test"
                    ]
                )
            )

        fixture_passed = (
            static_passed
            and behavioral[
                "passed"
            ]
        )

        actual_findings = sorted({
            finding[
                "finding_type"
            ]
            for finding in findings
        })

        results.append({
            "file_name": file_name,
            "fixture_result": (
                "PASS"
                if fixture_passed
                else "FAIL"
            ),
            "static_expected": (
                expectation[
                    "expected_static_result"
                ]
            ),
            "static_actual": (
                static_result[
                    "result"
                ]
            ),
            "expected_findings": (
                expectation[
                    "expected_findings"
                ]
            ),
            "actual_findings": (
                actual_findings
            ),
            "behavioral_tested": (
                behavioral[
                    "tested"
                ]
            ),
            "expected_match": (
                behavioral[
                    "expected_match"
                ]
            ),
            "actual_match": (
                behavioral[
                    "actual_match"
                ]
            ),
            "details": (
                "Fixture produced the "
                "expected validation behavior."
                if fixture_passed
                else (
                    "Fixture behavior did not "
                    "match expected ground truth."
                )
            )
        })

    return results


def build_report(
    results
):
    passed = sum(
        1
        for result in results
        if result[
            "fixture_result"
        ]
        == "PASS"
    )

    failed = (
        len(results)
        - passed
    )

    return {
        "fixtures_checked": len(
            results
        ),
        "fixtures_passed": passed,
        "fixtures_failed": failed,
        "quality_gate": (
            "PASSED"
            if failed == 0
            else "FAILED"
        ),
        "results": results
    }


def export_results(
    report
):
    with open(
        RESULTS_JSON,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )

    fieldnames = [
        "file_name",
        "fixture_result",
        "static_expected",
        "static_actual",
        "expected_findings",
        "actual_findings",
        "behavioral_tested",
        "expected_match",
        "actual_match",
        "details"
    ]

    with open(
        RESULTS_CSV,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for result in report[
            "results"
        ]:
            row = result.copy()

            row[
                "expected_findings"
            ] = "; ".join(
                result[
                    "expected_findings"
                ]
            )

            row[
                "actual_findings"
            ] = "; ".join(
                result[
                    "actual_findings"
                ]
            )

            writer.writerow(
                row
            )


def print_report(
    report
):
    print()
    print("=" * 82)

    print(
        "DETECTION-AS-CODE NEGATIVE "
        "FIXTURE VALIDATION"
    )

    print("=" * 82)

    print(
        f"Fixtures checked: "
        f"{report['fixtures_checked']}"
    )

    print(
        f"PASS:             "
        f"{report['fixtures_passed']}"
    )

    print(
        f"FAIL:             "
        f"{report['fixtures_failed']}"
    )

    print(
        f"Quality gate:     "
        f"{report['quality_gate']}"
    )

    print("=" * 82)

    for result in report[
        "results"
    ]:
        print(
            f"{result['fixture_result']:<7} "
            f"{result['file_name']}"
        )

        print(
            f"        Static expected: "
            f"{result['static_expected']}"
        )

        print(
            f"        Static actual:   "
            f"{result['static_actual']}"
        )

        if result[
            "behavioral_tested"
        ]:
            print(
                f"        Match expected:  "
                f"{result['expected_match']}"
            )

            print(
                f"        Match actual:    "
                f"{result['actual_match']}"
            )

    print("=" * 82)

    print(
        f"JSON report: "
        f"{RESULTS_JSON}"
    )

    print(
        f"CSV summary: "
        f"{RESULTS_CSV}"
    )

    print("=" * 82)


def main():
    OUTPUT_DIR.mkdir(
        exist_ok=True
    )

    policy = load_json(
        POLICY_FILE
    )

    expectations = load_json(
        EXPECTATIONS_FILE
    )

    results = validate_fixtures(
        policy,
        expectations
    )

    report = build_report(
        results
    )

    export_results(
        report
    )

    print_report(
        report
    )


if __name__ == "__main__":
    main()
