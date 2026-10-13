import csv
import json

from pathlib import Path

import yaml


BASE_DIR = Path(__file__).resolve().parent

DETECTIONS_DIR = (
    BASE_DIR
    / "detections"
)

TEST_FILE = (
    BASE_DIR
    / "tests"
    / "rule_tests.json"
)

STATIC_REPORT = (
    BASE_DIR
    / "output"
    / "rule_validation_results.json"
)

OUTPUT_DIR = (
    BASE_DIR
    / "output"
)

TEST_RESULTS_JSON = (
    OUTPUT_DIR
    / "rule_test_results.json"
)

TEST_RESULTS_CSV = (
    OUTPUT_DIR
    / "rule_test_summary.csv"
)


def load_json(file_path):
    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def load_rules():
    rules = {}

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

        if (
            rule_id
            and rule_id not in rules
        ):
            rules[
                rule_id
            ] = {
                "file_name": (
                    file_path.name
                ),
                "rule": rule
            }

    return rules


def get_static_pass_ids():
    report = load_json(
        STATIC_REPORT
    )

    return {
        result[
            "rule_id"
        ]
        for result in report[
            "results"
        ]
        if result[
            "result"
        ] in {
            "PASS",
            "REVIEW"
        }
        and result[
            "rule_id"
        ]
    }


def compare_value(
    actual,
    expected,
    modifier=None
):
    if actual is None:
        return False

    if isinstance(
        expected,
        list
    ):
        return any(
            compare_value(
                actual,
                item,
                modifier
            )
            for item in expected
        )

    if modifier is None:
        if isinstance(
            expected,
            str
        ):
            return (
                str(actual).lower()
                ==
                expected.lower()
            )

        return actual == expected

    actual_text = str(
        actual
    ).lower()

    expected_text = str(
        expected
    ).lower()

    if modifier == "contains":
        return (
            expected_text
            in actual_text
        )

    if modifier == "endswith":
        return actual_text.endswith(
            expected_text
        )

    return False


def evaluate_selection(
    selection,
    event
):
    if not isinstance(
        selection,
        dict
    ):
        return False

    for rule_field, expected in (
        selection.items()
    ):
        if "|" in rule_field:
            field_name, modifier = (
                rule_field.split(
                    "|",
                    1
                )
            )

        else:
            field_name = rule_field
            modifier = None

        actual = event.get(
            field_name
        )

        if not compare_value(
            actual,
            expected,
            modifier
        ):
            return False

    return True


def evaluate_condition(
    detection,
    event
):
    condition = detection.get(
        "condition"
    )

    if not isinstance(
        condition,
        str
    ):
        return False

    condition = condition.strip()

    if " and " in condition:
        selection_names = [
            item.strip()
            for item in condition.split(
                " and "
            )
        ]

        return all(
            evaluate_selection(
                detection.get(
                    name
                ),
                event
            )
            for name in selection_names
        )

    return evaluate_selection(
        detection.get(
            condition
        ),
        event
    )


def run_tests():
    rules = load_rules()

    static_pass_ids = (
        get_static_pass_ids()
    )

    test_cases = load_json(
        TEST_FILE
    )

    results = []

    for test_case in test_cases:
        rule_id = test_case[
            "rule_id"
        ]

        if rule_id not in (
            static_pass_ids
        ):
            results.append({
                "rule_id": rule_id,
                "file_name": None,
                "description": (
                    test_case[
                        "description"
                    ]
                ),
                "expected_match": (
                    test_case[
                        "expected_match"
                    ]
                ),
                "actual_match": None,
                "result": "SKIPPED",
                "details": (
                    "Rule did not pass "
                    "static validation."
                )
            })

            continue

        rule_record = rules.get(
            rule_id
        )

        if rule_record is None:
            results.append({
                "rule_id": rule_id,
                "file_name": None,
                "description": (
                    test_case[
                        "description"
                    ]
                ),
                "expected_match": (
                    test_case[
                        "expected_match"
                    ]
                ),
                "actual_match": None,
                "result": "FAIL",
                "details": (
                    "Rule could not be "
                    "loaded for testing."
                )
            })

            continue

        detection = (
            rule_record[
                "rule"
            ].get(
                "detection",
                {}
            )
        )

        actual_match = (
            evaluate_condition(
                detection,
                test_case[
                    "event"
                ]
            )
        )

        expected_match = (
            test_case[
                "expected_match"
            ]
        )

        passed = (
            actual_match
            == expected_match
        )

        results.append({
            "rule_id": rule_id,
            "file_name": (
                rule_record[
                    "file_name"
                ]
            ),
            "description": (
                test_case[
                    "description"
                ]
            ),
            "expected_match": (
                expected_match
            ),
            "actual_match": (
                actual_match
            ),
            "result": (
                "PASS"
                if passed
                else "FAIL"
            ),
            "details": (
                "Expected behavior matched."
                if passed
                else (
                    "Actual detection behavior "
                    "did not match the expected "
                    "test result."
                )
            )
        })

    return results


def export_results(
    results
):
    pass_count = sum(
        1
        for result in results
        if result[
            "result"
        ]
        == "PASS"
    )

    fail_count = sum(
        1
        for result in results
        if result[
            "result"
        ]
        == "FAIL"
    )

    skipped_count = sum(
        1
        for result in results
        if result[
            "result"
        ]
        == "SKIPPED"
    )

    report = {
        "tests_run": len(
            results
        ),
        "tests_passed": pass_count,
        "tests_failed": fail_count,
        "tests_skipped": skipped_count,
        "quality_gate": (
            "FAILED"
            if fail_count > 0
            else "PASSED"
        ),
        "results": results
    }

    with open(
        TEST_RESULTS_JSON,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )

    fieldnames = [
        "rule_id",
        "file_name",
        "description",
        "expected_match",
        "actual_match",
        "result",
        "details"
    ]

    with open(
        TEST_RESULTS_CSV,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for result in results:
            writer.writerow(
                result
            )

    return report


def print_report(
    report
):
    print()
    print("=" * 82)
    print(
        "DETECTION-AS-CODE "
        "BEHAVIORAL TESTING"
    )
    print("=" * 82)

    print(
        f"Tests run:      "
        f"{report['tests_run']}"
    )

    print(
        f"PASS:           "
        f"{report['tests_passed']}"
    )

    print(
        f"FAIL:           "
        f"{report['tests_failed']}"
    )

    print(
        f"SKIPPED:        "
        f"{report['tests_skipped']}"
    )

    print(
        f"Quality gate:   "
        f"{report['quality_gate']}"
    )

    print("=" * 82)

    for result in report[
        "results"
    ]:
        print(
            f"{result['result']:<8} "
            f"{result['file_name'] or '(no file)'}"
        )

        print(
            f"         Expected: "
            f"{result['expected_match']}"
        )

        print(
            f"         Actual:   "
            f"{result['actual_match']}"
        )

    print("=" * 82)

    print(
        f"JSON report: "
        f"{TEST_RESULTS_JSON}"
    )

    print(
        f"CSV summary: "
        f"{TEST_RESULTS_CSV}"
    )

    print("=" * 82)


def main():
    OUTPUT_DIR.mkdir(
        exist_ok=True
    )

    results = run_tests()

    report = export_results(
        results
    )

    print_report(
        report
    )


if __name__ == "__main__":
    main()
