import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

RESULTS_FILE = (
    BASE_DIR
    / "output"
    / "attack_coverage_results.json"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "coverage_expectations.json"
)

VALIDATION_OUTPUT = (
    BASE_DIR
    / "output"
    / "attack_coverage_validation_results.json"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def find_technique(report, technique_id):
    for item in report["technique_coverage"]:
        if item["technique_id"] == technique_id:
            return item

    return None


def find_redundancy(report, technique_id):
    for item in report["redundancy_review"]:
        if item["technique_id"] == technique_id:
            return item

    return None


def validate_summary(report, expectations):
    actual = report["summary"]
    expected = expectations["expected_summary"]

    passed = all(
        actual[key] == value
        for key, value in expected.items()
    )

    return {
        "check": "Coverage analysis summary",
        "passed": passed,
        "expected": expected,
        "actual": actual
    }


def validate_strong_techniques(report, expectations):
    checks = []

    for expected in expectations["strong_techniques"]:
        technique = find_technique(
            report,
            expected["technique_id"]
        )

        if technique is None:
            checks.append({
                "check": expected["technique_id"],
                "passed": False
            })
            continue

        score_match = (
            abs(
                technique["coverage_score"]
                - expected["coverage_score"]
            )
            < 0.01
        )

        passed = (
            technique["coverage_rating"]
            == "STRONG"
            and score_match
            and technique["detection_count"]
            == expected["detection_count"]
        )

        checks.append({
            "check": (
                f"{expected['technique_id']} "
                f"{expected['technique']} STRONG coverage"
            ),
            "passed": passed
        })

    return checks


def validate_gap_set(report, expectations):
    expected_ids = {
        item["technique_id"]
        for item in expectations["coverage_gaps"]
    }

    actual_ids = {
        item["technique_id"]
        for item in report["technique_coverage"]
        if item["coverage_rating"] == "GAP"
    }

    return {
        "check": "Expected ATT&CK coverage gaps",
        "passed": actual_ids == expected_ids
    }


def validate_gap_priorities(report, expectations):
    passed = True

    for expected in expectations["coverage_gaps"]:
        technique = find_technique(
            report,
            expected["technique_id"]
        )

        if (
            technique is None
            or technique["coverage_rating"] != "GAP"
            or technique["engineering_priority"]
            != expected["engineering_priority"]
        ):
            passed = False
            break

    return {
        "check": (
            "Coverage gaps receive correct "
            "engineering priorities"
        ),
        "passed": passed
    }


def validate_cloud_accounts(report, expectations):
    expected = expectations[
        "low_coverage_review"
    ]

    technique = find_technique(
        report,
        expected["technique_id"]
    )

    if technique is None:
        return {
            "check": "Cloud Accounts review coverage",
            "passed": False
        }

    score_match = (
        abs(
            technique["coverage_score"]
            - expected["coverage_score"]
        )
        < 0.01
    )

    passed = (
        score_match
        and technique["coverage_rating"]
        == expected["coverage_rating"]
        and technique["engineering_priority"]
        == expected["engineering_priority"]
        and technique["detection_count"]
        == expected["detection_count"]
        and technique["validated_detection_count"]
        == expected["validated_detection_count"]
        and technique["needs_review_count"]
        == expected["needs_review_count"]
        and technique["experimental_count"]
        == expected["experimental_count"]
    )

    return {
        "check": (
            "Experimental Cloud Accounts detection "
            "does not create false strong coverage"
        ),
        "passed": passed
    }


def validate_redundancy(report, expectations):
    checks = []

    for expected in expectations["redundancy_reviews"]:
        actual = find_redundancy(
            report,
            expected["technique_id"]
        )

        passed = (
            actual is not None
            and actual["detection_count"]
            == expected["detection_count"]
            and actual["classification"]
            == expected["classification"]
        )

        checks.append({
            "check": (
                f"{expected['technique_id']} "
                "redundancy review"
            ),
            "passed": passed
        })

    return checks


def validate_web_protocols_no_redundancy(report):
    technique = find_technique(
        report,
        "T1071.001"
    )

    redundancy = find_redundancy(
        report,
        "T1071.001"
    )

    passed = (
        technique is not None
        and technique["coverage_rating"] == "STRONG"
        and technique["detection_count"] == 2
        and redundancy is None
    )

    return {
        "check": (
            "Strong two-detection coverage does not "
            "incorrectly trigger redundancy threshold"
        ),
        "passed": passed
    }


def validate_multi_tactic_mapping(report):
    service = find_technique(
        report,
        "T1543.003"
    )

    account = find_technique(
        report,
        "T1098"
    )

    expected = {
        "Persistence",
        "Privilege Escalation"
    }

    passed = (
        service is not None
        and account is not None
        and set(service["tactics"]) == expected
        and set(account["tactics"]) == expected
    )

    return {
        "check": (
            "Multi-tactic ATT&CK mappings "
            "are split correctly"
        ),
        "passed": passed
    }


def validate_guardrails(report):
    text = " ".join(
        report["analyst_guardrails"]
    ).lower()

    required = [
        "detection count alone",
        "unvalidated or experimental rule",
        "independent coverage",
        "mitre att&ck mapping",
        "fully covered solely because one rule exists",
        "false-positive behavior",
        "engineering prioritization aid"
    ]

    passed = all(
        phrase in text
        for phrase in required
    )

    return {
        "check": (
            "Detection coverage analyst "
            "guardrails are preserved"
        ),
        "passed": passed
    }


def main():
    report = load_json(
        RESULTS_FILE
    )

    expectations = load_json(
        EXPECTATIONS_FILE
    )

    checks = [
        validate_summary(
            report,
            expectations
        )
    ]

    checks.extend(
        validate_strong_techniques(
            report,
            expectations
        )
    )

    checks.append(
        validate_gap_set(
            report,
            expectations
        )
    )

    checks.append(
        validate_gap_priorities(
            report,
            expectations
        )
    )

    checks.append(
        validate_cloud_accounts(
            report,
            expectations
        )
    )

    checks.extend(
        validate_redundancy(
            report,
            expectations
        )
    )

    checks.append(
        validate_web_protocols_no_redundancy(
            report
        )
    )

    checks.append(
        validate_multi_tactic_mapping(
            report
        )
    )

    checks.append(
        validate_guardrails(
            report
        )
    )

    passed = sum(
        1
        for check in checks
        if check["passed"]
    )

    failed = len(checks) - passed

    validation_report = {
        "validation_status": (
            "PASS"
            if failed == 0
            else "REVIEW"
        ),
        "checks_run": len(checks),
        "checks_passed": passed,
        "checks_failed": failed,
        "checks": checks
    }

    VALIDATION_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        VALIDATION_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            validation_report,
            file,
            indent=2
        )

    print()
    print("=" * 96)
    print(
        "MITRE ATT&CK DETECTION COVERAGE "
        "VALIDATION"
    )
    print("=" * 96)

    for check in checks:
        status = (
            "PASS"
            if check["passed"]
            else "REVIEW"
        )

        print(
            f"{status:<7} "
            f"{check['check']}"
        )

    print("=" * 96)

    print(
        f"Checks run:     {len(checks)}"
    )

    print(
        f"Checks passed:  {passed}"
    )

    print(
        f"Checks failed:  {failed}"
    )

    print(
        f"Overall:        "
        f"{validation_report['validation_status']}"
    )

    print("=" * 96)

    print(
        f"Validation report: "
        f"{VALIDATION_OUTPUT}"
    )


if __name__ == "__main__":
    main()
