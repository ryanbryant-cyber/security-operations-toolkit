import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

AUDIT_RESULTS_FILE = (
    BASE_DIR
    / "output"
    / "baseline_audit_results.json"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "audit_expectations.json"
)

VALIDATION_OUTPUT = (
    BASE_DIR
    / "output"
    / "baseline_audit_validation_results.json"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def find_control(results, control_id):
    for result in results:
        if result["control_id"] == control_id:
            return result

    return None


def validate_summary(audit_report, expectations):
    actual = audit_report["summary"]
    expected = expectations["expected_summary"]

    passed = (
        actual["total_controls"] == expected["total_controls"]
        and actual["pass"] == expected["pass"]
        and actual["fail"] == expected["fail"]
        and actual["review"] == expected["review"]
        and actual["not_applicable"] == expected["not_applicable"]
    )

    return {
        "check": "Audit summary",
        "expected": expected,
        "actual": actual,
        "passed": passed
    }


def validate_controls(audit_report, expectations):
    results = audit_report["results"]
    checks = []

    for expected in expectations["expected_controls"]:
        control = find_control(
            results,
            expected["control_id"]
        )

        if control is None:
            checks.append({
                "control_id": expected["control_id"],
                "passed": False,
                "reason": "Control missing from audit results"
            })
            continue

        status_match = (
            control["status"]
            == expected["expected_status"]
        )

        severity_match = (
            control["severity"]
            == expected["expected_severity"]
        )

        checks.append({
            "control_id": expected["control_id"],
            "name": control["name"],
            "expected_status": expected["expected_status"],
            "actual_status": control["status"],
            "expected_severity": expected["expected_severity"],
            "actual_severity": control["severity"],
            "passed": status_match and severity_match
        })

    return checks


def validate_behavior(audit_report):
    results = audit_report["results"]

    rdp_review = find_control(
        results,
        "BASE-008"
    )

    nla = find_control(
        results,
        "BASE-009"
    )

    smb = find_control(
        results,
        "BASE-010"
    )

    firewall_ids = [
        "BASE-005",
        "BASE-006",
        "BASE-007"
    ]

    firewall_controls = [
        find_control(results, control_id)
        for control_id in firewall_ids
    ]

    checks = []

    checks.append({
        "check": (
            "Enabled Remote Desktop requires analyst review "
            "rather than automatic failure"
        ),
        "passed": (
            rdp_review is not None
            and rdp_review["status"] == "REVIEW"
        )
    })

    checks.append({
        "check": (
            "Remote Desktop without Network Level "
            "Authentication produces FAIL"
        ),
        "passed": (
            nla is not None
            and nla["status"] == "FAIL"
        )
    })

    checks.append({
        "check": (
            "All Windows Firewall profiles pass baseline"
        ),
        "passed": (
            all(
                control is not None
                and control["status"] == "PASS"
                for control in firewall_controls
            )
        )
    })

    checks.append({
        "check": (
            "Disabled SMBv1 satisfies secure baseline"
        ),
        "passed": (
            smb is not None
            and smb["status"] == "PASS"
        )
    })

    return checks


def main():
    audit_report = load_json(
        AUDIT_RESULTS_FILE
    )

    expectations = load_json(
        EXPECTATIONS_FILE
    )

    summary_check = validate_summary(
        audit_report,
        expectations
    )

    control_checks = validate_controls(
        audit_report,
        expectations
    )

    behavior_checks = validate_behavior(
        audit_report
    )

    all_checks = (
        [summary_check]
        + control_checks
        + behavior_checks
    )

    passed = sum(
        1
        for check in all_checks
        if check["passed"]
    )

    failed = len(all_checks) - passed

    validation_report = {
        "validation_status": (
            "PASS"
            if failed == 0
            else "REVIEW"
        ),
        "checks_run": len(all_checks),
        "checks_passed": passed,
        "checks_failed": failed,
        "summary_check": summary_check,
        "control_checks": control_checks,
        "behavioral_checks": behavior_checks
    }

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
    print("=" * 86)
    print("SECURE BASELINE AUDIT VALIDATION")
    print("=" * 86)

    for check in control_checks:
        status = (
            "PASS"
            if check["passed"]
            else "REVIEW"
        )

        print(
            f"{status:<7} "
            f"{check['control_id']} | "
            f"{check.get('actual_status', 'N/A'):<14} | "
            f"{check.get('name', 'Missing Control')}"
        )

    print("-" * 86)

    for check in behavior_checks:
        status = (
            "PASS"
            if check["passed"]
            else "REVIEW"
        )

        print(
            f"{status:<7} "
            f"{check['check']}"
        )

    print("=" * 86)
    print(
        f"Summary check:  "
        f"{'PASS' if summary_check['passed'] else 'REVIEW'}"
    )
    print(
        f"Checks run:     "
        f"{len(all_checks)}"
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
        f"{validation_report['validation_status']}"
    )
    print("=" * 86)

    print(
        f"Validation report: "
        f"{VALIDATION_OUTPUT}"
    )


if __name__ == "__main__":
    main()
