import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

ANALYSIS_FILE = (
    BASE_DIR
    / "output"
    / "phishing_analysis_results.json"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "phishing_expectations.json"
)

VALIDATION_OUTPUT = (
    BASE_DIR
    / "output"
    / "phishing_validation_results.json"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def find_case(results, case_id):
    for result in results:
        if result["case_id"] == case_id:
            return result

    return None


def validate_summary(report, expectations):
    actual = report["summary"]
    expected = expectations["expected_summary"]

    passed = (
        actual["total_cases"] == expected["total_cases"]
        and actual["malicious"] == expected["malicious"]
        and actual["suspicious"] == expected["suspicious"]
        and actual["benign"] == expected["benign"]
    )

    return {
        "check": "Case summary",
        "expected": expected,
        "actual": actual,
        "passed": passed
    }


def validate_cases(report, expectations):
    results = report["results"]
    checks = []

    for expected in expectations["expected_cases"]:
        result = find_case(
            results,
            expected["case_id"]
        )

        if result is None:
            checks.append({
                "case_id": expected["case_id"],
                "passed": False,
                "reason": "Case missing from analysis results"
            })
            continue

        actual_indicator_count = len(
            result["risk_indicators"]
        )

        actual_ioc_count = len(
            result["extracted_iocs"]
        )

        score_match = (
            result["risk_score"]
            == expected["risk_score"]
        )

        disposition_match = (
            result["disposition"]
            == expected["disposition"]
        )

        indicator_match = (
            actual_indicator_count
            == expected["indicator_count"]
        )

        ioc_match = (
            actual_ioc_count
            == expected["ioc_count"]
        )

        checks.append({
            "case_id": expected["case_id"],
            "expected_score": expected["risk_score"],
            "actual_score": result["risk_score"],
            "expected_disposition": expected["disposition"],
            "actual_disposition": result["disposition"],
            "expected_indicator_count": expected["indicator_count"],
            "actual_indicator_count": actual_indicator_count,
            "expected_ioc_count": expected["ioc_count"],
            "actual_ioc_count": actual_ioc_count,
            "passed": (
                score_match
                and disposition_match
                and indicator_match
                and ioc_match
            )
        })

    return checks


def has_indicator(case, indicator_name):
    return any(
        item["indicator"] == indicator_name
        for item in case["risk_indicators"]
    )


def validate_behavior(report):
    results = report["results"]

    malicious = find_case(
        results,
        "EMAIL-001"
    )

    suspicious = find_case(
        results,
        "EMAIL-002"
    )

    benign = find_case(
        results,
        "EMAIL-003"
    )

    checks = []

    checks.append({
        "check": (
            "Authentication failures and impersonation "
            "produce MALICIOUS disposition"
        ),
        "passed": (
            malicious is not None
            and malicious["disposition"] == "MALICIOUS"
            and malicious["spf"] == "fail"
            and malicious["dkim"] == "fail"
            and malicious["dmarc"] == "fail"
            and has_indicator(
                malicious,
                "Display-name impersonation"
            )
        )
    })

    checks.append({
        "check": (
            "Credential request is detected in "
            "malicious phishing case"
        ),
        "passed": (
            malicious is not None
            and has_indicator(
                malicious,
                "Credential request"
            )
        )
    })

    checks.append({
        "check": (
            "External HTML form is detected in "
            "malicious phishing case"
        ),
        "passed": (
            malicious is not None
            and has_indicator(
                malicious,
                "HTML attachment"
            )
            and has_indicator(
                malicious,
                "Attachment contains external form"
            )
        )
    })

    checks.append({
        "check": (
            "Authenticated but contextually risky "
            "invoice remains SUSPICIOUS"
        ),
        "passed": (
            suspicious is not None
            and suspicious["spf"] == "pass"
            and suspicious["dkim"] == "pass"
            and suspicious["disposition"] == "SUSPICIOUS"
        )
    })

    checks.append({
        "check": (
            "Clean internal email receives "
            "BENIGN disposition"
        ),
        "passed": (
            benign is not None
            and benign["spf"] == "pass"
            and benign["dkim"] == "pass"
            and benign["dmarc"] == "pass"
            and benign["risk_score"] == 0
            and benign["disposition"] == "BENIGN"
        )
    })

    checks.append({
        "check": (
            "Benign email can contain extracted "
            "investigation artifacts without risk indicators"
        ),
        "passed": (
            benign is not None
            and len(benign["extracted_iocs"]) == 6
            and len(benign["risk_indicators"]) == 0
        )
    })

    return checks


def main():
    report = load_json(
        ANALYSIS_FILE
    )

    expectations = load_json(
        EXPECTATIONS_FILE
    )

    summary_check = validate_summary(
        report,
        expectations
    )

    case_checks = validate_cases(
        report,
        expectations
    )

    behavior_checks = validate_behavior(
        report
    )

    all_checks = (
        [summary_check]
        + case_checks
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
        "case_checks": case_checks,
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
    print("PHISHING EMAIL INVESTIGATION VALIDATION")
    print("=" * 86)

    for check in case_checks:
        status = (
            "PASS"
            if check["passed"]
            else "REVIEW"
        )

        print(
            f"{status:<7} "
            f"{check['case_id']} | "
            f"Score {check.get('actual_score', 'N/A')} | "
            f"{check.get('actual_disposition', 'N/A'):<10} | "
            f"Indicators {check.get('actual_indicator_count', 'N/A')} | "
            f"IOCs {check.get('actual_ioc_count', 'N/A')}"
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
