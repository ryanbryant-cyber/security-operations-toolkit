import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

ALERT_FILE = (
    BASE_DIR
    / "output"
    / "normalized_enriched_alerts.json"
)

CASE_FILE = (
    BASE_DIR
    / "output"
    / "analyst_incident_cases.json"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "incident_expectations.json"
)

VALIDATION_OUTPUT = (
    BASE_DIR
    / "output"
    / "incident_validation_results.json"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def find_case(cases, incident_id):
    for case in cases:
        if case["incident_id"] == incident_id:
            return case

    return None


def validate_alert_processing(alert_report, expectations):
    actual = alert_report["summary"]
    expected = expectations["alert_processing"]

    passed = (
        actual["raw_alert_count"]
        == expected["raw_alert_count"]
        and actual["normalized_alert_count"]
        == expected["normalized_alert_count"]
        and actual["post_deduplication_count"]
        == expected["post_deduplication_count"]
    )

    return {
        "check": "Alert normalization and deduplication",
        "passed": passed,
        "expected": expected,
        "actual": actual
    }


def validate_incident_summary(case_report, expectations):
    actual = case_report["summary"]
    expected = expectations["incident_summary"]

    passed = (
        actual["incident_count"]
        == expected["incident_count"]
        and actual["critical"]
        == expected["critical"]
        and actual["high"]
        == expected["high"]
        and actual["moderate"]
        == expected["moderate"]
        and actual["low"]
        == expected["low"]
    )

    return {
        "check": "Incident summary",
        "passed": passed,
        "expected": expected,
        "actual": actual
    }


def validate_cases(case_report, expectations):
    cases = case_report["cases"]
    checks = []

    for expected in expectations["expected_cases"]:
        case = find_case(
            cases,
            expected["incident_id"]
        )

        if case is None:
            checks.append({
                "check": expected["incident_id"],
                "passed": False,
                "reason": "Expected incident was missing."
            })
            continue

        passed = (
            case["priority"]
            == expected["priority"]
            and case["priority_score"]
            == expected["priority_score"]
            and case["affected_user"]
            == expected["affected_user"]
            and case["affected_asset"]
            == expected["affected_asset"]
            and case["source_alert_count"]
            == expected["source_alert_count"]
            and case["correlated_alert_count"]
            == expected["correlated_alert_count"]
            and case["routing"]
            == expected["routing"]
            and case["playbook"]["name"]
            == expected["playbook"]
        )

        checks.append({
            "check": expected["incident_id"],
            "priority": case["priority"],
            "priority_score": case["priority_score"],
            "routing": case["routing"],
            "playbook": case["playbook"]["name"],
            "passed": passed
        })

    return checks


def validate_finance_deduplication(
    alert_report,
    case_report,
    expectations
):
    alerts = alert_report["alerts"]

    deduplicated = next(
        (
            alert
            for alert in alerts
            if set(alert["source_alert_ids"])
            == {"ALERT-003", "ALERT-004"}
        ),
        None
    )

    finance = find_case(
        case_report["cases"],
        "INC-001"
    )

    expected_ids = set(
        expectations["finance_source_alert_ids"]
    )

    passed = (
        deduplicated is not None
        and deduplicated["deduplicated"] is True
        and deduplicated["event_type"]
        == "Suspicious Encoded PowerShell Execution"
        and finance is not None
        and set(finance["source_alert_ids"])
        == expected_ids
        and finance["source_alert_count"] == 8
        and finance["correlated_alert_count"] == 7
    )

    return {
        "check": (
            "PowerShell duplicates collapse while "
            "preserving original evidence"
        ),
        "passed": passed
    }


def validate_finance_enrichment(case_report):
    finance = find_case(
        case_report["cases"],
        "INC-001"
    )

    if finance is None:
        return {
            "check": "Finance enrichment",
            "passed": False
        }

    user = finance["business_context"]["user"]
    asset = finance["business_context"]["asset"]

    indicators = {
        item["indicator"]: item
        for item in finance["ioc_context"]
    }

    threat = indicators.get(
        "203.0.113.88"
    )

    passed = (
        user is not None
        and user["department"] == "Finance"
        and user["high_value_identity"] is True
        and asset is not None
        and asset["criticality"] == "High"
        and asset["data_sensitivity"] == "High"
        and threat is not None
        and threat["known_malicious"] is True
    )

    return {
        "check": (
            "Finance case contains business and "
            "threat enrichment"
        ),
        "passed": passed
    }


def validate_cross_source_correlation(case_report):
    finance = find_case(
        case_report["cases"],
        "INC-001"
    )

    required_categories = {
        "Authentication",
        "Execution",
        "Network",
        "Threat Intelligence",
        "Privilege",
        "Email"
    }

    required_products = {
        "Identity Monitor",
        "Endpoint Detection",
        "Network Monitor",
        "Threat Intelligence",
        "Privilege Monitor",
        "Email Security"
    }

    passed = (
        finance is not None
        and required_categories.issubset(
            set(finance["categories"])
        )
        and required_products.issubset(
            set(finance["security_products"])
        )
    )

    return {
        "check": (
            "Finance incident correlates multiple "
            "security categories and products"
        ),
        "passed": passed
    }


def validate_response_separation(case_report):
    finance = find_case(
        case_report["cases"],
        "INC-001"
    )

    if finance is None:
        return {
            "check": "Response action separation",
            "passed": False
        }

    safe_actions = finance[
        "automated_safe_actions"
    ]

    approval_actions = finance[
        "analyst_approval_required"
    ]

    passed = (
        "Create incident record"
        in safe_actions
        and "Enrich IOC context"
        in safe_actions
        and "Revoke active user sessions"
        in approval_actions
        and "Isolate endpoint"
        in approval_actions
        and "Disable user account"
        in approval_actions
    )

    return {
        "check": (
            "Safe automation and analyst-approved "
            "containment remain separated"
        ),
        "passed": passed
    }


def validate_trusted_admin_tuning(case_report):
    admin = find_case(
        case_report["cases"],
        "INC-004"
    )

    if admin is None:
        return {
            "check": "Trusted admin traffic tuning",
            "passed": False
        }

    trusted = any(
        item["indicator"]
        == "198.51.100.15"
        and item["reputation"]
        == "Trusted"
        and item["known_malicious"] is False
        for item in admin["ioc_context"]
    )

    reduction = any(
        factor["factor"]
        == "Trusted IOC reduction"
        and factor["points"] == -30
        for factor in admin[
            "priority_factors"
        ]
    )

    passed = (
        admin["priority"] == "LOW"
        and admin["priority_score"] == 29
        and admin["playbook"]["name"]
        == "Trusted Administrative Traffic"
        and trusted
        and reduction
    )

    return {
        "check": (
            "Trusted administrative traffic is "
            "deprioritized through enrichment"
        ),
        "passed": passed
    }


def validate_guardrails(case_report):
    finance = find_case(
        case_report["cases"],
        "INC-001"
    )

    if finance is None:
        return {
            "check": "Analyst guardrails",
            "passed": False
        }

    guardrails = " ".join(
        finance["analyst_guardrails"]
    ).lower()

    assessment = finance[
        "analyst_assessment"
    ].lower()

    passed = (
        "do not merge alerts solely"
        in guardrails
        and "do not automatically isolate"
        in guardrails
        and "do not treat enrichment data as proof"
        in guardrails
        and (
            "does not independently establish "
            "the complete compromise mechanism"
        )
        in assessment
    )

    return {
        "check": (
            "Analyst guardrails preserve human "
            "review and evidentiary uncertainty"
        ),
        "passed": passed
    }


def main():
    alert_report = load_json(
        ALERT_FILE
    )

    case_report = load_json(
        CASE_FILE
    )

    expectations = load_json(
        EXPECTATIONS_FILE
    )

    checks = [
        validate_alert_processing(
            alert_report,
            expectations
        ),

        validate_incident_summary(
            case_report,
            expectations
        )
    ]

    checks.extend(
        validate_cases(
            case_report,
            expectations
        )
    )

    checks.extend([
        validate_finance_deduplication(
            alert_report,
            case_report,
            expectations
        ),

        validate_finance_enrichment(
            case_report
        ),

        validate_cross_source_correlation(
            case_report
        ),

        validate_response_separation(
            case_report
        ),

        validate_trusted_admin_tuning(
            case_report
        ),

        validate_guardrails(
            case_report
        )
    ])

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
        "SOC ALERT ENRICHMENT & "
        "RESPONSE VALIDATION"
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
