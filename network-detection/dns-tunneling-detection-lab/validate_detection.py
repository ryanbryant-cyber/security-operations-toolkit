import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

RESULTS_FILE = (
    BASE_DIR
    / "output"
    / "dns_detection_results.json"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "dns_detection_expectations.json"
)

VALIDATION_OUTPUT = (
    BASE_DIR
    / "output"
    / "dns_detection_validation_results.json"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def indicator_names(finding):
    return {
        item["indicator"]
        for item in finding["indicators"]
    }


def validate_summary(report, expectations):
    actual = report["summary"]
    expected = expectations["expected_summary"]

    passed = all(
        actual[key] == value
        for key, value in expected.items()
    )

    return {
        "check": "DNS analysis summary",
        "passed": passed
    }


def validate_primary_finding(report, expectations):
    if len(report["findings"]) != 1:
        return {
            "check": "Primary DNS finding",
            "passed": False
        }

    finding = report["findings"][0]
    expected = expectations["expected_finding"]

    numeric_matches = (
        abs(
            finding["unique_subdomain_ratio"]
            - expected["unique_subdomain_ratio"]
        ) < 0.001
        and abs(
            finding["encoded_subdomain_ratio"]
            - expected["encoded_subdomain_ratio"]
        ) < 0.001
        and abs(
            finding["average_query_interval_seconds"]
            - expected["average_query_interval_seconds"]
        ) < 0.01
    )

    passed = (
        finding["finding_id"]
        == expected["finding_id"]
        and finding["finding_type"]
        == expected["finding_type"]
        and finding["source_host"]
        == expected["source_host"]
        and finding["source_ip"]
        == expected["source_ip"]
        and finding["parent_domain"]
        == expected["parent_domain"]
        and finding["query_count"]
        == expected["query_count"]
        and finding["txt_query_count"]
        == expected["txt_query_count"]
        and finding["risk_score"]
        == expected["risk_score"]
        and finding["priority"]
        == expected["priority"]
        and finding["indicator_count"]
        == expected["indicator_count"]
        and numeric_matches
    )

    return {
        "check": "Primary DNS tunneling finding",
        "passed": passed
    }


def validate_indicators(report, expectations):
    finding = report["findings"][0]

    required = set(
        expectations["required_indicators"]
    )

    actual = indicator_names(finding)

    return {
        "check": "All six DNS behavioral indicators are present",
        "passed": required.issubset(actual)
    }


def validate_txt_behavior(report):
    finding = report["findings"][0]

    return {
        "check": "Multiple TXT queries contribute to the finding",
        "passed": (
            finding["txt_query_count"] == 5
            and "Multiple TXT queries"
            in indicator_names(finding)
        )
    }


def validate_subdomain_behavior(report):
    finding = report["findings"][0]

    return {
        "check": "Unique and encoded subdomain behavior is preserved",
        "passed": (
            finding["unique_subdomain_ratio"] == 1.0
            and finding["encoded_subdomain_ratio"] == 1.0
            and "High unique-subdomain ratio"
            in indicator_names(finding)
            and "Encoded-looking subdomains"
            in indicator_names(finding)
        )
    }


def validate_normal_traffic_not_alerted(report):
    findings = report["findings"]

    suspicious_hosts = {
        item["source_host"]
        for item in findings
    }

    return {
        "check": "Normal peer hosts do not become analyst findings",
        "passed": suspicious_hosts == {"NFG-FIN-WS07"}
    }


def validate_only_target_domain_alerted(report):
    domains = {
        item["parent_domain"]
        for item in report["findings"]
    }

    return {
        "check": "Only the higher-interest parent domain becomes a finding",
        "passed": domains == {"tunnel-demo.example"}
    }


def validate_assessment_language(report):
    assessment = (
        report["findings"][0][
            "analyst_assessment"
        ].lower()
    )

    required = [
        "possible dns tunneling",
        "does not prove command-and-control",
        "data exfiltration"
    ]

    return {
        "check": "Analyst assessment preserves evidentiary uncertainty",
        "passed": all(
            phrase in assessment
            for phrase in required
        )
    }


def validate_guardrails(report):
    text = " ".join(
        report["findings"][0][
            "analyst_guardrails"
        ]
    ).lower()

    required = [
        "long dns queries",
        "txt record usage",
        "high subdomain diversity",
        "hexadecimal-looking labels",
        "investigation priority",
        "observed dns behavior"
    ]

    return {
        "check": "DNS analyst guardrails are preserved",
        "passed": all(
            phrase in text
            for phrase in required
        )
    }


def validate_priority(report):
    finding = report["findings"][0]

    return {
        "check": "Correlated DNS behavior reaches CRITICAL priority",
        "passed": (
            finding["risk_score"] == 100
            and finding["priority"] == "CRITICAL"
            and finding["indicator_count"] == 6
        )
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
        ),
        validate_primary_finding(
            report,
            expectations
        ),
        validate_indicators(
            report,
            expectations
        ),
        validate_txt_behavior(
            report
        ),
        validate_subdomain_behavior(
            report
        ),
        validate_normal_traffic_not_alerted(
            report
        ),
        validate_only_target_domain_alerted(
            report
        ),
        validate_assessment_language(
            report
        ),
        validate_guardrails(
            report
        ),
        validate_priority(
            report
        )
    ]

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
    print("=" * 92)
    print(
        "DNS TUNNELING DETECTION VALIDATION"
    )
    print("=" * 92)

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

    print("=" * 92)

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

    print("=" * 92)

    print(
        f"Validation report: "
        f"{VALIDATION_OUTPUT}"
    )


if __name__ == "__main__":
    main()
