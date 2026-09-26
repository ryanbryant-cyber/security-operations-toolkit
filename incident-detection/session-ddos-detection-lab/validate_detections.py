import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

ANALYSIS_FILE = (
    BASE_DIR
    / "output"
    / "activity_analysis_results.json"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "detection_expectations.json"
)

VALIDATION_OUTPUT = (
    BASE_DIR
    / "output"
    / "activity_validation_results.json"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def find_finding(findings, finding_id):
    for finding in findings:
        if finding["finding_id"] == finding_id:
            return finding

    return None


def indicator_names(finding):
    return {
        item["indicator"]
        for item in finding["indicators"]
    }


def validate_summary(report, expectations):
    actual = report["summary"]
    expected = expectations["expected_summary"]

    passed = (
        actual["session_findings"]
        == expected["session_findings"]
        and actual["ddos_findings"]
        == expected["ddos_findings"]
        and actual["total_findings"]
        == expected["total_findings"]
    )

    return {
        "check": "Finding summary",
        "expected": expected,
        "actual": actual,
        "passed": passed
    }


def validate_session(report, expectations):
    findings = report[
        "session_hijacking_analysis"
    ]["findings"]

    expected = expectations["session_finding"]

    finding = find_finding(
        findings,
        expected["finding_id"]
    )

    if finding is None:
        return {
            "check": "Session hijacking finding",
            "passed": False,
            "reason": "Expected session finding was missing."
        }

    passed = (
        finding["user"] == expected["user"]
        and finding["session_id"]
        == expected["session_id"]
        and finding["risk_score"]
        == expected["risk_score"]
        and finding["severity"]
        == expected["severity"]
        and len(finding["indicators"])
        == expected["indicator_count"]
        and expected["anomalous_source_ip"]
        in finding["anomalous_source_ips"]
        and expected["anomalous_user_agent"]
        in finding["anomalous_user_agents"]
    )

    return {
        "check": "Session hijacking finding",
        "finding_id": finding["finding_id"],
        "risk_score": finding["risk_score"],
        "severity": finding["severity"],
        "indicator_count": len(
            finding["indicators"]
        ),
        "passed": passed
    }


def validate_ddos_findings(report, expectations):
    findings = report[
        "ddos_analysis"
    ]["findings"]

    checks = []

    for expected in expectations["ddos_findings"]:
        finding = find_finding(
            findings,
            expected["finding_id"]
        )

        if finding is None:
            checks.append({
                "check": expected["finding_id"],
                "passed": False,
                "reason": "Expected DDoS finding was missing."
            })
            continue

        multiplier_match = (
            abs(
                finding["baseline_multiplier"]
                - expected["baseline_multiplier"]
            )
            < 0.01
        )

        passed = (
            finding["minute"]
            == expected["minute"]
            and finding[
                "observed_requests_per_minute"
            ]
            == expected[
                "observed_requests_per_minute"
            ]
            and multiplier_match
            and finding["distinct_sources"]
            == expected["distinct_sources"]
            and finding["target_endpoint"]
            == expected["target_endpoint"]
            and finding["risk_score"]
            == expected["risk_score"]
            and finding["severity"]
            == expected["severity"]
            and len(finding["indicators"])
            == expected["indicator_count"]
        )

        checks.append({
            "check": expected["finding_id"],
            "requests_per_minute": finding[
                "observed_requests_per_minute"
            ],
            "baseline_multiplier": finding[
                "baseline_multiplier"
            ],
            "risk_score": finding["risk_score"],
            "severity": finding["severity"],
            "passed": passed
        })

    return checks


def validate_behavior(report, expectations):
    session_findings = report[
        "session_hijacking_analysis"
    ]["findings"]

    ddos_analysis = report["ddos_analysis"]
    ddos_findings = ddos_analysis["findings"]

    session = find_finding(
        session_findings,
        "HIJACK-FIN-8842"
    )

    required_session_indicators = {
        "Source IP change",
        "User-agent change",
        "MFA not verified on anomalous origin",
        "Rapid origin change",
        "Sensitive action from anomalous origin",
        "Concurrent origin reuse"
    }

    required_ddos_indicators = {
        "Traffic volume spike",
        "Critical traffic volume spike",
        "Distributed source activity",
        "Endpoint concentration",
        "Error response increase",
        "Response-time degradation"
    }

    baseline_expected = expectations["baseline"]

    checks = []

    checks.append({
        "check": (
            "Session finding contains all six "
            "behavioral indicators"
        ),
        "passed": (
            session is not None
            and required_session_indicators.issubset(
                indicator_names(session)
            )
        )
    })

    checks.append({
        "check": (
            "Finance session is the only "
            "session-hijacking finding"
        ),
        "passed": (
            len(session_findings) == 1
            and session is not None
            and session["user"] == "finance.user"
        )
    })

    checks.append({
        "check": (
            "DDoS baseline matches expected "
            "normal traffic"
        ),
        "passed": (
            ddos_analysis["baseline_totals"]
            == baseline_expected["minute_totals"]
            and abs(
                ddos_analysis["baseline_average"]
                - baseline_expected[
                    "average_requests_per_minute"
                ]
            )
            < 0.01
        )
    })

    checks.append({
        "check": (
            "Both DDoS findings contain all "
            "six behavioral indicators"
        ),
        "passed": (
            len(ddos_findings) == 2
            and all(
                required_ddos_indicators.issubset(
                    indicator_names(finding)
                )
                for finding in ddos_findings
            )
        )
    })

    checks.append({
        "check": (
            "Both DDoS findings exceed "
            "20x normal traffic baseline"
        ),
        "passed": (
            len(ddos_findings) == 2
            and all(
                finding["baseline_multiplier"] >= 20
                for finding in ddos_findings
            )
        )
    })

    checks.append({
        "check": (
            "Containment recommendations are "
            "present for both incident types"
        ),
        "passed": (
            session is not None
            and "Revoke the affected session identifier."
            in session["containment_recommendations"]
            and all(
                (
                    "Apply or tighten rate limiting "
                    "for the affected service or endpoint."
                )
                in finding["containment_recommendations"]
                for finding in ddos_findings
            )
        )
    })

    return checks


def main():
    report = load_json(ANALYSIS_FILE)
    expectations = load_json(EXPECTATIONS_FILE)

    summary_check = validate_summary(
        report,
        expectations
    )

    session_check = validate_session(
        report,
        expectations
    )

    ddos_checks = validate_ddos_findings(
        report,
        expectations
    )

    behavior_checks = validate_behavior(
        report,
        expectations
    )

    all_checks = (
        [summary_check]
        + [session_check]
        + ddos_checks
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
        "session_check": session_check,
        "ddos_checks": ddos_checks,
        "behavioral_checks": behavior_checks
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
        "SESSION HIJACKING & DDoS "
        "DETECTION VALIDATION"
    )
    print("=" * 92)

    print(
        f"{'PASS' if session_check['passed'] else 'REVIEW':<7}"
        f" {session_check['check']} | "
        f"{session_check.get('finding_id', 'N/A')} | "
        f"Score {session_check.get('risk_score', 'N/A')} | "
        f"{session_check.get('severity', 'N/A')}"
    )

    for check in ddos_checks:
        status = (
            "PASS"
            if check["passed"]
            else "REVIEW"
        )

        print(
            f"{status:<7} "
            f"{check['check']} | "
            f"{check.get('requests_per_minute', 'N/A')} req/min | "
            f"{check.get('baseline_multiplier', 'N/A')}x | "
            f"{check.get('severity', 'N/A')}"
        )

    print("-" * 92)

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

    print("=" * 92)

    print(
        f"Summary check:  "
        f"{'PASS' if summary_check['passed'] else 'REVIEW'}"
    )

    print(f"Checks run:     {len(all_checks)}")
    print(f"Checks passed:  {passed}")
    print(f"Checks failed:  {failed}")

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
