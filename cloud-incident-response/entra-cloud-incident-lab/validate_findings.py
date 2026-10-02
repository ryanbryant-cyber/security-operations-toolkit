import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

ANALYSIS_FILE = (
    BASE_DIR
    / "output"
    / "cloud_incident_results.json"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "cloud_incident_expectations.json"
)

VALIDATION_OUTPUT = (
    BASE_DIR
    / "output"
    / "cloud_incident_validation_results.json"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def find_incident(incidents, incident_id):
    for incident in incidents:
        if incident["incident_id"] == incident_id:
            return incident

    return None


def indicator_names(incident):
    return {
        item["indicator"]
        for item in incident["indicators"]
    }


def validate_summary(report, expectations):
    actual = report["summary"]
    expected = expectations["expected_summary"]

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
        "expected": expected,
        "actual": actual,
        "passed": passed
    }


def validate_incidents(report, expectations):
    incidents = report["incidents"]
    checks = []

    for expected in expectations["expected_incidents"]:
        incident = find_incident(
            incidents,
            expected["incident_id"]
        )

        if incident is None:
            checks.append({
                "check": expected["incident_id"],
                "passed": False,
                "reason": "Expected incident was missing."
            })
            continue

        services_match = (
            set(incident["cloud_services"])
            == set(expected["cloud_services"])
        )

        containment_match = (
            len(incident["containment_observed"])
            == expected["containment_count"]
        )

        passed = (
            incident["user"]
            == expected["user"]
            and incident["session_id"]
            == expected["session_id"]
            and incident["source_ip"]
            == expected["source_ip"]
            and incident["risk_score"]
            == expected["risk_score"]
            and incident["priority"]
            == expected["priority"]
            and incident["indicator_count"]
            == expected["indicator_count"]
            and incident["privileged_activity_count"]
            == expected["privileged_activity_count"]
            and incident["resource_activity_count"]
            == expected["resource_activity_count"]
            and services_match
            and containment_match
        )

        checks.append({
            "check": expected["incident_id"],
            "user": incident["user"],
            "risk_score": incident["risk_score"],
            "priority": incident["priority"],
            "indicator_count": incident["indicator_count"],
            "containment_count": len(
                incident["containment_observed"]
            ),
            "passed": passed
        })

    return checks


def validate_required_indicators(
    incident,
    required,
    label
):
    actual = indicator_names(
        incident
    )

    missing = sorted(
        set(required) - actual
    )

    return {
        "check": label,
        "required_count": len(required),
        "actual_count": len(actual),
        "missing_indicators": missing,
        "passed": len(missing) == 0
    }


def validate_finance_authentication(report):
    finance = find_incident(
        report["incidents"],
        "CLOUD-INC-001"
    )

    if finance is None:
        return {
            "check": "Finance authentication correlation",
            "passed": False
        }

    names = indicator_names(finance)

    passed = (
        "Repeated failed sign-ins" in names
        and "Success after repeated failures" in names
        and "High sign-in risk" in names
        and "Unfamiliar external source" in names
    )

    return {
        "check": (
            "Finance incident preserves authentication "
            "failure-to-success correlation"
        ),
        "passed": passed
    }


def validate_conditional_access_precision(report):
    finance = find_incident(
        report["incidents"],
        "CLOUD-INC-001"
    )

    if finance is None:
        return {
            "check": "Conditional Access interpretation",
            "passed": False
        }

    names = indicator_names(finance)

    report_only_present = (
        "Report-only policy failure"
        in names
    )

    mfa_present = (
        "MFA satisfied"
        in names
    )

    mfa_indicator = next(
        (
            item
            for item in finance["indicators"]
            if item["indicator"]
            == "MFA satisfied"
        ),
        None
    )

    passed = (
        report_only_present
        and mfa_present
        and mfa_indicator is not None
        and mfa_indicator["points"] == -5
    )

    return {
        "check": (
            "Conditional Access and MFA evidence "
            "are interpreted precisely"
        ),
        "passed": passed
    }


def validate_privilege_context(report):
    finance = find_incident(
        report["incidents"],
        "CLOUD-INC-001"
    )

    if finance is None:
        return {
            "check": "Privilege activity context",
            "passed": False
        }

    names = indicator_names(finance)

    passed = (
        "Role added without justification"
        in names
        and "Role modified without ticket"
        in names
        and "Role activity in suspicious session"
        in names
    )

    return {
        "check": (
            "Finance incident preserves undocumented "
            "cloud role activity"
        ),
        "passed": passed
    }


def validate_resource_scope(report):
    finance = find_incident(
        report["incidents"],
        "CLOUD-INC-001"
    )

    if finance is None:
        return {
            "check": "Cloud resource scope",
            "passed": False
        }

    expected_services = {
        "Microsoft 365",
        "Azure Resource Manager",
        "Azure Storage"
    }

    expected_resources = {
        "Finance SharePoint Site",
        "NFG-FIN-VM01",
        "nfgfinstorage"
    }

    passed = (
        expected_services.issubset(
            set(finance["cloud_services"])
        )
        and expected_resources.issubset(
            set(finance["resources_accessed"])
        )
    )

    return {
        "check": (
            "Finance incident spans multiple cloud "
            "services and resources"
        ),
        "passed": passed
    }


def validate_separate_incidents(report):
    finance = find_incident(
        report["incidents"],
        "CLOUD-INC-001"
    )

    contractor = find_incident(
        report["incidents"],
        "CLOUD-INC-002"
    )

    passed = (
        finance is not None
        and contractor is not None
        and finance["user"]
        != contractor["user"]
        and finance["session_id"]
        != contractor["session_id"]
    )

    return {
        "check": (
            "Finance and dormant-contractor activity "
            "remain separate incidents"
        ),
        "passed": passed
    }


def validate_containment_separation(report):
    finance = find_incident(
        report["incidents"],
        "CLOUD-INC-001"
    )

    contractor = find_incident(
        report["incidents"],
        "CLOUD-INC-002"
    )

    if (
        finance is None
        or contractor is None
    ):
        return {
            "check": "Containment separation",
            "passed": False
        }

    finance_actions = {
        item["action"]
        for item in finance[
            "containment_observed"
        ]
    }

    contractor_actions = {
        item["action"]
        for item in contractor[
            "containment_observed"
        ]
    }

    finance_timeline_phases = {
        item["phase"]
        for item in finance["timeline"]
    }

    contractor_timeline_phases = {
        item["phase"]
        for item in contractor["timeline"]
    }

    passed = (
        "Revoke Sessions"
        in finance_actions
        and "Remove Member"
        in contractor_actions
        and "Disable Account"
        in contractor_actions
        and "Response / Containment"
        in finance_timeline_phases
        and "Response / Containment"
        in contractor_timeline_phases
    )

    return {
        "check": (
            "Containment actions remain distinct "
            "from incident activity"
        ),
        "passed": passed
    }


def validate_assessment_language(report):
    finance = find_incident(
        report["incidents"],
        "CLOUD-INC-001"
    )

    if finance is None:
        return {
            "check": "Analyst assessment precision",
            "passed": False
        }

    assessment = finance[
        "analyst_assessment"
    ].lower()

    required = [
        "does not independently prove credential theft",
        "mfa bypass",
        "data exfiltration",
        "successful vm compromise",
        "persistence"
    ]

    passed = all(
        phrase in assessment
        for phrase in required
    )

    return {
        "check": (
            "Analyst assessment preserves "
            "evidentiary uncertainty"
        ),
        "passed": passed
    }


def validate_guardrails(report):
    finance = find_incident(
        report["incidents"],
        "CLOUD-INC-001"
    )

    if finance is None:
        return {
            "check": "Analyst guardrails",
            "passed": False
        }

    text = " ".join(
        finance["analyst_guardrails"]
    ).lower()

    required = [
        "confirmed credential theft",
        "mfa as bypassed",
        "report-only conditional access failure",
        "confirmed privilege escalation",
        "confirmed data exfiltration",
        "successful vm compromise",
        "separate incident activity from later containment"
    ]

    passed = all(
        phrase in text
        for phrase in required
    )

    return {
        "check": (
            "Cloud incident-response guardrails "
            "are present"
        ),
        "passed": passed
    }


def main():
    report = load_json(
        ANALYSIS_FILE
    )

    expectations = load_json(
        EXPECTATIONS_FILE
    )

    finance = find_incident(
        report["incidents"],
        "CLOUD-INC-001"
    )

    contractor = find_incident(
        report["incidents"],
        "CLOUD-INC-002"
    )

    checks = [
        validate_summary(
            report,
            expectations
        )
    ]

    checks.extend(
        validate_incidents(
            report,
            expectations
        )
    )

    checks.append(
        validate_required_indicators(
            finance,
            expectations[
                "required_finance_indicators"
            ],
            (
                "Finance incident contains all "
                "required indicators"
            )
        )
    )

    checks.append(
        validate_required_indicators(
            contractor,
            expectations[
                "required_contractor_indicators"
            ],
            (
                "Dormant-contractor incident contains "
                "all required indicators"
            )
        )
    )

    checks.extend([
        validate_finance_authentication(
            report
        ),

        validate_conditional_access_precision(
            report
        ),

        validate_privilege_context(
            report
        ),

        validate_resource_scope(
            report
        ),

        validate_separate_incidents(
            report
        ),

        validate_containment_separation(
            report
        ),

        validate_assessment_language(
            report
        ),

        validate_guardrails(
            report
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
        "MICROSOFT ENTRA ID CLOUD INCIDENT "
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
        f"{validation_report['validation_status']}"
    )

    print("=" * 96)

    print(
        f"Validation report: "
        f"{VALIDATION_OUTPUT}"
    )


if __name__ == "__main__":
    main()
