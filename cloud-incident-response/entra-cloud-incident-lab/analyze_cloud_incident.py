import csv
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

SIGNIN_FILE = (
    BASE_DIR
    / "sample-data"
    / "signin_events.csv"
)

CA_FILE = (
    BASE_DIR
    / "sample-data"
    / "conditional_access.csv"
)

PRIVILEGE_FILE = (
    BASE_DIR
    / "sample-data"
    / "privileged_activity.csv"
)

RESOURCE_FILE = (
    BASE_DIR
    / "sample-data"
    / "resource_activity.csv"
)

RULES_FILE = (
    BASE_DIR
    / "rules"
    / "cloud_response_rules.json"
)

OUTPUT_DIR = BASE_DIR / "output"

JSON_OUTPUT = (
    OUTPUT_DIR
    / "cloud_incident_results.json"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "cloud_incident_summary.csv"
)


def load_csv(path):
    with open(
        path,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        return list(csv.DictReader(file))


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def parse_time(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def to_bool(value):
    return str(value).strip().lower() == "true"


def assign_priority(score, thresholds):
    if score >= thresholds["CRITICAL"]:
        return "CRITICAL"

    if score >= thresholds["HIGH"]:
        return "HIGH"

    if score >= thresholds["MODERATE"]:
        return "MODERATE"

    return "LOW"


def add_indicator(
    indicators,
    category,
    name,
    points,
    evidence
):
    indicators.append({
        "category": category,
        "indicator": name,
        "points": points,
        "evidence": evidence
    })


def failed_signins_before_success(
    signin_events,
    success_event,
    minimum_failures,
    window_seconds
):
    success_time = parse_time(
        success_event["timestamp"]
    )

    matching = []

    for event in signin_events:
        if event["result"] != "failure":
            continue

        if event["user"] != success_event["user"]:
            continue

        if event["source_ip"] != success_event["source_ip"]:
            continue

        event_time = parse_time(
            event["timestamp"]
        )

        difference = (
            success_time - event_time
        ).total_seconds()

        if 0 < difference <= window_seconds:
            matching.append(event)

    matching.sort(
        key=lambda item: parse_time(
            item["timestamp"]
        )
    )

    if len(matching) >= minimum_failures:
        return matching

    return []


def analyze_authentication(
    signin_events,
    success_event,
    rules,
    indicators
):
    score = 0

    auth_rules = rules[
        "authentication_indicators"
    ]

    repeated_rule = auth_rules[
        "repeated_failed_signins"
    ]

    failures = failed_signins_before_success(
        signin_events,
        success_event,
        repeated_rule["minimum_failures"],
        repeated_rule["window_seconds"]
    )

    if failures:
        score += repeated_rule["points"]

        add_indicator(
            indicators,
            "Authentication",
            "Repeated failed sign-ins",
            repeated_rule["points"],
            (
                f"{len(failures)} failed sign-ins "
                f"from {success_event['source_ip']} "
                "preceded the successful authentication."
            )
        )

        success_rule = auth_rules[
            "success_after_failures"
        ]

        last_failure_time = parse_time(
            failures[-1]["timestamp"]
        )

        success_time = parse_time(
            success_event["timestamp"]
        )

        seconds_after = int(
            (
                success_time
                - last_failure_time
            ).total_seconds()
        )

        if (
            seconds_after
            <= success_rule[
                "maximum_seconds_after_failure"
            ]
        ):
            score += success_rule["points"]

            add_indicator(
                indicators,
                "Authentication",
                "Success after repeated failures",
                success_rule["points"],
                (
                    "Successful authentication occurred "
                    f"{seconds_after} seconds after the "
                    "last failed sign-in from the same source."
                )
            )

    if (
        success_event["sign_in_risk"].lower()
        == "high"
    ):
        rule = auth_rules[
            "high_signin_risk"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Authentication",
            "High sign-in risk",
            rule["points"],
            "The successful sign-in was marked high risk."
        )

    if not to_bool(
        success_event["device_managed"]
    ):
        rule = auth_rules[
            "unmanaged_device"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Authentication",
            "Unmanaged device",
            rule["points"],
            (
                "The successful session originated "
                "from an unmanaged device."
            )
        )

    if not to_bool(
        success_event["device_compliant"]
    ):
        rule = auth_rules[
            "noncompliant_device"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Authentication",
            "Noncompliant device",
            rule["points"],
            (
                "The successful session originated "
                "from a noncompliant device."
            )
        )

    if (
        not success_event["source_ip"].startswith("10.")
        and success_event["location"]
        == "Unknown"
    ):
        rule = auth_rules[
            "unfamiliar_external_source"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Authentication",
            "Unfamiliar external source",
            rule["points"],
            (
                f"Successful authentication originated "
                f"from {success_event['source_ip']} "
                "rather than the established internal baseline."
            )
        )

    return score, failures


def analyze_conditional_access(
    ca_events,
    session_id,
    rules,
    indicators
):
    score = 0

    ca_rules = rules[
        "conditional_access_indicators"
    ]

    session_events = [
        event
        for event in ca_events
        if event["session_id"] == session_id
    ]

    report_only_failure = any(
        event["policy_result"]
        == "reportOnlyFailure"
        for event in session_events
    )

    if report_only_failure:
        rule = ca_rules[
            "report_only_policy_failure"
        ]

        score += rule["points"]

        policies = sorted({
            event["policy_name"]
            for event in session_events
            if event["policy_result"]
            == "reportOnlyFailure"
        })

        add_indicator(
            indicators,
            "Conditional Access",
            "Report-only policy failure",
            rule["points"],
            (
                "Report-only policy concern: "
                + ", ".join(policies)
            )
        )

    mfa_satisfied = any(
        to_bool(event["mfa_satisfied"])
        for event in session_events
    )

    if mfa_satisfied:
        rule = ca_rules[
            "mfa_satisfied_reduction"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Conditional Access",
            "MFA satisfied",
            rule["points"],
            (
                "Telemetry shows MFA was satisfied. "
                "This reduces support for an MFA-bypass hypothesis."
            )
        )

    return score, session_events


def analyze_privileged_activity(
    privilege_events,
    session_id,
    rules,
    indicators
):
    score = 0

    privilege_rules = rules[
        "privileged_activity_indicators"
    ]

    session_events = [
        event
        for event in privilege_events
        if event["session_id"] == session_id
    ]

    role_added = [
        event
        for event in session_events
        if (
            event["action"] == "Add Member"
            and not event["justification"].strip()
        )
    ]

    if role_added:
        rule = privilege_rules[
            "role_added_without_justification"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Privileged Access",
            "Role added without justification",
            rule["points"],
            "; ".join(
                (
                    f"{event['role']} on "
                    f"{event['target']}"
                )
                for event in role_added
            )
        )

    modified_without_ticket = [
        event
        for event in session_events
        if (
            event["action"]
            == "Role Assignment Modified"
            and event["ticket_number"]
            == "NONE"
        )
    ]

    if modified_without_ticket:
        rule = privilege_rules[
            "role_modified_without_ticket"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Privileged Access",
            "Role modified without ticket",
            rule["points"],
            "; ".join(
                (
                    f"{event['role']} on "
                    f"{event['target']}"
                )
                for event
                in modified_without_ticket
            )
        )

    suspicious_role_activity = [
        event
        for event in session_events
        if event["action"] in {
            "Add Member",
            "Role Assignment Modified"
        }
    ]

    if suspicious_role_activity:
        rule = privilege_rules[
            "suspicious_session_role_activity"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Privileged Access",
            "Role activity in suspicious session",
            rule["points"],
            (
                f"{len(suspicious_role_activity)} "
                "privilege-related events occurred "
                "within the session."
            )
        )

    approved_activity = [
        event
        for event in session_events
        if (
            event["action"]
            in {
                "Activate Role",
                "Role Activation Confirmed"
            }
            and event["justification"].strip()
            and event["ticket_number"]
            not in {
                "",
                "NONE"
            }
        )
    ]

    if approved_activity:
        rule = privilege_rules[
            "approved_pim_activity_reduction"
        ]

        score += rule["points"]

        add_indicator(
            indicators,
            "Privileged Access",
            "Approved privileged workflow",
            rule["points"],
            (
                "Privilege activity included documented "
                "justification and ticketing."
            )
        )

    return score, session_events


def analyze_resource_activity(
    resource_events,
    session_id,
    rules,
    indicators
):
    score = 0

    resource_rules = rules[
        "resource_activity_indicators"
    ]

    session_events = [
        event
        for event in resource_events
        if event["session_id"] == session_id
    ]

    sensitive_rule = resource_rules[
        "sensitive_document_access"
    ]

    sensitive_events = [
        event
        for event in session_events
        if event["operation"]
        in sensitive_rule["operations"]
    ]

    if sensitive_events:
        score += sensitive_rule["points"]

        add_indicator(
            indicators,
            "Cloud Resource",
            "Sensitive content accessed",
            sensitive_rule["points"],
            "; ".join(
                (
                    f"{event['operation']} on "
                    f"{event['resource']}"
                )
                for event in sensitive_events
            )
        )

    enumeration_rule = resource_rules[
        "cloud_resource_enumeration"
    ]

    enumeration_events = [
        event
        for event in session_events
        if event["operation"]
        in enumeration_rule["operations"]
    ]

    if enumeration_events:
        score += enumeration_rule["points"]

        add_indicator(
            indicators,
            "Cloud Resource",
            "Cloud resource enumeration",
            enumeration_rule["points"],
            "; ".join(
                (
                    f"{event['operation']} on "
                    f"{event['resource']}"
                )
                for event
                in enumeration_events
            )
        )

    vm_rule = resource_rules[
        "vm_login_access_requested"
    ]

    vm_requests = [
        event
        for event in session_events
        if event["operation"]
        == vm_rule["operation"]
    ]

    if vm_requests:
        score += vm_rule["points"]

        add_indicator(
            indicators,
            "Cloud Resource",
            "VM login access requested",
            vm_rule["points"],
            "; ".join(
                event["resource"]
                for event in vm_requests
            )
        )

    services = {
        event["service"]
        for event in session_events
    }

    multiple_rule = resource_rules[
        "multiple_cloud_services"
    ]

    if (
        len(services)
        >= multiple_rule[
            "minimum_services"
        ]
    ):
        score += multiple_rule["points"]

        add_indicator(
            indicators,
            "Cloud Resource",
            "Multiple cloud services accessed",
            multiple_rule["points"],
            ", ".join(
                sorted(services)
            )
        )

    return score, session_events


def build_timeline(
    failed_signins,
    success_event,
    ca_events,
    privilege_events,
    resource_events,
    containment_events
):
    timeline = []

    for event in failed_signins:
        timeline.append({
            "timestamp": event["timestamp"],
            "source": "Authentication",
            "event": (
                f"Failed sign-in from "
                f"{event['source_ip']}"
            ),
            "phase": "Incident Activity"
        })

    timeline.append({
        "timestamp": success_event["timestamp"],
        "source": "Authentication",
        "event": (
            f"Successful sign-in from "
            f"{success_event['source_ip']} "
            f"using session "
            f"{success_event['session_id']}"
        ),
        "phase": "Incident Activity"
    })

    for event in ca_events:
        timeline.append({
            "timestamp": event["timestamp"],
            "source": "Conditional Access",
            "event": (
                f"{event['policy_name']} → "
                f"{event['policy_result']}"
            ),
            "phase": "Security Control Evidence"
        })

    for event in privilege_events:
        timeline.append({
            "timestamp": event["timestamp"],
            "source": "Privileged Access",
            "event": (
                f"{event['action']} | "
                f"{event['role']} | "
                f"{event['target']}"
            ),
            "phase": "Incident Activity"
        })

    for event in resource_events:
        timeline.append({
            "timestamp": event["timestamp"],
            "source": "Cloud Resource",
            "event": (
                f"{event['operation']} | "
                f"{event['service']} | "
                f"{event['resource']}"
            ),
            "phase": "Incident Activity"
        })

    for event in containment_events:
        timeline.append({
            "timestamp": event["timestamp"],
            "source": "Containment",
            "event": (
                f"{event['action']} | "
                f"{event['target']}"
            ),
            "phase": "Response / Containment"
        })

    timeline.sort(
        key=lambda item: parse_time(
            item["timestamp"]
        )
    )

    return timeline


def containment_for_user(
    privilege_events,
    user
):
    containment_actions = {
        "Revoke Sessions",
        "Remove Member",
        "Disable Account"
    }

    return [
        event
        for event in privilege_events
        if (
            event["action"]
            in containment_actions
            and event["target"] == user
        )
    ]


def create_incident(
    incident_id,
    signin_events,
    ca_events,
    privilege_events,
    resource_events,
    success_event,
    rules,
    containment_recommendations
):
    indicators = []
    score = 0

    auth_score, failures = (
        analyze_authentication(
            signin_events,
            success_event,
            rules,
            indicators
        )
    )

    score += auth_score

    ca_score, session_ca = (
        analyze_conditional_access(
            ca_events,
            success_event["session_id"],
            rules,
            indicators
        )
    )

    score += ca_score

    privilege_score, session_privilege = (
        analyze_privileged_activity(
            privilege_events,
            success_event["session_id"],
            rules,
            indicators
        )
    )

    score += privilege_score

    resource_score, session_resources = (
        analyze_resource_activity(
            resource_events,
            success_event["session_id"],
            rules,
            indicators
        )
    )

    score += resource_score

    services = {
        event["service"]
        for event in session_resources
    }

    scope_rule = rules[
        "scope_indicators"
    ][
        "single_identity_multiple_services"
    ]

    if len(services) >= 2:
        score += scope_rule["points"]

        add_indicator(
            indicators,
            "Scope",
            "Single identity active across multiple services",
            scope_rule["points"],
            ", ".join(
                sorted(services)
            )
        )

    final_score = max(
        0,
        min(
            score,
            rules["maximum_score"]
        )
    )

    priority = assign_priority(
        final_score,
        rules["priority_thresholds"]
    )

    containment_events = containment_for_user(
        privilege_events,
        success_event["user"]
    )

    timeline = build_timeline(
        failures,
        success_event,
        session_ca,
        session_privilege,
        session_resources,
        containment_events
    )

    resources = sorted({
        event["resource"]
        for event in session_resources
    })

    finding_name = rules[
        "incident_classification"
    ][
        "default_finding"
    ]

    return {
        "incident_id": incident_id,
        "finding_type": finding_name,
        "user": success_event["user"],
        "session_id": success_event["session_id"],
        "source_ip": success_event["source_ip"],
        "risk_score": final_score,
        "priority": priority,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "cloud_services": sorted(services),
        "resources_accessed": resources,
        "privileged_activity_count": len(
            session_privilege
        ),
        "resource_activity_count": len(
            session_resources
        ),
        "containment_observed": [
            {
                "timestamp": event["timestamp"],
                "action": event["action"],
                "target": event["target"],
                "notes": event["notes"]
            }
            for event in containment_events
        ],
        "containment_recommendations": (
            containment_recommendations
        ),
        "timeline": timeline,
        "analyst_assessment": (
            "Multiple cloud identity, Conditional Access, "
            "privileged-access, and resource artifacts "
            "converge on the same authenticated session. "
            "The evidence supports a suspected cloud "
            "identity compromise investigation and "
            "containment response. The available telemetry "
            "does not independently prove credential theft, "
            "MFA bypass, data exfiltration, successful VM "
            "compromise, or persistence."
        ),
        "analyst_guardrails": rules[
            "analyst_guardrails"
        ]
    }


def find_success_event(
    signin_events,
    user,
    session_id
):
    return next(
        (
            event
            for event in signin_events
            if (
                event["user"] == user
                and event["session_id"]
                == session_id
                and event["result"]
                == "success"
            )
        ),
        None
    )


def analyze_incidents(
    signin_events,
    ca_events,
    privilege_events,
    resource_events,
    rules
):
    incidents = []

    finance_success = find_success_event(
        signin_events,
        "finance.user@northstar.example",
        "SESSION-FIN-8842"
    )

    if finance_success:
        incidents.append(
            create_incident(
                "CLOUD-INC-001",
                signin_events,
                ca_events,
                privilege_events,
                resource_events,
                finance_success,
                rules,
                rules[
                    "containment_recommendations"
                ][
                    "finance_identity"
                ]
            )
        )

    contractor_success = find_success_event(
        signin_events,
        "dormant.contractor@northstar.example",
        "SESSION-CONTRACT-4402"
    )

    if contractor_success:
        incident = create_incident(
            "CLOUD-INC-002",
            signin_events,
            ca_events,
            privilege_events,
            resource_events,
            contractor_success,
            rules,
            rules[
                "containment_recommendations"
            ][
                "dormant_identity"
            ]
        )

        dormant_rule = rules[
            "scope_indicators"
        ][
            "separate_dormant_identity_activity"
        ]

        incident[
            "raw_scope_adjustment"
        ] = dormant_rule["points"]

        incident[
            "scope_note"
        ] = (
            "A separate dormant identity generated "
            "authentication, privilege, and resource "
            "activity and is treated as a distinct incident."
        )

        incidents.append(incident)

    return incidents


def export_results(incidents):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    summary = {
        "incident_count": len(incidents),
        "critical": sum(
            1
            for incident in incidents
            if incident["priority"]
            == "CRITICAL"
        ),
        "high": sum(
            1
            for incident in incidents
            if incident["priority"]
            == "HIGH"
        ),
        "moderate": sum(
            1
            for incident in incidents
            if incident["priority"]
            == "MODERATE"
        ),
        "low": sum(
            1
            for incident in incidents
            if incident["priority"]
            == "LOW"
        )
    }

    report = {
        "summary": summary,
        "incidents": incidents
    }

    with open(
        JSON_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )

    fieldnames = [
        "incident_id",
        "finding_type",
        "user",
        "session_id",
        "source_ip",
        "risk_score",
        "priority",
        "indicator_count",
        "privileged_activity_count",
        "resource_activity_count",
        "cloud_services",
        "resources_accessed",
        "analyst_assessment"
    ]

    with open(
        CSV_OUTPUT,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for incident in incidents:
            writer.writerow({
                "incident_id": incident[
                    "incident_id"
                ],
                "finding_type": incident[
                    "finding_type"
                ],
                "user": incident["user"],
                "session_id": incident[
                    "session_id"
                ],
                "source_ip": incident[
                    "source_ip"
                ],
                "risk_score": incident[
                    "risk_score"
                ],
                "priority": incident[
                    "priority"
                ],
                "indicator_count": incident[
                    "indicator_count"
                ],
                "privileged_activity_count": (
                    incident[
                        "privileged_activity_count"
                    ]
                ),
                "resource_activity_count": (
                    incident[
                        "resource_activity_count"
                    ]
                ),
                "cloud_services": " | ".join(
                    incident[
                        "cloud_services"
                    ]
                ),
                "resources_accessed": " | ".join(
                    incident[
                        "resources_accessed"
                    ]
                ),
                "analyst_assessment": incident[
                    "analyst_assessment"
                ]
            })


def print_results(incidents):
    print()
    print("=" * 96)
    print(
        "MICROSOFT ENTRA ID CLOUD "
        "COMPROMISE INVESTIGATION & RESPONSE LAB"
    )
    print("=" * 96)

    for incident in incidents:
        print(
            f"{incident['incident_id']} | "
            f"{incident['priority']:<8} | "
            f"Score {incident['risk_score']:>3} | "
            f"{incident['user']}"
        )

        print(
            f"             "
            f"Session: {incident['session_id']} | "
            f"Source: {incident['source_ip']}"
        )

        print(
            f"             "
            f"Indicators: "
            f"{incident['indicator_count']} | "
            f"Privilege Events: "
            f"{incident['privileged_activity_count']} | "
            f"Resource Events: "
            f"{incident['resource_activity_count']}"
        )

        print(
            f"             "
            f"Services: "
            + ", ".join(
                incident["cloud_services"]
            )
        )

        print("-" * 96)

    print(
        f"Incidents: {len(incidents)}"
    )

    print(
        f"CRITICAL:  "
        f"{sum(1 for item in incidents if item['priority'] == 'CRITICAL')}"
    )

    print(
        f"HIGH:      "
        f"{sum(1 for item in incidents if item['priority'] == 'HIGH')}"
    )

    print(
        f"MODERATE:  "
        f"{sum(1 for item in incidents if item['priority'] == 'MODERATE')}"
    )

    print(
        f"LOW:       "
        f"{sum(1 for item in incidents if item['priority'] == 'LOW')}"
    )

    print("=" * 96)

    print(
        f"JSON report: {JSON_OUTPUT}"
    )

    print(
        f"CSV report:  {CSV_OUTPUT}"
    )

    print("=" * 96)


def main():
    signin_events = load_csv(
        SIGNIN_FILE
    )

    ca_events = load_csv(
        CA_FILE
    )

    privilege_events = load_csv(
        PRIVILEGE_FILE
    )

    resource_events = load_csv(
        RESOURCE_FILE
    )

    rules = load_json(
        RULES_FILE
    )

    incidents = analyze_incidents(
        signin_events,
        ca_events,
        privilege_events,
        resource_events,
        rules
    )

    export_results(
        incidents
    )

    print_results(
        incidents
    )


if __name__ == "__main__":
    main()
