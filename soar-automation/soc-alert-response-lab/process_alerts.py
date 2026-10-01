import csv
import json
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

ALERTS_FILE = (
    BASE_DIR
    / "sample-data"
    / "alerts.json"
)

USERS_FILE = (
    BASE_DIR
    / "sample-data"
    / "users.json"
)

ASSETS_FILE = (
    BASE_DIR
    / "sample-data"
    / "assets.json"
)

IOC_FILE = (
    BASE_DIR
    / "sample-data"
    / "ioc_context.json"
)

RULES_FILE = (
    BASE_DIR
    / "rules"
    / "response_rules.json"
)

OUTPUT_DIR = BASE_DIR / "output"

ALERT_OUTPUT = (
    OUTPUT_DIR
    / "normalized_enriched_alerts.json"
)

CASE_OUTPUT = (
    OUTPUT_DIR
    / "analyst_incident_cases.json"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "analyst_incident_summary.csv"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def parse_time(value):
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def severity_rank(value):
    ranks = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }

    return ranks.get(value, 0)


def build_lookups(
    users_data,
    assets_data,
    ioc_data
):
    users = {
        user["username"]: user
        for user in users_data["users"]
    }

    assets = {
        asset["hostname"]: asset
        for asset in assets_data["assets"]
    }

    indicators = {
        item["indicator"]: item
        for item in ioc_data["indicators"]
    }

    return users, assets, indicators


def enrich_iocs(alert, ioc_lookup):
    values = [
        alert.get("indicator", ""),
        alert.get("source_ip", ""),
        alert.get("destination_ip", "")
    ]

    enrichment = []
    seen = set()

    for value in values:
        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)

        if value in ioc_lookup:
            enrichment.append(
                dict(ioc_lookup[value])
            )

    return enrichment


def normalize_alerts(
    alerts_data,
    user_lookup,
    asset_lookup,
    ioc_lookup
):
    normalized = []

    for alert in alerts_data["alerts"]:
        item = dict(alert)

        item["source_alert_ids"] = [
            alert["alert_id"]
        ]

        item["user_context"] = (
            user_lookup.get(
                alert["user"]
            )
            if alert["user"]
            else None
        )

        item["asset_context"] = (
            asset_lookup.get(
                alert["asset"]
            )
            if alert["asset"]
            else None
        )

        item["ioc_context"] = enrich_iocs(
            alert,
            ioc_lookup
        )

        normalized.append(item)

    normalized.sort(
        key=lambda item: parse_time(
            item["timestamp"]
        )
    )

    return normalized


def matches_dedup_rule(
    first,
    second,
    rule
):
    if (
        first["event_type"]
        not in rule["event_types"]
        or second["event_type"]
        not in rule["event_types"]
    ):
        return False

    if (
        rule["require_same_user"]
        and first["user"]
        != second["user"]
    ):
        return False

    if (
        rule["require_same_asset"]
        and first["asset"]
        != second["asset"]
    ):
        return False

    difference = abs(
        (
            parse_time(first["timestamp"])
            - parse_time(second["timestamp"])
        ).total_seconds()
    )

    return (
        difference
        <= rule[
            "maximum_time_difference_seconds"
        ]
    )


def merge_duplicate_alerts(
    alerts,
    rule
):
    alerts = sorted(
        alerts,
        key=lambda item: parse_time(
            item["timestamp"]
        )
    )

    representative = max(
        alerts,
        key=lambda item: (
            severity_rank(
                item["severity"]
            ),
            item["confidence"]
        )
    )

    merged = dict(representative)

    merged["alert_id"] = (
        "DEDUP-"
        + "-".join(
            item["alert_id"]
            for item in alerts
        )
    )

    merged["source_alert_ids"] = sorted(
        {
            source_id
            for item in alerts
            for source_id
            in item["source_alert_ids"]
        }
    )

    merged["timestamp"] = min(
        item["timestamp"]
        for item in alerts
    )

    merged["event_type"] = rule[
        "retained_event_label"
    ]

    merged["confidence"] = max(
        item["confidence"]
        for item in alerts
    )

    merged["description"] = (
        "Deduplicated related alerts: "
        + " | ".join(
            item["description"]
            for item in alerts
        )
    )

    merged["deduplicated"] = True

    return merged


def deduplicate_alerts(
    alerts,
    rules
):
    if not rules["enabled"]:
        return alerts

    processed = set()
    output = []

    for index, alert in enumerate(alerts):
        if index in processed:
            continue

        matched_group = [
            alert
        ]

        matched_rule = None

        for rule in rules["rules"]:
            candidates = []

            for other_index in range(
                index + 1,
                len(alerts)
            ):
                if other_index in processed:
                    continue

                other = alerts[
                    other_index
                ]

                if matches_dedup_rule(
                    alert,
                    other,
                    rule
                ):
                    candidates.append(
                        (
                            other_index,
                            other
                        )
                    )

            if candidates:
                matched_rule = rule

                for (
                    other_index,
                    other
                ) in candidates:
                    matched_group.append(
                        other
                    )

                    processed.add(
                        other_index
                    )

                break

        processed.add(index)

        if (
            matched_rule
            and len(matched_group) > 1
        ):
            output.append(
                merge_duplicate_alerts(
                    matched_group,
                    matched_rule
                )
            )
        else:
            single = dict(alert)

            single[
                "deduplicated"
            ] = False

            output.append(single)

    output.sort(
        key=lambda item: parse_time(
            item["timestamp"]
        )
    )

    return output


def shared_context(first, second):
    fields = [
        "user",
        "asset",
        "source_ip",
        "indicator"
    ]

    shared = []

    for field in fields:
        first_value = first.get(
            field,
            ""
        )

        second_value = second.get(
            field,
            ""
        )

        if (
            first_value
            and second_value
            and first_value
            == second_value
        ):
            shared.append(
                field
            )

    return shared


def alerts_are_related(
    first,
    second,
    correlation_rules
):
    time_difference = abs(
        (
            parse_time(
                first["timestamp"]
            )
            - parse_time(
                second["timestamp"]
            )
        ).total_seconds()
    )

    allowed_seconds = (
        correlation_rules[
            "time_window_minutes"
        ]
        * 60
    )

    if time_difference > allowed_seconds:
        return False

    shared = shared_context(
        first,
        second
    )

    if (
        correlation_rules[
            "require_shared_context"
        ]
        and not shared
    ):
        return False

    return True


def correlate_alerts(
    alerts,
    correlation_rules
):
    adjacency = {
        index: set()
        for index in range(
            len(alerts)
        )
    }

    for first_index in range(
        len(alerts)
    ):
        for second_index in range(
            first_index + 1,
            len(alerts)
        ):
            if alerts_are_related(
                alerts[first_index],
                alerts[second_index],
                correlation_rules
            ):
                adjacency[
                    first_index
                ].add(
                    second_index
                )

                adjacency[
                    second_index
                ].add(
                    first_index
                )

    visited = set()
    groups = []

    for start in range(
        len(alerts)
    ):
        if start in visited:
            continue

        stack = [
            start
        ]

        component = []

        while stack:
            current = stack.pop()

            if current in visited:
                continue

            visited.add(current)

            component.append(
                alerts[current]
            )

            for neighbor in adjacency[
                current
            ]:
                if neighbor not in visited:
                    stack.append(
                        neighbor
                    )

        component.sort(
            key=lambda item: parse_time(
                item["timestamp"]
            )
        )

        groups.append(component)

    groups.sort(
        key=lambda group: parse_time(
            group[0]["timestamp"]
        )
    )

    return groups


def primary_user_context(alerts):
    for alert in alerts:
        if alert.get(
            "user_context"
        ):
            return alert[
                "user_context"
            ]

    return None


def primary_asset_context(alerts):
    for alert in alerts:
        if alert.get(
            "asset_context"
        ):
            return alert[
                "asset_context"
            ]

    return None


def collect_ioc_context(alerts):
    results = []
    seen = set()

    for alert in alerts:
        for item in alert.get(
            "ioc_context",
            []
        ):
            indicator = item[
                "indicator"
            ]

            if indicator in seen:
                continue

            seen.add(indicator)
            results.append(item)

    return results


def source_alert_ids(alerts):
    return sorted(
        {
            source_id
            for alert in alerts
            for source_id
            in alert[
                "source_alert_ids"
            ]
        }
    )


def calculate_base_severity_score(
    alerts,
    weights
):
    highest_alert = max(
        alerts,
        key=lambda item: severity_rank(
            item["severity"]
        )
    )

    points = weights[
        "base_alert_severity"
    ].get(
        highest_alert["severity"],
        0
    )

    return points, {
        "factor": (
            "Highest alert severity"
        ),
        "value": highest_alert[
            "severity"
        ],
        "points": points
    }


def calculate_user_score(
    user_context,
    weights
):
    points = 0
    factors = []

    if not user_context:
        return points, factors

    user_weights = weights[
        "user_context"
    ]

    if user_context[
        "high_value_identity"
    ]:
        value = user_weights[
            "high_value_identity"
        ]

        points += value

        factors.append({
            "factor": (
                "High-value identity"
            ),
            "points": value
        })

    if user_context[
        "business_impact"
    ] in {
        "High",
        "Critical"
    }:
        value = user_weights[
            "high_business_impact"
        ]

        points += value

        factors.append({
            "factor": (
                "High business impact identity"
            ),
            "points": value
        })

    if (
        user_context[
            "privilege_level"
        ]
        == "Privileged"
    ):
        value = user_weights[
            "privileged_identity"
        ]

        points += value

        factors.append({
            "factor": (
                "Privileged identity"
            ),
            "points": value
        })

    return points, factors


def calculate_asset_score(
    asset_context,
    weights
):
    points = 0
    factors = []

    if not asset_context:
        return points, factors

    asset_weights = weights[
        "asset_context"
    ]

    criticality = asset_context[
        "criticality"
    ]

    if criticality == "Critical":
        value = asset_weights[
            "critical_asset"
        ]

        points += value

        factors.append({
            "factor": (
                "Critical asset"
            ),
            "points": value
        })

    elif criticality == "High":
        value = asset_weights[
            "high_asset"
        ]

        points += value

        factors.append({
            "factor": (
                "High-criticality asset"
            ),
            "points": value
        })

    elif criticality == "Moderate":
        value = asset_weights[
            "moderate_asset"
        ]

        points += value

        factors.append({
            "factor": (
                "Moderate-criticality asset"
            ),
            "points": value
        })

    if (
        asset_context[
            "data_sensitivity"
        ]
        == "High"
    ):
        value = asset_weights[
            "high_data_sensitivity"
        ]

        points += value

        factors.append({
            "factor": (
                "High data sensitivity"
            ),
            "points": value
        })

    return points, factors


def calculate_threat_score(
    ioc_context,
    weights
):
    if not ioc_context:
        return 0, []

    threat_weights = weights[
        "threat_context"
    ]

    candidates = []

    for item in ioc_context:
        if item[
            "known_malicious"
        ]:
            candidates.append({
                "factor": (
                    "Known malicious IOC"
                ),
                "indicator": item[
                    "indicator"
                ],
                "points": threat_weights[
                    "known_malicious_ioc"
                ]
            })

        elif (
            item["reputation"]
            == "High Interest"
        ):
            candidates.append({
                "factor": (
                    "High-interest IOC"
                ),
                "indicator": item[
                    "indicator"
                ],
                "points": threat_weights[
                    "high_interest_ioc"
                ]
            })

        elif (
            item["reputation"]
            == "Unknown External"
        ):
            candidates.append({
                "factor": (
                    "Unknown external IOC"
                ),
                "indicator": item[
                    "indicator"
                ],
                "points": threat_weights[
                    "unknown_external_ioc"
                ]
            })

        elif (
            item["reputation"]
            == "Trusted"
        ):
            candidates.append({
                "factor": (
                    "Trusted IOC reduction"
                ),
                "indicator": item[
                    "indicator"
                ],
                "points": threat_weights[
                    "trusted_ioc_reduction"
                ]
            })

    if not candidates:
        return 0, []

    strongest = max(
        candidates,
        key=lambda item: item[
            "points"
        ]
    )

    return (
        strongest["points"],
        [
            strongest
        ]
    )


def calculate_correlation_score(
    alerts,
    source_ids,
    weights
):
    categories = {
        alert["category"]
        for alert in alerts
    }

    products = {
        alert["source_product"]
        for alert in alerts
    }

    correlation_weights = weights[
        "correlation_context"
    ]

    points = 0
    factors = []

    if len(categories) >= 2:
        value = correlation_weights[
            "multiple_alert_categories"
        ]

        points += value

        factors.append({
            "factor": (
                "Multiple alert categories"
            ),
            "points": value
        })

    if len(products) >= 2:
        value = correlation_weights[
            "multiple_security_products"
        ]

        points += value

        factors.append({
            "factor": (
                "Multiple security products"
            ),
            "points": value
        })

    if {
        "Authentication",
        "Execution"
    }.issubset(categories):
        value = correlation_weights[
            "authentication_plus_execution"
        ]

        points += value

        factors.append({
            "factor": (
                "Authentication plus execution"
            ),
            "points": value
        })

    if {
        "Execution",
        "Network"
    }.issubset(categories):
        value = correlation_weights[
            "execution_plus_network"
        ]

        points += value

        factors.append({
            "factor": (
                "Execution plus network"
            ),
            "points": value
        })

    if {
        "Authentication",
        "Privilege"
    }.issubset(categories):
        value = correlation_weights[
            "identity_plus_privilege"
        ]

        points += value

        factors.append({
            "factor": (
                "Identity plus privilege"
            ),
            "points": value
        })

    if len(source_ids) >= 4:
        value = correlation_weights[
            "related_alert_count_4_or_more"
        ]

        points += value

        factors.append({
            "factor": (
                "Four or more related source alerts"
            ),
            "points": value
        })

    return points, factors


def assign_priority(
    score,
    thresholds
):
    if score >= thresholds[
        "CRITICAL"
    ]:
        return "CRITICAL"

    if score >= thresholds[
        "HIGH"
    ]:
        return "HIGH"

    if score >= thresholds[
        "MODERATE"
    ]:
        return "MODERATE"

    return "LOW"


def select_playbook(
    categories,
    user_context,
    ioc_context,
    rules
):
    if {
        "Authentication",
        "Execution",
        "Network"
    }.issubset(categories):
        return (
            "Finance Compromise Sequence",
            rules[
                "recommended_playbooks"
            ][
                "Finance Compromise Sequence"
            ]
        )

    if categories == {
        "Authentication"
    }:
        return (
            "Low-Risk Authentication Noise",
            rules[
                "recommended_playbooks"
            ][
                "Low-Risk Authentication Noise"
            ]
        )

    trusted_ioc = any(
        item["reputation"]
        == "Trusted"
        for item in ioc_context
    )

    privileged_user = (
        user_context is not None
        and user_context[
            "privilege_level"
        ]
        == "Privileged"
    )

    if (
        categories == {"Network"}
        and trusted_ioc
        and privileged_user
    ):
        return (
            "Trusted Administrative Traffic",
            rules[
                "recommended_playbooks"
            ][
                "Trusted Administrative Traffic"
            ]
        )

    return (
        "General Analyst Review",
        {
            "conditions": sorted(
                categories
            ),
            "recommended_actions": [
                (
                    "Review correlated evidence "
                    "and enrichment context."
                ),
                (
                    "Determine whether additional "
                    "investigation is required."
                )
            ]
        }
    )


def triggered_escalation_conditions(
    categories,
    user_context,
    asset_context,
    ioc_context
):
    triggered = []

    if (
        user_context
        and user_context[
            "high_value_identity"
        ]
    ):
        triggered.append(
            "High-value identity involved"
        )

    if (
        asset_context
        and asset_context[
            "criticality"
        ] in {
            "Critical",
            "High"
        }
    ):
        triggered.append(
            (
                "Critical or high-value "
                "asset involved"
            )
        )

    known_malicious = any(
        item["known_malicious"]
        for item in ioc_context
    )

    if (
        known_malicious
        and "Execution" in categories
    ):
        triggered.append(
            (
                "Known malicious IOC correlated "
                "with endpoint activity"
            )
        )

    if {
        "Authentication",
        "Execution"
    }.issubset(categories):
        triggered.append(
            (
                "Authentication anomalies followed "
                "by suspicious execution"
            )
        )

    if {
        "Execution",
        "Network"
    }.issubset(categories):
        triggered.append(
            (
                "Suspicious execution followed "
                "by external network activity"
            )
        )

    if (
        "Privilege" in categories
        and "Execution" in categories
    ):
        triggered.append(
            (
                "Privilege-related activity follows "
                "suspected compromise"
            )
        )

    return triggered


def build_evidence(alerts):
    evidence = []

    for alert in alerts:
        evidence.append({
            "source_alert_ids": alert[
                "source_alert_ids"
            ],
            "timestamp": alert[
                "timestamp"
            ],
            "source_product": alert[
                "source_product"
            ],
            "category": alert[
                "category"
            ],
            "event_type": alert[
                "event_type"
            ],
            "severity": alert[
                "severity"
            ],
            "confidence": alert[
                "confidence"
            ],
            "description": alert[
                "description"
            ]
        })

    return evidence


def build_assessment(
    priority,
    source_ids,
    categories,
    user_context,
    asset_context
):
    if priority in {
        "CRITICAL",
        "HIGH"
    }:
        return (
            f"{len(source_ids)} related source alerts "
            "were correlated across "
            f"{len(categories)} security categories. "
            "Business and security enrichment increased "
            "the investigation priority. The combined "
            "evidence supports escalation but does not "
            "independently establish the complete "
            "compromise mechanism or prove that every "
            "related alert represents malicious activity."
        )

    if priority == "MODERATE":
        return (
            "Available enrichment raises the importance "
            "of the activity, but the evidence remains "
            "limited and requires analyst review before "
            "containment or escalation decisions are made."
        )

    return (
        "The available evidence has limited correlation "
        "or risk context. Review the enrichment and "
        "close, suppress, or continue monitoring if no "
        "contradictory evidence is identified."
    )


def create_case(
    incident_number,
    alerts,
    rules
):
    user_context = primary_user_context(
        alerts
    )

    asset_context = primary_asset_context(
        alerts
    )

    ioc_context = collect_ioc_context(
        alerts
    )

    source_ids = source_alert_ids(
        alerts
    )

    categories = {
        alert["category"]
        for alert in alerts
    }

    products = {
        alert["source_product"]
        for alert in alerts
    }

    score_factors = []

    base_points, base_factor = (
        calculate_base_severity_score(
            alerts,
            rules["priority_weights"]
        )
    )

    score_factors.append(
        base_factor
    )

    user_points, user_factors = (
        calculate_user_score(
            user_context,
            rules["priority_weights"]
        )
    )

    score_factors.extend(
        user_factors
    )

    asset_points, asset_factors = (
        calculate_asset_score(
            asset_context,
            rules["priority_weights"]
        )
    )

    score_factors.extend(
        asset_factors
    )

    threat_points, threat_factors = (
        calculate_threat_score(
            ioc_context,
            rules["priority_weights"]
        )
    )

    score_factors.extend(
        threat_factors
    )

    correlation_points, correlation_factors = (
        calculate_correlation_score(
            alerts,
            source_ids,
            rules["priority_weights"]
        )
    )

    score_factors.extend(
        correlation_factors
    )

    raw_score = (
        base_points
        + user_points
        + asset_points
        + threat_points
        + correlation_points
    )

    final_score = max(
        0,
        min(
            raw_score,
            100
        )
    )

    priority = assign_priority(
        final_score,
        rules[
            "priority_thresholds"
        ]
    )

    routing = rules[
        "routing"
    ][priority]

    playbook_name, playbook = (
        select_playbook(
            categories,
            user_context,
            ioc_context,
            rules
        )
    )

    escalation_conditions = (
        triggered_escalation_conditions(
            categories,
            user_context,
            asset_context,
            ioc_context
        )
    )

    earliest = min(
        alert["timestamp"]
        for alert in alerts
    )

    latest = max(
        alert["timestamp"]
        for alert in alerts
    )

    case = {
        "incident_id": (
            f"INC-{incident_number:03d}"
        ),
        "priority": priority,
        "priority_score": final_score,
        "raw_priority_score": raw_score,
        "routing": routing,
        "first_alert_time": earliest,
        "last_alert_time": latest,
        "affected_user": (
            user_context["username"]
            if user_context
            else None
        ),
        "affected_asset": (
            asset_context["hostname"]
            if asset_context
            else None
        ),
        "business_context": {
            "user": user_context,
            "asset": asset_context
        },
        "ioc_context": ioc_context,
        "categories": sorted(
            categories
        ),
        "security_products": sorted(
            products
        ),
        "source_alert_count": len(
            source_ids
        ),
        "correlated_alert_count": len(
            alerts
        ),
        "source_alert_ids": source_ids,
        "deduplication_applied": any(
            alert.get(
                "deduplicated",
                False
            )
            for alert in alerts
        ),
        "priority_factors": score_factors,
        "evidence": build_evidence(
            alerts
        ),
        "playbook": {
            "name": playbook_name,
            "recommended_actions": playbook[
                "recommended_actions"
            ]
        },
        "automated_safe_actions": rules[
            "response_actions"
        ][
            "automated_safe_actions"
        ],
        "analyst_approval_required": (
            rules[
                "response_actions"
            ][
                "analyst_approval_required"
            ]
            if priority in {
                "CRITICAL",
                "HIGH"
            }
            else []
        ),
        "triggered_escalation_conditions": (
            escalation_conditions
        ),
        "analyst_assessment": (
            build_assessment(
                priority,
                source_ids,
                categories,
                user_context,
                asset_context
            )
        ),
        "analyst_guardrails": rules[
            "analyst_guardrails"
        ]
    }

    return case


def process_cases(
    correlated_groups,
    rules
):
    cases = []

    for number, group in enumerate(
        correlated_groups,
        start=1
    ):
        cases.append(
            create_case(
                number,
                group,
                rules
            )
        )

    return cases


def export_results(
    normalized_alerts,
    deduplicated_alerts,
    cases
):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    alert_report = {
        "summary": {
            "raw_alert_count": sum(
                len(
                    alert[
                        "source_alert_ids"
                    ]
                )
                for alert
                in deduplicated_alerts
            ),
            "normalized_alert_count": len(
                normalized_alerts
            ),
            "post_deduplication_count": len(
                deduplicated_alerts
            )
        },
        "alerts": deduplicated_alerts
    }

    with open(
        ALERT_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            alert_report,
            file,
            indent=2
        )

    case_report = {
        "summary": {
            "incident_count": len(
                cases
            ),
            "critical": sum(
                1
                for case in cases
                if case["priority"]
                == "CRITICAL"
            ),
            "high": sum(
                1
                for case in cases
                if case["priority"]
                == "HIGH"
            ),
            "moderate": sum(
                1
                for case in cases
                if case["priority"]
                == "MODERATE"
            ),
            "low": sum(
                1
                for case in cases
                if case["priority"]
                == "LOW"
            )
        },
        "cases": cases
    }

    with open(
        CASE_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            case_report,
            file,
            indent=2
        )

    fieldnames = [
        "incident_id",
        "priority",
        "priority_score",
        "routing",
        "affected_user",
        "affected_asset",
        "source_alert_count",
        "correlated_alert_count",
        "categories",
        "playbook",
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

        for case in cases:
            writer.writerow({
                "incident_id": case[
                    "incident_id"
                ],
                "priority": case[
                    "priority"
                ],
                "priority_score": case[
                    "priority_score"
                ],
                "routing": case[
                    "routing"
                ],
                "affected_user": case[
                    "affected_user"
                ],
                "affected_asset": case[
                    "affected_asset"
                ],
                "source_alert_count": case[
                    "source_alert_count"
                ],
                "correlated_alert_count": case[
                    "correlated_alert_count"
                ],
                "categories": " | ".join(
                    case["categories"]
                ),
                "playbook": case[
                    "playbook"
                ]["name"],
                "analyst_assessment": case[
                    "analyst_assessment"
                ]
            })


def print_results(
    raw_alert_count,
    deduplicated_alerts,
    cases
):
    print()
    print("=" * 96)
    print(
        "SOC ALERT ENRICHMENT & "
        "RESPONSE AUTOMATION LAB"
    )
    print("=" * 96)

    print(
        f"Raw alerts:              "
        f"{raw_alert_count}"
    )

    print(
        f"After deduplication:      "
        f"{len(deduplicated_alerts)}"
    )

    print(
        f"Analyst incident cases:   "
        f"{len(cases)}"
    )

    print("-" * 96)

    for case in cases:
        print(
            f"{case['incident_id']} | "
            f"{case['priority']:<8} | "
            f"Score {case['priority_score']:>3} | "
            f"User: "
            f"{case['affected_user'] or 'N/A':<15} | "
            f"Asset: "
            f"{case['affected_asset'] or 'N/A'}"
        )

        print(
            f"          "
            f"Source Alerts: "
            f"{case['source_alert_count']} | "
            f"Correlated Alerts: "
            f"{case['correlated_alert_count']} | "
            f"Route: {case['routing']}"
        )

        print(
            f"          "
            f"Playbook: "
            f"{case['playbook']['name']}"
        )

    print("=" * 96)

    print(
        f"Normalized alerts: "
        f"{ALERT_OUTPUT}"
    )

    print(
        f"Incident cases:    "
        f"{CASE_OUTPUT}"
    )

    print(
        f"CSV summary:       "
        f"{CSV_OUTPUT}"
    )

    print("=" * 96)


def main():
    alerts_data = load_json(
        ALERTS_FILE
    )

    users_data = load_json(
        USERS_FILE
    )

    assets_data = load_json(
        ASSETS_FILE
    )

    ioc_data = load_json(
        IOC_FILE
    )

    rules = load_json(
        RULES_FILE
    )

    (
        user_lookup,
        asset_lookup,
        ioc_lookup
    ) = build_lookups(
        users_data,
        assets_data,
        ioc_data
    )

    normalized_alerts = normalize_alerts(
        alerts_data,
        user_lookup,
        asset_lookup,
        ioc_lookup
    )

    deduplicated_alerts = deduplicate_alerts(
        normalized_alerts,
        rules["deduplication"]
    )

    correlated_groups = correlate_alerts(
        deduplicated_alerts,
        rules["correlation"]
    )

    cases = process_cases(
        correlated_groups,
        rules
    )

    export_results(
        normalized_alerts,
        deduplicated_alerts,
        cases
    )

    print_results(
        len(alerts_data["alerts"]),
        deduplicated_alerts,
        cases
    )


if __name__ == "__main__":
    main()
