import csv
import json

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

SAMPLE_DATA_DIR = (
    BASE_DIR
    / "sample-data"
)

CONFIG_DIR = (
    BASE_DIR
    / "config"
)

OUTPUT_DIR = (
    BASE_DIR
    / "output"
)

USERS_FILE = (
    SAMPLE_DATA_DIR
    / "users.json"
)

AUTHORIZED_OBJECTS_FILE = (
    SAMPLE_DATA_DIR
    / "authorized_objects.json"
)

API_REQUESTS_FILE = (
    SAMPLE_DATA_DIR
    / "api_requests.json"
)

POLICY_FILE = (
    CONFIG_DIR
    / "detection_policy.json"
)

NORMALIZED_OUTPUT = (
    OUTPUT_DIR
    / "normalized_api_events.json"
)

FINDINGS_OUTPUT = (
    OUTPUT_DIR
    / "api_findings.json"
)

FINDINGS_CSV = (
    OUTPUT_DIR
    / "api_findings_summary.csv"
)

USER_SUMMARY_OUTPUT = (
    OUTPUT_DIR
    / "user_activity_summary.json"
)

TOKEN_SUMMARY_OUTPUT = (
    OUTPUT_DIR
    / "token_activity_summary.json"
)


def load_json(file_path):
    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def normalize_text(value):
    if value is None:
        return None

    text = str(
        value
    ).strip()

    if not text:
        return None

    return text


def parse_timestamp(value):
    text = normalize_text(
        value
    )

    if text is None:
        return None

    try:
        parsed = datetime.fromisoformat(
            text.replace(
                "Z",
                "+00:00"
            )
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )

    except ValueError:
        return None


def normalize_timestamp(value):
    parsed = parse_timestamp(
        value
    )

    if parsed is None:
        return None

    return (
        parsed
        .isoformat()
        .replace(
            "+00:00",
            "Z"
        )
    )


def unique_values(values):
    seen = set()
    result = []

    for value in values:
        if value is None:
            continue

        if value not in seen:
            seen.add(
                value
            )

            result.append(
                value
            )

    return result


def build_user_lookup(
    users
):
    return {
        user[
            "user"
        ].lower(): user
        for user in users
    }


def identify_resource_type(
    endpoint
):
    if endpoint is None:
        return "unknown"

    if endpoint.startswith(
        "/api/accounts/"
    ):
        return "accounts"

    if endpoint.startswith(
        "/api/invoices/"
    ):
        return "invoices"

    if endpoint.startswith(
        "/api/reports/"
    ):
        return "reports"

    if endpoint.startswith(
        "/api/admin/"
    ):
        return "admin"

    if endpoint.startswith(
        "/api/auth/"
    ):
        return "authentication"

    return "other"


def source_ip_is_expected(
    source_ip,
    user_record
):
    if user_record is None:
        return False

    expected_ips = user_record.get(
        "expected_source_ips",
        []
    )

    return (
        source_ip
        in expected_ips
    )


def object_is_authorized(
    user,
    resource_type,
    object_id,
    authorized_objects
):
    if object_id is None:
        return None

    if resource_type not in {
        "accounts",
        "invoices",
        "reports"
    }:
        return None

    permissions = (
        authorized_objects.get(
            resource_type,
            {}
        )
    )

    allowed_objects = (
        permissions.get(
            user,
            []
        )
    )

    return (
        object_id
        in allowed_objects
    )


def normalize_event(
    raw_event,
    user_lookup,
    authorized_objects
):
    user = normalize_text(
        raw_event.get(
            "user"
        )
    )

    if user:
        user = user.lower()

    user_record = (
        user_lookup.get(
            user
        )
        if user
        else None
    )

    endpoint = normalize_text(
        raw_event.get(
            "endpoint"
        )
    )

    resource_type = (
        identify_resource_type(
            endpoint
        )
    )

    object_id = normalize_text(
        raw_event.get(
            "object_id"
        )
    )

    source_ip = normalize_text(
        raw_event.get(
            "source_ip"
        )
    )

    role = None
    department = None

    if user_record:
        role = user_record.get(
            "role"
        )

        department = user_record.get(
            "department"
        )

    normalized = {
        "timestamp": (
            normalize_timestamp(
                raw_event.get(
                    "timestamp"
                )
            )
        ),
        "request_id": (
            normalize_text(
                raw_event.get(
                    "request_id"
                )
            )
        ),
        "source_ip": source_ip,
        "source_ip_expected": (
            source_ip_is_expected(
                source_ip,
                user_record
            )
        ),
        "user": user,
        "role": role,
        "department": department,
        "token_id": (
            normalize_text(
                raw_event.get(
                    "token_id"
                )
            )
        ),
        "http_method": (
            normalize_text(
                raw_event.get(
                    "http_method"
                )
            )
        ),
        "endpoint": endpoint,
        "resource_type": (
            resource_type
        ),
        "object_id": object_id,
        "object_in_expected_scope": (
            object_is_authorized(
                user,
                resource_type,
                object_id,
                authorized_objects
            )
            if user
            else None
        ),
        "response_status": (
            raw_event.get(
                "response_status"
            )
        ),
        "response_bytes": (
            raw_event.get(
                "response_bytes"
            )
        ),
        "user_agent": (
            normalize_text(
                raw_event.get(
                    "user_agent"
                )
            )
        ),
        "authentication_result": (
            normalize_text(
                raw_event.get(
                    "authentication_result"
                )
            )
        ),
        "authorization_result": (
            normalize_text(
                raw_event.get(
                    "authorization_result"
                )
            )
        )
    }

    if normalized[
        "http_method"
    ]:
        normalized[
            "http_method"
        ] = normalized[
            "http_method"
        ].upper()

    if normalized[
        "authentication_result"
    ]:
        normalized[
            "authentication_result"
        ] = normalized[
            "authentication_result"
        ].lower()

    if normalized[
        "authorization_result"
    ]:
        normalized[
            "authorization_result"
        ] = normalized[
            "authorization_result"
        ].lower()

    return normalized


def normalize_events(
    api_requests,
    users,
    authorized_objects
):
    user_lookup = (
        build_user_lookup(
            users
        )
    )

    return [
        normalize_event(
            event,
            user_lookup,
            authorized_objects
        )
        for event in api_requests
    ]


def seconds_between(
    first_event,
    second_event
):
    first = parse_timestamp(
        first_event[
            "timestamp"
        ]
    )

    second = parse_timestamp(
        second_event[
            "timestamp"
        ]
    )

    if (
        first is None
        or second is None
    ):
        return None

    return int(
        (
            second
            - first
        ).total_seconds()
    )


def make_finding(
    finding_id,
    title,
    severity,
    user,
    events,
    indicators,
    assessment,
    owasp_mapping,
    guardrail
):
    events = sorted(
        events,
        key=lambda event: (
            event[
                "timestamp"
            ]
            or ""
        )
    )

    return {
        "finding_id": finding_id,
        "title": title,
        "severity": severity,
        "user": user,
        "source_ips": unique_values(
            event[
                "source_ip"
            ]
            for event in events
        ),
        "affected_endpoints": (
            unique_values(
                event[
                    "endpoint"
                ]
                for event in events
            )
        ),
        "first_seen": (
            events[0][
                "timestamp"
            ]
            if events
            else None
        ),
        "last_seen": (
            events[-1][
                "timestamp"
            ]
            if events
            else None
        ),
        "supporting_request_ids": (
            [
                event[
                    "request_id"
                ]
                for event in events
            ]
        ),
        "supporting_event_count": (
            len(
                events
            )
        ),
        "observed_indicators": (
            indicators
        ),
        "assessment": assessment,
        "owasp_mapping": (
            owasp_mapping
        ),
        "guardrail": guardrail
    }


def detect_authentication_abuse(
    events,
    policy
):
    config = policy[
        "authentication_abuse"
    ]

    grouped = defaultdict(
        list
    )

    for event in events:
        if event[
            "endpoint"
        ] == config[
            "login_endpoint"
        ]:
            grouped[
                event[
                    "user"
                ]
            ].append(
                event
            )

    findings = []

    for user, user_events in grouped.items():
        failures = sorted(
            [
                event
                for event in user_events
                if event[
                    "authentication_result"
                ]
                == config[
                    "failure_value"
                ]
            ],
            key=lambda event: (
                event[
                    "timestamp"
                ]
            )
        )

        successes = sorted(
            [
                event
                for event in user_events
                if event[
                    "authentication_result"
                ]
                == config[
                    "success_value"
                ]
            ],
            key=lambda event: (
                event[
                    "timestamp"
                ]
            )
        )

        for index, first_failure in enumerate(
            failures
        ):
            failure_cluster = []

            for failure in failures[
                index:
            ]:
                elapsed = seconds_between(
                    first_failure,
                    failure
                )

                if (
                    elapsed is not None
                    and elapsed
                    <= config[
                        "failure_window_seconds"
                    ]
                ):
                    failure_cluster.append(
                        failure
                    )

            if len(
                failure_cluster
            ) < config[
                "failure_threshold"
            ]:
                continue

            last_failure = (
                failure_cluster[-1]
            )

            matching_success = None

            for success in successes:
                delay = seconds_between(
                    last_failure,
                    success
                )

                if (
                    delay is not None
                    and 0 <= delay
                    <= config[
                        "success_after_failures_seconds"
                    ]
                ):
                    matching_success = success
                    break

            supporting = list(
                failure_cluster
            )

            indicators = [
                (
                    f"{len(failure_cluster)} "
                    f"failed authentication "
                    f"attempts observed within "
                    f"{seconds_between(first_failure, last_failure)} "
                    f"seconds."
                )
            ]

            if matching_success:
                supporting.append(
                    matching_success
                )

                indicators.append(
                    (
                        "Successful authentication "
                        f"occurred "
                        f"{seconds_between(last_failure, matching_success)} "
                        "seconds after the final failure."
                    )
                )

            findings.append(
                make_finding(
                    policy[
                        "finding_ids"
                    ][
                        "authentication_abuse"
                    ],
                    "Repeated Authentication Failures",
                    config[
                        "severity"
                    ],
                    user,
                    supporting,
                    indicators,
                    (
                        "Repeated authentication "
                        "failures exceeded the "
                        "configured threshold."
                    ),
                    config[
                        "owasp_mapping"
                    ],
                    policy[
                        "analyst_guardrails"
                    ][
                        "authentication_abuse"
                    ]
                )
            )

            break

    return findings


def detect_object_authorization(
    events,
    policy
):
    config = policy[
        "object_authorization"
    ]

    grouped = defaultdict(
        list
    )

    for event in events:
        if (
            event[
                "object_in_expected_scope"
            ]
            is False
        ):
            grouped[
                event[
                    "user"
                ]
            ].append(
                event
            )

    findings = []

    for user, unauthorized in grouped.items():
        if len(
            unauthorized
        ) < config[
            "unauthorized_attempt_threshold"
        ]:
            continue

        findings.append(
            make_finding(
                policy[
                    "finding_ids"
                ][
                    "object_authorization"
                ],
                "Unauthorized Object Access Pattern",
                config[
                    "severity"
                ],
                user,
                unauthorized,
                [
                    (
                        f"{len(unauthorized)} "
                        "requests targeted objects "
                        "outside the user's expected "
                        "authorization scope."
                    ),
                    (
                        f"{sum(1 for event in unauthorized if event['authorization_result'] == config['authorization_denied_value'])} "
                        "requests were explicitly "
                        "denied by the API."
                    )
                ],
                (
                    "The user repeatedly requested "
                    "protected objects outside the "
                    "configured authorization scope."
                ),
                config[
                    "owasp_mapping"
                ],
                policy[
                    "analyst_guardrails"
                ][
                    "object_authorization"
                ]
            )
        )

    return findings


def detect_token_reuse(
    events,
    policy
):
    config = policy[
        "token_reuse"
    ]

    grouped = defaultdict(
        list
    )

    for event in events:
        if event[
            "token_id"
        ]:
            grouped[
                event[
                    "token_id"
                ]
            ].append(
                event
            )

    findings = []

    for token_id, token_events in grouped.items():
        token_events = sorted(
            token_events,
            key=lambda event: (
                event[
                    "timestamp"
                ]
            )
        )

        best_cluster = []

        for index, first_event in enumerate(
            token_events
        ):
            cluster = []

            for event in token_events[
                index:
            ]:
                elapsed = seconds_between(
                    first_event,
                    event
                )

                if (
                    elapsed is not None
                    and elapsed
                    <= config[
                        "window_seconds"
                    ]
                ):
                    cluster.append(
                        event
                    )

            source_ips = {
                event[
                    "source_ip"
                ]
                for event in cluster
                if event[
                    "source_ip"
                ]
            }

            unexpected = [
                event
                for event in cluster
                if not event[
                    "source_ip_expected"
                ]
            ]

            meets_ip_threshold = (
                len(
                    source_ips
                )
                >= config[
                    "minimum_distinct_source_ips"
                ]
            )

            meets_unexpected_rule = (
                bool(
                    unexpected
                )
                if config[
                    "require_unexpected_source_ip"
                ]
                else True
            )

            if (
                meets_ip_threshold
                and meets_unexpected_rule
                and len(cluster)
                > len(best_cluster)
            ):
                best_cluster = (
                    cluster
                )

        if not best_cluster:
            continue

        user = best_cluster[0][
            "user"
        ]

        source_ips = unique_values(
            event[
                "source_ip"
            ]
            for event in best_cluster
        )

        unexpected_count = sum(
            1
            for event in best_cluster
            if not event[
                "source_ip_expected"
            ]
        )

        findings.append(
            make_finding(
                policy[
                    "finding_ids"
                ][
                    "token_reuse"
                ],
                "Suspicious Token Reuse",
                config[
                    "severity"
                ],
                user,
                best_cluster,
                [
                    (
                        f"Token {token_id} was "
                        f"observed from "
                        f"{len(source_ips)} distinct "
                        "source IP addresses."
                    ),
                    (
                        f"{unexpected_count} token "
                        "uses originated from an "
                        "unexpected source IP."
                    )
                ],
                (
                    "The same authentication token "
                    "was reused across multiple "
                    "source addresses within the "
                    "configured analysis window."
                ),
                config[
                    "owasp_mapping"
                ],
                policy[
                    "analyst_guardrails"
                ][
                    "token_reuse"
                ]
            )
        )

    return findings


def longest_sequential_run(
    object_ids
):
    numeric_ids = sorted({
        int(
            object_id
        )
        for object_id in object_ids
        if (
            object_id
            and object_id.isdigit()
        )
    })

    if not numeric_ids:
        return 0

    longest = 1
    current = 1

    for index in range(
        1,
        len(
            numeric_ids
        )
    ):
        if (
            numeric_ids[index]
            ==
            numeric_ids[index - 1]
            + 1
        ):
            current += 1

            longest = max(
                longest,
                current
            )

        else:
            current = 1

    return longest


def detect_object_enumeration(
    events,
    policy
):
    config = policy[
        "object_enumeration"
    ]

    grouped = defaultdict(
        list
    )

    for event in events:
        if (
            event[
                "resource_type"
            ]
            == config[
                "resource"
            ]
            and event[
                "endpoint"
            ]
            and event[
                "endpoint"
            ].startswith(
                config[
                    "endpoint_prefix"
                ]
            )
        ):
            grouped[
                event[
                    "user"
                ]
            ].append(
                event
            )

    findings = []

    for user, user_events in grouped.items():
        user_events = sorted(
            user_events,
            key=lambda event: (
                event[
                    "timestamp"
                ]
            )
        )

        best_cluster = []
        best_run = 0

        for index, first_event in enumerate(
            user_events
        ):
            cluster = []

            for event in user_events[
                index:
            ]:
                elapsed = seconds_between(
                    first_event,
                    event
                )

                if (
                    elapsed is not None
                    and elapsed
                    <= config[
                        "window_seconds"
                    ]
                ):
                    cluster.append(
                        event
                    )

            distinct_objects = {
                event[
                    "object_id"
                ]
                for event in cluster
                if event[
                    "object_id"
                ]
            }

            sequential_run = (
                longest_sequential_run(
                    distinct_objects
                )
            )

            if (
                len(
                    distinct_objects
                )
                >= config[
                    "minimum_distinct_objects"
                ]
                and sequential_run
                >= config[
                    "minimum_sequential_run"
                ]
                and len(cluster)
                > len(best_cluster)
            ):
                best_cluster = cluster
                best_run = sequential_run

        if not best_cluster:
            continue

        object_ids = unique_values(
            event[
                "object_id"
            ]
            for event in best_cluster
        )

        duration = seconds_between(
            best_cluster[0],
            best_cluster[-1]
        )

        findings.append(
            make_finding(
                policy[
                    "finding_ids"
                ][
                    "object_enumeration"
                ],
                "Sequential Object Enumeration",
                config[
                    "severity"
                ],
                user,
                best_cluster,
                [
                    (
                        f"{len(object_ids)} distinct "
                        "account objects were "
                        f"requested within "
                        f"{duration} seconds."
                    ),
                    (
                        f"Longest sequential object "
                        f"run: {best_run}."
                    )
                ],
                (
                    "The request sequence shows "
                    "rapid access to multiple "
                    "sequential account identifiers."
                ),
                config[
                    "owasp_mapping"
                ],
                policy[
                    "analyst_guardrails"
                ][
                    "object_enumeration"
                ]
            )
        )

    return findings


def detect_administrative_access(
    events,
    policy
):
    config = policy[
        "administrative_access"
    ]

    grouped = defaultdict(
        list
    )

    for event in events:
        endpoint = event[
            "endpoint"
        ]

        if (
            endpoint
            and endpoint.startswith(
                config[
                    "endpoint_prefix"
                ]
            )
            and event[
                "role"
            ]
            not in config[
                "approved_roles"
            ]
        ):
            grouped[
                event[
                    "user"
                ]
            ].append(
                event
            )

    findings = []

    for user, admin_events in grouped.items():
        findings.append(
            make_finding(
                policy[
                    "finding_ids"
                ][
                    "administrative_access"
                ],
                (
                    "Unauthorized Administrative "
                    "Endpoint Access"
                ),
                config[
                    "severity"
                ],
                user,
                admin_events,
                [
                    (
                        f"{len(admin_events)} "
                        "administrative API request "
                        "was made by a role not "
                        "approved for admin access."
                    )
                ],
                (
                    "A non-administrator attempted "
                    "to access an administrative "
                    "API function."
                ),
                config[
                    "owasp_mapping"
                ],
                policy[
                    "analyst_guardrails"
                ][
                    "administrative_access"
                ]
            )
        )

    return findings


def detect_rate_abuse(
    events,
    policy
):
    config = policy[
        "rate_abuse"
    ]

    grouped = defaultdict(
        list
    )

    for event in events:
        grouped[
            event[
                "user"
            ]
        ].append(
            event
        )

    findings = []

    for user, user_events in grouped.items():
        user_events = sorted(
            user_events,
            key=lambda event: (
                event[
                    "timestamp"
                ]
            )
        )

        best_cluster = []

        for index, first_event in enumerate(
            user_events
        ):
            cluster = []

            for event in user_events[
                index:
            ]:
                elapsed = seconds_between(
                    first_event,
                    event
                )

                if (
                    elapsed is not None
                    and elapsed
                    <= config[
                        "window_seconds"
                    ]
                ):
                    cluster.append(
                        event
                    )

            if len(
                cluster
            ) > len(
                best_cluster
            ):
                best_cluster = cluster

        if len(
            best_cluster
        ) < config[
            "request_threshold"
        ]:
            continue

        duration = seconds_between(
            best_cluster[0],
            best_cluster[-1]
        )

        findings.append(
            make_finding(
                policy[
                    "finding_ids"
                ][
                    "rate_abuse"
                ],
                "Excessive API Request Rate",
                config[
                    "severity"
                ],
                user,
                best_cluster,
                [
                    (
                        f"{len(best_cluster)} API "
                        f"requests occurred within "
                        f"{duration} seconds."
                    ),
                    (
                        "Configured threshold: "
                        f"{config['request_threshold']} "
                        "requests within "
                        f"{config['window_seconds']} "
                        "seconds."
                    )
                ],
                (
                    "The user's API request rate "
                    "exceeded the configured "
                    "analysis threshold."
                ),
                config[
                    "owasp_mapping"
                ],
                policy[
                    "analyst_guardrails"
                ][
                    "rate_abuse"
                ]
            )
        )

    return findings


def generate_findings(
    events,
    policy
):
    findings = []

    findings.extend(
        detect_authentication_abuse(
            events,
            policy
        )
    )

    findings.extend(
        detect_object_authorization(
            events,
            policy
        )
    )

    findings.extend(
        detect_token_reuse(
            events,
            policy
        )
    )

    findings.extend(
        detect_object_enumeration(
            events,
            policy
        )
    )

    findings.extend(
        detect_administrative_access(
            events,
            policy
        )
    )

    findings.extend(
        detect_rate_abuse(
            events,
            policy
        )
    )

    return findings


def build_user_activity_summary(
    events
):
    grouped = defaultdict(
        list
    )

    for event in events:
        grouped[
            event[
                "user"
            ]
        ].append(
            event
        )

    summaries = []

    for user, user_events in sorted(
        grouped.items()
    ):
        summaries.append({
            "user": user,
            "role": (
                user_events[0][
                    "role"
                ]
            ),
            "request_count": len(
                user_events
            ),
            "failed_authentication_count": (
                sum(
                    1
                    for event in user_events
                    if event[
                        "authentication_result"
                    ]
                    == "failure"
                )
            ),
            "authorization_denied_count": (
                sum(
                    1
                    for event in user_events
                    if event[
                        "authorization_result"
                    ]
                    == "denied"
                )
            ),
            "unexpected_source_count": (
                sum(
                    1
                    for event in user_events
                    if not event[
                        "source_ip_expected"
                    ]
                )
            ),
            "out_of_scope_object_count": (
                sum(
                    1
                    for event in user_events
                    if event[
                        "object_in_expected_scope"
                    ]
                    is False
                )
            ),
            "distinct_endpoints": (
                len({
                    event[
                        "endpoint"
                    ]
                    for event in user_events
                    if event[
                        "endpoint"
                    ]
                })
            )
        })

    return summaries


def build_token_activity_summary(
    events
):
    grouped = defaultdict(
        list
    )

    for event in events:
        if event[
            "token_id"
        ]:
            grouped[
                event[
                    "token_id"
                ]
            ].append(
                event
            )

    summaries = []

    for token_id, token_events in sorted(
        grouped.items()
    ):
        summaries.append({
            "token_id": token_id,
            "request_count": len(
                token_events
            ),
            "users": unique_values(
                event[
                    "user"
                ]
                for event in token_events
            ),
            "source_ips": unique_values(
                event[
                    "source_ip"
                ]
                for event in token_events
            ),
            "unexpected_source_event_count": (
                sum(
                    1
                    for event in token_events
                    if not event[
                        "source_ip_expected"
                    ]
                )
            )
        })

    return summaries


def export_json(
    file_path,
    data
):
    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            data,
            file,
            indent=2
        )


def export_findings_csv(
    findings
):
    fieldnames = [
        "finding_id",
        "title",
        "severity",
        "user",
        "source_ips",
        "affected_endpoints",
        "supporting_event_count",
        "supporting_request_ids",
        "owasp_mapping",
        "assessment",
        "guardrail"
    ]

    with open(
        FINDINGS_CSV,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for finding in findings:
            writer.writerow({
                "finding_id": (
                    finding[
                        "finding_id"
                    ]
                ),
                "title": (
                    finding[
                        "title"
                    ]
                ),
                "severity": (
                    finding[
                        "severity"
                    ]
                ),
                "user": (
                    finding[
                        "user"
                    ]
                ),
                "source_ips": (
                    "; ".join(
                        finding[
                            "source_ips"
                        ]
                    )
                ),
                "affected_endpoints": (
                    "; ".join(
                        finding[
                            "affected_endpoints"
                        ]
                    )
                ),
                "supporting_event_count": (
                    finding[
                        "supporting_event_count"
                    ]
                ),
                "supporting_request_ids": (
                    "; ".join(
                        finding[
                            "supporting_request_ids"
                        ]
                    )
                ),
                "owasp_mapping": (
                    "; ".join(
                        finding[
                            "owasp_mapping"
                        ]
                    )
                ),
                "assessment": (
                    finding[
                        "assessment"
                    ]
                ),
                "guardrail": (
                    finding[
                        "guardrail"
                    ]
                )
            })


def print_summary(
    events,
    findings
):
    print()
    print("=" * 82)

    print(
        "API SECURITY ASSESSMENT "
        "AND ABUSE DETECTION"
    )

    print("=" * 82)

    print(
        f"Normalized API events: "
        f"{len(events)}"
    )

    print(
        f"Security findings:     "
        f"{len(findings)}"
    )

    print("=" * 82)

    for finding in findings:
        print(
            f"{finding['finding_id']} | "
            f"{finding['severity']:<6} | "
            f"{finding['title']}"
        )

        print(
            f"         User: "
            f"{finding['user']}"
        )

        print(
            f"         Evidence: "
            f"{finding['supporting_event_count']} "
            f"requests"
        )

    print("=" * 82)

    print(
        f"Normalized events: "
        f"{NORMALIZED_OUTPUT}"
    )

    print(
        f"Findings JSON:     "
        f"{FINDINGS_OUTPUT}"
    )

    print(
        f"Findings CSV:      "
        f"{FINDINGS_CSV}"
    )

    print(
        f"User summary:      "
        f"{USER_SUMMARY_OUTPUT}"
    )

    print(
        f"Token summary:     "
        f"{TOKEN_SUMMARY_OUTPUT}"
    )

    print("=" * 82)


def main():
    OUTPUT_DIR.mkdir(
        exist_ok=True
    )

    users = load_json(
        USERS_FILE
    )

    authorized_objects = load_json(
        AUTHORIZED_OBJECTS_FILE
    )

    api_requests = load_json(
        API_REQUESTS_FILE
    )

    policy = load_json(
        POLICY_FILE
    )

    normalized_events = (
        normalize_events(
            api_requests,
            users,
            authorized_objects
        )
    )

    findings = generate_findings(
        normalized_events,
        policy
    )

    user_summary = (
        build_user_activity_summary(
            normalized_events
        )
    )

    token_summary = (
        build_token_activity_summary(
            normalized_events
        )
    )

    export_json(
        NORMALIZED_OUTPUT,
        {
            "event_count": len(
                normalized_events
            ),
            "events": normalized_events
        }
    )

    export_json(
        FINDINGS_OUTPUT,
        {
            "finding_count": len(
                findings
            ),
            "findings": findings
        }
    )

    export_findings_csv(
        findings
    )

    export_json(
        USER_SUMMARY_OUTPUT,
        {
            "user_count": len(
                user_summary
            ),
            "users": user_summary
        }
    )

    export_json(
        TOKEN_SUMMARY_OUTPUT,
        {
            "token_count": len(
                token_summary
            ),
            "tokens": token_summary
        }
    )

    print_summary(
        normalized_events,
        findings
    )


if __name__ == "__main__":
    main()
