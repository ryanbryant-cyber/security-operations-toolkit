import csv
import ipaddress
import json

from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

SAMPLE_DATA_DIR = (
    BASE_DIR
    / "sample-data"
)

MAPPINGS_FILE = (
    BASE_DIR
    / "mappings"
    / "schema_mappings.json"
)

QUALITY_RULES_FILE = (
    BASE_DIR
    / "rules"
    / "quality_rules.json"
)

OUTPUT_DIR = (
    BASE_DIR
    / "output"
)


def load_json(file_path):
    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def load_configuration():
    mappings = load_json(
        MAPPINGS_FILE
    )

    quality_rules = load_json(
        QUALITY_RULES_FILE
    )

    return mappings, quality_rules


def discover_telemetry_files():
    return sorted(
        SAMPLE_DATA_DIR.glob("*.json")
    )


def load_telemetry():
    telemetry_sources = []

    for file_path in discover_telemetry_files():
        data = load_json(
            file_path
        )

        telemetry_sources.append({
            "file_name": file_path.name,
            "source": data.get(
                "source"
            ),
            "events": data.get(
                "events",
                []
            )
        })

    return telemetry_sources


def utc_now():
    return (
        datetime.now(
            timezone.utc
        )
        .isoformat()
        .replace(
            "+00:00",
            "Z"
        )
    )


def is_blank(value):
    if value is None:
        return True

    if isinstance(
        value,
        str
    ):
        return not value.strip()

    return False


def add_issue(
    issues,
    issue_type,
    field,
    details
):
    issues.append({
        "issue_type": issue_type,
        "field": field,
        "details": details
    })


def normalize_text(value):
    if is_blank(value):
        return None

    return str(value).strip()


def normalize_host(value):
    text = normalize_text(
        value
    )

    if text is None:
        return None

    return text.upper()


def normalize_user(value):
    text = normalize_text(
        value
    )

    if text is None:
        return None

    if "\\" in text:
        text = text.split(
            "\\",
            1
        )[1]

    if "@" in text:
        text = text.split(
            "@",
            1
        )[0]

    return text.lower()


def normalize_timestamp(value):
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

        parsed = parsed.astimezone(
            timezone.utc
        )

        return (
            parsed
            .isoformat()
            .replace(
                "+00:00",
                "Z"
            )
        )

    except ValueError:
        return None


def normalize_ip(value):
    text = normalize_text(
        value
    )

    if text is None:
        return None

    try:
        return str(
            ipaddress.ip_address(
                text
            )
        )

    except ValueError:
        return None


def normalize_severity(
    source_name,
    raw_value,
    quality_rules
):
    text = normalize_text(
        raw_value
    )

    if text is None:
        return None

    source_map = (
        quality_rules[
            "severity_normalization"
        ]
        .get(
            source_name,
            {}
        )
    )

    return source_map.get(
        text
    )


def get_raw_value(
    raw_event,
    source_mapping,
    normalized_field
):
    raw_field = source_mapping.get(
        normalized_field
    )

    if raw_field is None:
        return None

    return raw_event.get(
        raw_field
    )


def calculate_quality_score(
    issues,
    quality_rules
):
    score = quality_rules[
        "maximum_quality_score"
    ]

    penalties = quality_rules[
        "quality_penalties"
    ]

    for issue in issues:
        score -= penalties.get(
            issue[
                "issue_type"
            ],
            0
        )

    return max(
        quality_rules[
            "minimum_quality_score"
        ],
        min(
            quality_rules[
                "maximum_quality_score"
            ],
            score
        )
    )


def determine_status(
    issues,
    quality_rules
):
    fatal_issues = set(
        quality_rules[
            "fatal_issues"
        ]
    )

    event_issue_types = {
        issue["issue_type"]
        for issue in issues
    }

    if fatal_issues.intersection(
        event_issue_types
    ):
        return "INVALID"

    return "VALID"


def normalize_event(
    source_name,
    raw_event,
    source_mapping,
    quality_rules
):
    issues = []

    raw_values = {
        "timestamp": get_raw_value(
            raw_event,
            source_mapping,
            "timestamp"
        ),
        "event_source": source_name,
        "event_category": (
            source_mapping.get(
                "event_category"
            )
        ),
        "host": get_raw_value(
            raw_event,
            source_mapping,
            "host"
        ),
        "user": get_raw_value(
            raw_event,
            source_mapping,
            "user"
        ),
        "source_ip": get_raw_value(
            raw_event,
            source_mapping,
            "source_ip"
        ),
        "destination_ip": get_raw_value(
            raw_event,
            source_mapping,
            "destination_ip"
        ),
        "action": get_raw_value(
            raw_event,
            source_mapping,
            "action"
        ),
        "outcome": get_raw_value(
            raw_event,
            source_mapping,
            "outcome"
        ),
        "severity": get_raw_value(
            raw_event,
            source_mapping,
            "severity"
        ),
        "raw_event_id": get_raw_value(
            raw_event,
            source_mapping,
            "raw_event_id"
        )
    }

    for field in quality_rules[
        "required_fields"
    ]:
        if is_blank(
            raw_values.get(
                field
            )
        ):
            add_issue(
                issues,
                "missing_required_field",
                field,
                (
                    f"Required normalized field "
                    f"'{field}' has no usable "
                    f"source value."
                )
            )

    normalized_timestamp = (
        normalize_timestamp(
            raw_values["timestamp"]
        )
    )

    if (
        not is_blank(
            raw_values["timestamp"]
        )
        and normalized_timestamp
        is None
    ):
        add_issue(
            issues,
            "invalid_timestamp",
            "timestamp",
            (
                "Timestamp could not be "
                "normalized to UTC ISO 8601."
            )
        )

    normalized_source_ip = (
        normalize_ip(
            raw_values["source_ip"]
        )
    )

    if (
        not is_blank(
            raw_values["source_ip"]
        )
        and normalized_source_ip
        is None
    ):
        add_issue(
            issues,
            "invalid_ip_address",
            "source_ip",
            (
                f"Invalid source IP: "
                f"{raw_values['source_ip']}"
            )
        )

    normalized_destination_ip = (
        normalize_ip(
            raw_values[
                "destination_ip"
            ]
        )
    )

    if (
        not is_blank(
            raw_values[
                "destination_ip"
            ]
        )
        and normalized_destination_ip
        is None
    ):
        add_issue(
            issues,
            "invalid_ip_address",
            "destination_ip",
            (
                f"Invalid destination IP: "
                f"{raw_values['destination_ip']}"
            )
        )

    normalized_severity = (
        normalize_severity(
            source_name,
            raw_values["severity"],
            quality_rules
        )
    )

    if (
        not is_blank(
            raw_values["severity"]
        )
        and normalized_severity
        is None
    ):
        add_issue(
            issues,
            "invalid_severity",
            "severity",
            (
                f"Unsupported severity value: "
                f"{raw_values['severity']}"
            )
        )

    normalized_event = {
        "timestamp": (
            normalized_timestamp
        ),
        "event_source": (
            normalize_text(
                source_name
            )
        ),
        "event_category": (
            normalize_text(
                raw_values[
                    "event_category"
                ]
            )
        ),
        "host": normalize_host(
            raw_values["host"]
        ),
        "user": normalize_user(
            raw_values["user"]
        ),
        "source_ip": (
            normalized_source_ip
        ),
        "destination_ip": (
            normalized_destination_ip
        ),
        "action": normalize_text(
            raw_values["action"]
        ),
        "outcome": normalize_text(
            raw_values["outcome"]
        ),
        "severity": (
            normalized_severity
        ),
        "raw_event_id": (
            normalize_text(
                raw_values[
                    "raw_event_id"
                ]
            )
        )
    }

    quality_score = (
        calculate_quality_score(
            issues,
            quality_rules
        )
    )

    status = determine_status(
        issues,
        quality_rules
    )

    return (
        normalized_event,
        issues,
        quality_score,
        status
    )


def normalize_all_telemetry(
    telemetry_sources,
    mappings,
    quality_rules
):
    results = []

    source_mappings = mappings[
        "sources"
    ]

    for source in telemetry_sources:
        source_name = source[
            "source"
        ]

        source_mapping = (
            source_mappings.get(
                source_name
            )
        )

        for event_number, raw_event in enumerate(
            source["events"],
            start=1
        ):
            if source_mapping is None:
                issues = []

                add_issue(
                    issues,
                    "unknown_event_source",
                    "event_source",
                    (
                        f"No schema mapping exists "
                        f"for source '{source_name}'."
                    )
                )

                results.append({
                    "source_file": (
                        source[
                            "file_name"
                        ]
                    ),
                    "source_event_number": (
                        event_number
                    ),
                    "normalized_event": {
                        "event_source": (
                            source_name
                        )
                    },
                    "issues": issues,
                    "quality_score": (
                        calculate_quality_score(
                            issues,
                            quality_rules
                        )
                    ),
                    "status": "INVALID",
                    "raw_event": raw_event
                })

                continue

            (
                normalized_event,
                issues,
                quality_score,
                status
            ) = normalize_event(
                source_name,
                raw_event,
                source_mapping,
                quality_rules
            )

            results.append({
                "source_file": (
                    source[
                        "file_name"
                    ]
                ),
                "source_event_number": (
                    event_number
                ),
                "normalized_event": (
                    normalized_event
                ),
                "issues": issues,
                "quality_score": (
                    quality_score
                ),
                "status": status,
                "raw_event": raw_event
            })

    return results


def main():
    OUTPUT_DIR.mkdir(
        exist_ok=True
    )

    mappings, quality_rules = (
        load_configuration()
    )

    telemetry_sources = (
        load_telemetry()
    )

    total_events = sum(
        len(source["events"])
        for source in telemetry_sources
    )

    results = normalize_all_telemetry(
        telemetry_sources,
        mappings,
        quality_rules
    )

    valid_count = sum(
        1
        for result in results
        if result["status"]
        == "VALID"
    )

    invalid_count = (
        len(results)
        - valid_count
    )

    print()
    print("=" * 72)
    print(
        "SOC TELEMETRY NORMALIZATION "
        "AND DATA QUALITY PIPELINE"
    )
    print("=" * 72)

    print(
        f"Telemetry sources loaded: "
        f"{len(telemetry_sources)}"
    )

    print(
        f"Raw events loaded:        "
        f"{total_events}"
    )

    print(
        f"Schema fields defined:    "
        f"{len(mappings['normalized_schema'])}"
    )

    print(
        f"Required fields defined:  "
        f"{len(quality_rules['required_fields'])}"
    )

    print("=" * 72)

    for source in telemetry_sources:
        print(
            f"{source['source']:<24} "
            f"{len(source['events'])} events "
            f"({source['file_name']})"
        )

    print("=" * 72)
    print("PRELIMINARY QUALITY RESULTS")
    print("=" * 72)

    print(
        f"Events normalized:        "
        f"{len(results)}"
    )

    print(
        f"Preliminary valid:        "
        f"{valid_count}"
    )

    print(
        f"Preliminary invalid:      "
        f"{invalid_count}"
    )

    print("=" * 72)

    for result in results:
        if result["status"] != "INVALID":
            continue

        event = result[
            "normalized_event"
        ]

        event_id = (
            event.get(
                "raw_event_id"
            )
            or "(missing ID)"
        )

        issue_text = ", ".join(
            (
                f"{issue['issue_type']}"
                f":{issue['field']}"
            )
            for issue in result[
                "issues"
            ]
        )

        print(
            f"{event.get('event_source', 'UNKNOWN'):<24} "
            f"{event_id:<14} "
            f"score={result['quality_score']:<3} "
            f"{issue_text}"
        )

    print("=" * 72)


if __name__ == "__main__":
    main()
