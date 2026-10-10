import csv
import ipaddress
import json

from collections import Counter
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

NORMALIZED_JSON = (
    OUTPUT_DIR
    / "normalized_events.json"
)

NORMALIZED_CSV = (
    OUTPUT_DIR
    / "normalized_events.csv"
)

INVALID_JSON = (
    OUTPUT_DIR
    / "invalid_events.json"
)

DUPLICATE_JSON = (
    OUTPUT_DIR
    / "duplicate_events.json"
)

QUALITY_REPORT_JSON = (
    OUTPUT_DIR
    / "telemetry_quality_report.json"
)

QUALITY_SUMMARY_CSV = (
    OUTPUT_DIR
    / "telemetry_quality_summary.csv"
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

    issue_types = {
        issue["issue_type"]
        for issue in issues
    }

    if fatal_issues.intersection(
        issue_types
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

        "event_source": (
            source_name
        ),

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
            raw_values[
                "source_ip"
            ]
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
            raw_values[
                "severity"
            ],
            quality_rules
        )
    )

    if (
        not is_blank(
            raw_values[
                "severity"
            ]
        )
        and normalized_severity
        is None
    ):
        add_issue(
            issues,
            "invalid_severity",
            "severity",
            (
                f"Unsupported severity "
                f"value: "
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
                        f"No schema mapping "
                        f"exists for source "
                        f"'{source_name}'."
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

                    "raw_event": (
                        raw_event
                    )
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

                "status": (
                    status
                ),

                "raw_event": (
                    raw_event
                )
            })

    return results


def apply_duplicate_detection(
    results,
    quality_rules
):
    seen = set()

    identity_fields = (
        quality_rules[
            "duplicate_identity_fields"
        ]
    )

    for result in results:
        event = result[
            "normalized_event"
        ]

        identity_values = [
            event.get(
                field
            )
            for field in identity_fields
        ]

        if any(
            is_blank(value)
            for value in identity_values
        ):
            continue

        identity = tuple(
            identity_values
        )

        if identity in seen:
            add_issue(
                result[
                    "issues"
                ],
                "duplicate_event",
                (
                    "+".join(
                        identity_fields
                    )
                ),
                (
                    "Event identity already "
                    "appeared earlier in the "
                    "telemetry stream."
                )
            )

            result[
                "quality_score"
            ] = calculate_quality_score(
                result["issues"],
                quality_rules
            )

            if (
                result["status"]
                != "INVALID"
            ):
                result[
                    "status"
                ] = "DUPLICATE"

        else:
            seen.add(
                identity
            )

    return results


def quality_label(score):
    if score >= 95:
        return "EXCELLENT"

    if score >= 85:
        return "GOOD"

    if score >= 70:
        return "FAIR"

    return "POOR"


def calculate_source_summary(
    source_name,
    source_results
):
    total = len(
        source_results
    )

    valid = sum(
        1
        for result in source_results
        if result["status"]
        == "VALID"
    )

    duplicates = sum(
        1
        for result in source_results
        if result["status"]
        == "DUPLICATE"
    )

    invalid = sum(
        1
        for result in source_results
        if result["status"]
        == "INVALID"
    )

    if total:
        average_event_score = round(
            sum(
                result[
                    "quality_score"
                ]
                for result
                in source_results
            )
            / total,
            2
        )

        accepted_event_rate = round(
            (
                valid
                / total
            )
            * 100,
            2
        )

    else:
        average_event_score = 0.0
        accepted_event_rate = 0.0

    source_quality_score = round(
        (
            average_event_score
            * 0.70
        )
        +
        (
            accepted_event_rate
            * 0.30
        ),
        2
    )

    return {
        "source": source_name,
        "total_events": total,
        "normalized_events": valid,
        "duplicate_events": duplicates,
        "invalid_events": invalid,
        "average_event_score": (
            average_event_score
        ),
        "accepted_event_rate": (
            accepted_event_rate
        ),
        "source_quality_score": (
            source_quality_score
        ),
        "quality_label": (
            quality_label(
                source_quality_score
            )
        )
    }


def build_quality_report(
    results
):
    source_names = sorted({
        result[
            "normalized_event"
        ].get(
            "event_source",
            "UNKNOWN"
        )
        for result in results
    })

    source_summaries = []

    for source_name in source_names:
        source_results = [
            result
            for result in results
            if result[
                "normalized_event"
            ].get(
                "event_source",
                "UNKNOWN"
            )
            == source_name
        ]

        source_summaries.append(
            calculate_source_summary(
                source_name,
                source_results
            )
        )

    total = len(
        results
    )

    valid = sum(
        1
        for result in results
        if result["status"]
        == "VALID"
    )

    duplicates = sum(
        1
        for result in results
        if result["status"]
        == "DUPLICATE"
    )

    invalid = sum(
        1
        for result in results
        if result["status"]
        == "INVALID"
    )

    if total:
        average_event_score = round(
            sum(
                result[
                    "quality_score"
                ]
                for result in results
            )
            / total,
            2
        )

        accepted_event_rate = round(
            (
                valid
                / total
            )
            * 100,
            2
        )

    else:
        average_event_score = 0.0
        accepted_event_rate = 0.0

    overall_quality_score = round(
        (
            average_event_score
            * 0.70
        )
        +
        (
            accepted_event_rate
            * 0.30
        ),
        2
    )

    issue_counter = Counter()

    for result in results:
        for issue in result[
            "issues"
        ]:
            issue_counter[
                issue[
                    "issue_type"
                ]
            ] += 1

    return {
        "generated_timestamp": (
            utc_now()
        ),

        "scoring_method": {
            "average_event_score_weight": (
                0.70
            ),
            "accepted_event_rate_weight": (
                0.30
            ),
            "description": (
                "Source and overall quality "
                "scores combine average "
                "event quality with the "
                "percentage of events accepted "
                "into the clean normalized "
                "dataset."
            )
        },

        "overall": {
            "raw_events": total,
            "normalized_events": valid,
            "duplicate_events": (
                duplicates
            ),
            "invalid_events": invalid,
            "average_event_score": (
                average_event_score
            ),
            "accepted_event_rate": (
                accepted_event_rate
            ),
            "overall_quality_score": (
                overall_quality_score
            ),
            "quality_label": (
                quality_label(
                    overall_quality_score
                )
            )
        },

        "issue_counts": dict(
            issue_counter
        ),

        "sources": (
            source_summaries
        )
    }


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


def export_normalized_events(
    results,
    mappings
):
    valid_events = [
        result[
            "normalized_event"
        ]
        for result in results
        if result["status"]
        == "VALID"
    ]

    export_json(
        NORMALIZED_JSON,
        {
            "generated_timestamp": (
                utc_now()
            ),
            "event_count": len(
                valid_events
            ),
            "schema": mappings[
                "normalized_schema"
            ],
            "events": valid_events
        }
    )

    with open(
        NORMALIZED_CSV,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=mappings[
                "normalized_schema"
            ]
        )

        writer.writeheader()

        for event in valid_events:
            writer.writerow(
                event
            )

    return valid_events


def export_problem_events(
    results
):
    invalid_events = [
        result
        for result in results
        if result["status"]
        == "INVALID"
    ]

    duplicate_events = [
        result
        for result in results
        if result["status"]
        == "DUPLICATE"
    ]

    export_json(
        INVALID_JSON,
        {
            "generated_timestamp": (
                utc_now()
            ),
            "invalid_event_count": (
                len(
                    invalid_events
                )
            ),
            "events": invalid_events
        }
    )

    export_json(
        DUPLICATE_JSON,
        {
            "generated_timestamp": (
                utc_now()
            ),
            "duplicate_event_count": (
                len(
                    duplicate_events
                )
            ),
            "events": duplicate_events
        }
    )

    return (
        invalid_events,
        duplicate_events
    )


def export_quality_report(
    report
):
    export_json(
        QUALITY_REPORT_JSON,
        report
    )

    fieldnames = [
        "source",
        "total_events",
        "normalized_events",
        "duplicate_events",
        "invalid_events",
        "average_event_score",
        "accepted_event_rate",
        "source_quality_score",
        "quality_label"
    ]

    with open(
        QUALITY_SUMMARY_CSV,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for source in report[
            "sources"
        ]:
            writer.writerow(
                source
            )


def print_report(
    telemetry_sources,
    mappings,
    quality_rules,
    results,
    report
):
    overall = report[
        "overall"
    ]

    print()
    print("=" * 78)

    print(
        "SOC TELEMETRY NORMALIZATION "
        "AND DATA QUALITY PIPELINE"
    )

    print("=" * 78)

    print(
        f"Telemetry sources loaded: "
        f"{len(telemetry_sources)}"
    )

    print(
        f"Raw events loaded:        "
        f"{overall['raw_events']}"
    )

    print(
        f"Schema fields defined:    "
        f"{len(mappings['normalized_schema'])}"
    )

    print(
        f"Required fields defined:  "
        f"{len(quality_rules['required_fields'])}"
    )

    print("=" * 78)
    print("PIPELINE RESULTS")
    print("=" * 78)

    print(
        f"Clean normalized events:  "
        f"{overall['normalized_events']}"
    )

    print(
        f"Duplicate events:         "
        f"{overall['duplicate_events']}"
    )

    print(
        f"Invalid events:           "
        f"{overall['invalid_events']}"
    )

    print(
        f"Average event score:      "
        f"{overall['average_event_score']}"
    )

    print(
        f"Accepted event rate:      "
        f"{overall['accepted_event_rate']}%"
    )

    print(
        f"Overall quality score:    "
        f"{overall['overall_quality_score']}"
    )

    print(
        f"Overall quality rating:   "
        f"{overall['quality_label']}"
    )

    print("=" * 78)
    print("SOURCE QUALITY")
    print("=" * 78)

    for source in report[
        "sources"
    ]:
        print(
            f"{source['source']:<24} "
            f"score="
            f"{source['source_quality_score']:<6} "
            f"{source['quality_label']:<10} "
            f"clean="
            f"{source['normalized_events']} "
            f"dup="
            f"{source['duplicate_events']} "
            f"invalid="
            f"{source['invalid_events']}"
        )

    print("=" * 78)
    print("DATA QUALITY ISSUES")
    print("=" * 78)

    for issue, count in sorted(
        report[
            "issue_counts"
        ].items()
    ):
        print(
            f"{issue:<28} "
            f"{count}"
        )

    print("=" * 78)
    print("OUTPUT FILES")
    print("=" * 78)

    print(
        f"Normalized JSON: "
        f"{NORMALIZED_JSON}"
    )

    print(
        f"Normalized CSV:  "
        f"{NORMALIZED_CSV}"
    )

    print(
        f"Invalid events:  "
        f"{INVALID_JSON}"
    )

    print(
        f"Duplicates:      "
        f"{DUPLICATE_JSON}"
    )

    print(
        f"Quality report:  "
        f"{QUALITY_REPORT_JSON}"
    )

    print(
        f"Quality summary: "
        f"{QUALITY_SUMMARY_CSV}"
    )

    print("=" * 78)


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

    results = normalize_all_telemetry(
        telemetry_sources,
        mappings,
        quality_rules
    )

    results = apply_duplicate_detection(
        results,
        quality_rules
    )

    export_normalized_events(
        results,
        mappings
    )

    export_problem_events(
        results
    )

    report = build_quality_report(
        results
    )

    export_quality_report(
        report
    )

    print_report(
        telemetry_sources,
        mappings,
        quality_rules,
        results,
        report
    )


if __name__ == "__main__":
    main()
