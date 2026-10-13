import csv
import json
import re

from collections import Counter
from pathlib import Path

import yaml


BASE_DIR = Path(__file__).resolve().parent

DETECTIONS_DIR = (
    BASE_DIR
    / "detections"
)

POLICY_FILE = (
    BASE_DIR
    / "config"
    / "validation_policy.json"
)

OUTPUT_DIR = (
    BASE_DIR
    / "output"
)

VALIDATION_JSON = (
    OUTPUT_DIR
    / "rule_validation_results.json"
)

VALIDATION_CSV = (
    OUTPUT_DIR
    / "rule_validation_summary.csv"
)


def load_json(file_path):
    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def discover_rule_files():
    return sorted(
        DETECTIONS_DIR.glob("*.yml")
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


def finding_severity(
    finding_type,
    policy
):
    if finding_type in policy[
        "fatal_failures"
    ]:
        return "FAIL"

    if finding_type in policy[
        "review_findings"
    ]:
        return "REVIEW"

    return "INFO"


def add_finding(
    findings,
    finding_type,
    field,
    details,
    policy
):
    findings.append({
        "finding_type": finding_type,
        "severity": finding_severity(
            finding_type,
            policy
        ),
        "field": field,
        "details": details
    })


def parse_yaml_rule(
    file_path,
    policy
):
    try:
        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:
            rule = yaml.safe_load(
                file
            )

    except yaml.YAMLError as error:
        findings = []

        add_finding(
            findings,
            "yaml_parse_error",
            "yaml",
            str(error),
            policy
        )

        return None, findings

    if not isinstance(
        rule,
        dict
    ):
        findings = []

        add_finding(
            findings,
            "yaml_parse_error",
            "yaml",
            (
                "YAML parsed successfully but "
                "did not produce a rule mapping."
            ),
            policy
        )

        return None, findings

    return rule, []


def validate_required_fields(
    rule,
    findings,
    policy
):
    for field in policy[
        "required_fields"
    ]:
        if (
            field not in rule
            or is_blank(
                rule.get(
                    field
                )
            )
        ):
            add_finding(
                findings,
                "missing_required_field",
                field,
                (
                    f"Required field "
                    f"'{field}' is missing "
                    f"or empty."
                ),
                policy
            )


def validate_uuid(
    rule,
    findings,
    policy
):
    rule_id = rule.get(
        "id"
    )

    if is_blank(
        rule_id
    ):
        return

    if not re.fullmatch(
        policy[
            "uuid_pattern"
        ],
        str(rule_id)
    ):
        add_finding(
            findings,
            "invalid_uuid",
            "id",
            (
                f"Rule ID '{rule_id}' "
                f"does not match the "
                f"approved UUID format."
            ),
            policy
        )


def validate_status(
    rule,
    findings,
    policy
):
    status = rule.get(
        "status"
    )

    if is_blank(
        status
    ):
        return

    if status not in policy[
        "approved_statuses"
    ]:
        add_finding(
            findings,
            "invalid_status",
            "status",
            (
                f"Status '{status}' is "
                f"not approved."
            ),
            policy
        )


def validate_level(
    rule,
    findings,
    policy
):
    level = rule.get(
        "level"
    )

    if is_blank(
        level
    ):
        return

    if level not in policy[
        "approved_levels"
    ]:
        add_finding(
            findings,
            "invalid_level",
            "level",
            (
                f"Level '{level}' is "
                f"not approved."
            ),
            policy
        )


def validate_date(
    rule,
    findings,
    policy
):
    date_value = rule.get(
        "date"
    )

    if is_blank(
        date_value
    ):
        return

    date_text = str(
        date_value
    )

    if not re.fullmatch(
        policy[
            "date_pattern"
        ],
        date_text
    ):
        add_finding(
            findings,
            "invalid_date",
            "date",
            (
                f"Date '{date_text}' does "
                f"not use YYYY-MM-DD format."
            ),
            policy
        )


def validate_attack_tags(
    rule,
    findings,
    policy
):
    tags = rule.get(
        "tags"
    )

    if not isinstance(
        tags,
        list
    ):
        if policy[
            "require_attack_mapping"
        ]:
            add_finding(
                findings,
                "missing_attack_mapping",
                "tags",
                (
                    "Rule does not contain "
                    "a usable ATT&CK technique "
                    "mapping."
                ),
                policy
            )

        return

    valid_technique_tags = []

    for tag in tags:
        if not isinstance(
            tag,
            str
        ):
            continue

        if tag.startswith(
            "attack.t"
        ):
            if re.fullmatch(
                policy[
                    "attack_tag_pattern"
                ],
                tag
            ):
                valid_technique_tags.append(
                    tag
                )

            else:
                add_finding(
                    findings,
                    "invalid_attack_tag",
                    "tags",
                    (
                        f"ATT&CK technique tag "
                        f"'{tag}' does not match "
                        f"the approved format."
                    ),
                    policy
                )

    if (
        policy[
            "require_attack_mapping"
        ]
        and not valid_technique_tags
    ):
        add_finding(
            findings,
            "missing_attack_mapping",
            "tags",
            (
                "At least one valid ATT&CK "
                "technique tag is required."
            ),
            policy
        )


def validate_logsource(
    rule,
    findings,
    policy
):
    logsource = rule.get(
        "logsource"
    )

    if not isinstance(
        logsource,
        dict
    ):
        add_finding(
            findings,
            "invalid_logsource",
            "logsource",
            (
                "Logsource must be a "
                "YAML mapping."
            ),
            policy
        )

        return

    required_any = policy[
        "required_logsource_any_of"
    ]

    has_required_value = any(
        (
            field in logsource
            and not is_blank(
                logsource.get(
                    field
                )
            )
        )
        for field in required_any
    )

    if not has_required_value:
        add_finding(
            findings,
            "invalid_logsource",
            "logsource",
            (
                "Logsource must contain "
                "at least one of: "
                + ", ".join(
                    required_any
                )
            ),
            policy
        )


def validate_detection(
    rule,
    findings,
    policy
):
    detection = rule.get(
        "detection"
    )

    if not isinstance(
        detection,
        dict
    ):
        add_finding(
            findings,
            "missing_detection_condition",
            "detection",
            (
                "Detection must be a YAML "
                "mapping containing a condition."
            ),
            policy
        )

        return

    condition = detection.get(
        "condition"
    )

    if is_blank(
        condition
    ):
        add_finding(
            findings,
            "missing_detection_condition",
            "condition",
            (
                "Detection section does not "
                "contain a usable condition."
            ),
            policy
        )


def validate_documentation(
    rule,
    findings,
    policy
):
    title = rule.get(
        "title"
    )

    if (
        isinstance(
            title,
            str
        )
        and len(
            title.strip()
        )
        < policy[
            "minimum_title_length"
        ]
    ):
        add_finding(
            findings,
            "short_title",
            "title",
            (
                "Rule title is shorter than "
                "the configured minimum."
            ),
            policy
        )

    description = rule.get(
        "description"
    )

    if (
        isinstance(
            description,
            str
        )
        and len(
            description.strip()
        )
        < policy[
            "minimum_description_length"
        ]
    ):
        add_finding(
            findings,
            "short_description",
            "description",
            (
                "Rule description is shorter "
                "than the configured minimum."
            ),
            policy
        )

    falsepositives = rule.get(
        "falsepositives"
    )

    if (
        not isinstance(
            falsepositives,
            list
        )
        or len(
            falsepositives
        )
        < policy[
            "minimum_falsepositive_entries"
        ]
    ):
        add_finding(
            findings,
            "limited_falsepositive_documentation",
            "falsepositives",
            (
                "Rule does not contain the "
                "minimum false-positive "
                "documentation."
            ),
            policy
        )


def determine_rule_status(
    findings
):
    if any(
        finding[
            "severity"
        ]
        == "FAIL"
        for finding in findings
    ):
        return "FAIL"

    if any(
        finding[
            "severity"
        ]
        == "REVIEW"
        for finding in findings
    ):
        return "REVIEW"

    return "PASS"


def validate_rules(
    rule_files,
    policy
):
    results = []

    seen_ids = {}

    for file_path in rule_files:
        rule, findings = parse_yaml_rule(
            file_path,
            policy
        )

        if rule is None:
            results.append({
                "file_name": (
                    file_path.name
                ),
                "title": None,
                "rule_id": None,
                "result": "FAIL",
                "fatal_findings": 1,
                "review_findings": 0,
                "findings": findings
            })

            continue

        validate_required_fields(
            rule,
            findings,
            policy
        )

        validate_uuid(
            rule,
            findings,
            policy
        )

        validate_status(
            rule,
            findings,
            policy
        )

        validate_level(
            rule,
            findings,
            policy
        )

        validate_date(
            rule,
            findings,
            policy
        )

        validate_attack_tags(
            rule,
            findings,
            policy
        )

        validate_logsource(
            rule,
            findings,
            policy
        )

        validate_detection(
            rule,
            findings,
            policy
        )

        validate_documentation(
            rule,
            findings,
            policy
        )

        rule_id = rule.get(
            "id"
        )

        if not is_blank(
            rule_id
        ):
            if rule_id in seen_ids:
                add_finding(
                    findings,
                    "duplicate_rule_id",
                    "id",
                    (
                        f"Rule ID '{rule_id}' "
                        f"was already used by "
                        f"{seen_ids[rule_id]}."
                    ),
                    policy
                )

            else:
                seen_ids[
                    rule_id
                ] = file_path.name

        result = determine_rule_status(
            findings
        )

        fatal_count = sum(
            1
            for finding in findings
            if finding[
                "severity"
            ]
            == "FAIL"
        )

        review_count = sum(
            1
            for finding in findings
            if finding[
                "severity"
            ]
            == "REVIEW"
        )

        results.append({
            "file_name": (
                file_path.name
            ),
            "title": rule.get(
                "title"
            ),
            "rule_id": rule_id,
            "result": result,
            "fatal_findings": (
                fatal_count
            ),
            "review_findings": (
                review_count
            ),
            "findings": findings
        })

    return results


def build_report(
    results,
    policy
):
    pass_count = sum(
        1
        for result in results
        if result[
            "result"
        ]
        == "PASS"
    )

    review_count = sum(
        1
        for result in results
        if result[
            "result"
        ]
        == "REVIEW"
    )

    fail_count = sum(
        1
        for result in results
        if result[
            "result"
        ]
        == "FAIL"
    )

    finding_counter = Counter()

    for result in results:
        for finding in result[
            "findings"
        ]:
            finding_counter[
                finding[
                    "finding_type"
                ]
            ] += 1

    gate_failed = False

    if (
        policy[
            "quality_gate"
        ][
            "fail_on_fatal"
        ]
        and fail_count > 0
    ):
        gate_failed = True

    if (
        policy[
            "quality_gate"
        ][
            "fail_on_review"
        ]
        and review_count > 0
    ):
        gate_failed = True

    return {
        "rules_scanned": len(
            results
        ),
        "pass_rules": pass_count,
        "review_rules": review_count,
        "fail_rules": fail_count,
        "quality_gate": (
            "FAILED"
            if gate_failed
            else "PASSED"
        ),
        "finding_counts": dict(
            finding_counter
        ),
        "results": results
    }


def export_json(
    report
):
    with open(
        VALIDATION_JSON,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )


def export_csv(
    results
):
    fieldnames = [
        "file_name",
        "title",
        "rule_id",
        "result",
        "fatal_findings",
        "review_findings",
        "finding_types"
    ]

    with open(
        VALIDATION_CSV,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for result in results:
            writer.writerow({
                "file_name": (
                    result[
                        "file_name"
                    ]
                ),
                "title": (
                    result[
                        "title"
                    ]
                ),
                "rule_id": (
                    result[
                        "rule_id"
                    ]
                ),
                "result": (
                    result[
                        "result"
                    ]
                ),
                "fatal_findings": (
                    result[
                        "fatal_findings"
                    ]
                ),
                "review_findings": (
                    result[
                        "review_findings"
                    ]
                ),
                "finding_types": (
                    "; ".join(
                        finding[
                            "finding_type"
                        ]
                        for finding
                        in result[
                            "findings"
                        ]
                    )
                )
            })


def print_report(
    report
):
    print()
    print("=" * 82)

    print(
        "DETECTION-AS-CODE STATIC "
        "VALIDATION"
    )

    print("=" * 82)

    print(
        f"Rules scanned:   "
        f"{report['rules_scanned']}"
    )

    print(
        f"PASS:            "
        f"{report['pass_rules']}"
    )

    print(
        f"REVIEW:          "
        f"{report['review_rules']}"
    )

    print(
        f"FAIL:            "
        f"{report['fail_rules']}"
    )

    print(
        f"Quality gate:    "
        f"{report['quality_gate']}"
    )

    print("=" * 82)

    for result in report[
        "results"
    ]:
        print(
            f"{result['result']:<7} "
            f"{result['file_name']}"
        )

        for finding in result[
            "findings"
        ]:
            print(
                f"        "
                f"{finding['severity']:<7} "
                f"{finding['finding_type']}"
                f" [{finding['field']}]"
            )

    print("=" * 82)
    print("FINDING COUNTS")
    print("=" * 82)

    if report[
        "finding_counts"
    ]:
        for finding_type, count in sorted(
            report[
                "finding_counts"
            ].items()
        ):
            print(
                f"{finding_type:<34} "
                f"{count}"
            )

    else:
        print(
            "No findings detected."
        )

    print("=" * 82)

    print(
        f"JSON report: "
        f"{VALIDATION_JSON}"
    )

    print(
        f"CSV summary: "
        f"{VALIDATION_CSV}"
    )

    print("=" * 82)


def main():
    OUTPUT_DIR.mkdir(
        exist_ok=True
    )

    policy = load_json(
        POLICY_FILE
    )

    rule_files = (
        discover_rule_files()
    )

    results = validate_rules(
        rule_files,
        policy
    )

    report = build_report(
        results,
        policy
    )

    export_json(
        report
    )

    export_csv(
        results
    )

    print_report(
        report
    )


if __name__ == "__main__":
    main()
