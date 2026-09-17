import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml


EVENT_FILE = Path("sample_events.json")
DETECTION_DIR = Path("detections")

OUTPUT_DIR = Path("output")
DETECTION_OUTPUT = OUTPUT_DIR / "detection_results.json"
CORRELATION_OUTPUT = OUTPUT_DIR / "correlation_findings.json"


def load_events(file_path):
    """Load fictional Windows events from JSON."""
    with open(file_path, "r", encoding="utf-8") as event_file:
        return json.load(event_file)


def load_sigma_rules(directory):
    """Load all Sigma YAML rules from the detections directory."""
    rules = []

    for rule_path in sorted(directory.glob("*.yml")):
        with open(rule_path, "r", encoding="utf-8") as rule_file:
            rule = yaml.safe_load(rule_file)
            rule["_file"] = rule_path.name
            rules.append(rule)

    return rules


def normalize_event(event):
    """Map training fields to Sigma-style field names."""
    normalized = dict(event)

    field_map = {
        "event_id": "EventID",
        "image": "Image",
        "command_line": "CommandLine",
        "service_path": "ServiceFileName",
        "service_name": "ServiceName",
        "user": "User",
        "source_ip": "SourceIp",
        "computer": "Computer"
    }

    for source_field, sigma_field in field_map.items():
        if source_field in event:
            normalized[sigma_field] = event[source_field]

    return normalized


def value_matches(event_value, rule_value, operator=None):
    """Compare an event value with a Sigma-style rule value."""
    if event_value is None:
        return False

    event_text = str(event_value).lower()
    values = rule_value if isinstance(rule_value, list) else [rule_value]

    for candidate in values:
        candidate_text = str(candidate).lower()

        if operator == "contains":
            if candidate_text in event_text:
                return True

        elif operator == "endswith":
            if event_text.endswith(candidate_text):
                return True

        else:
            if event_text == candidate_text:
                return True

    return False


def selection_matches(event, selection):
    """Evaluate one Sigma selection against one normalized event."""
    for field_expression, rule_value in selection.items():

        if "|" in field_expression:
            field_name, operator = field_expression.split("|", 1)
        else:
            field_name = field_expression
            operator = None

        event_value = event.get(field_name)

        if not value_matches(
            event_value,
            rule_value,
            operator
        ):
            return False

    return True


def evaluate_condition(event, detection):
    """Evaluate the simple Sigma conditions used in this lab."""
    condition = detection["condition"].strip()

    if " and " in condition:
        selection_names = [
            item.strip()
            for item in condition.split(" and ")
        ]

        return all(
            selection_matches(
                event,
                detection[name]
            )
            for name in selection_names
        )

    return selection_matches(
        event,
        detection[condition]
    )


def test_rule(rule, events):
    """Run one Sigma rule against all sample events."""
    matches = []

    for event in events:
        normalized_event = normalize_event(event)

        if evaluate_condition(
            normalized_event,
            rule["detection"]
        ):
            matches.append(event)

    return matches


def parse_timestamp(timestamp):
    """Convert ISO-8601 UTC text into a datetime."""
    return datetime.strptime(
        timestamp,
        "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)


def correlate_failed_logons(events, threshold=3, window_seconds=60):
    """
    Detect repeated failed logons from the same source IP
    against the same user and destination computer.
    """
    grouped = defaultdict(list)

    for event in events:
        if event.get("event_id") != 4625:
            continue

        key = (
            event.get("source_ip"),
            event.get("user"),
            event.get("computer")
        )

        grouped[key].append(event)

    findings = []

    for key, group_events in grouped.items():
        sorted_events = sorted(
            group_events,
            key=lambda event: parse_timestamp(event["timestamp"])
        )

        for start_index in range(len(sorted_events)):
            window_events = [sorted_events[start_index]]

            start_time = parse_timestamp(
                sorted_events[start_index]["timestamp"]
            )

            for next_event in sorted_events[start_index + 1:]:
                next_time = parse_timestamp(next_event["timestamp"])
                elapsed = (next_time - start_time).total_seconds()

                if elapsed <= window_seconds:
                    window_events.append(next_event)
                else:
                    break

            if len(window_events) >= threshold:
                first_time = parse_timestamp(
                    window_events[0]["timestamp"]
                )
                last_time = parse_timestamp(
                    window_events[-1]["timestamp"]
                )

                findings.append(
                    {
                        "finding_type": "Repeated Failed Logons",
                        "source_ip": key[0],
                        "user": key[1],
                        "computer": key[2],
                        "attempts": len(window_events),
                        "window_seconds": int(
                            (last_time - first_time).total_seconds()
                        ),
                        "first_seen": window_events[0]["timestamp"],
                        "last_seen": window_events[-1]["timestamp"],
                        "severity": "HIGH",
                        "assessment": (
                            "Repeated failed authentication activity "
                            "may indicate password guessing."
                        )
                    }
                )

                break

    return findings


def print_correlation_findings(findings):
    """Display behavioral correlation findings."""
    print("=" * 70)
    print("BEHAVIORAL CORRELATION RESULTS")
    print("=" * 70)

    if not findings:
        print("No repeated failed-logon patterns detected.")
        return

    for finding in findings:
        print(
            f"[CORRELATED ALERT] "
            f"{finding['attempts']} failed logons in "
            f"{finding['window_seconds']} seconds"
        )
        print(f"Source IP:   {finding['source_ip']}")
        print(f"User:        {finding['user']}")
        print(f"Computer:    {finding['computer']}")
        print(f"First Seen:  {finding['first_seen']}")
        print(f"Last Seen:   {finding['last_seen']}")
        print(f"Severity:    {finding['severity']}")
        print(f"Assessment:  {finding['assessment']}")
        print()


def export_detection_results(
    detection_matches,
    total_events,
    total_rules,
    correct,
    false_positive,
    false_negative
):
    """Export Sigma detection test results to JSON."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    report = {
        "lab": "Windows Sigma Detection Lab",
        "summary": {
            "total_events": total_events,
            "sigma_rules_loaded": total_rules,
            "rule_matches": len(detection_matches),
            "correct_results": correct,
            "false_positives": false_positive,
            "false_negatives": false_negative
        },
        "detections": detection_matches
    }

    with open(
        DETECTION_OUTPUT,
        "w",
        encoding="utf-8"
    ) as output_file:
        json.dump(report, output_file, indent=4)


def export_correlation_findings(findings):
    """Export behavioral correlation findings to JSON."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    report = {
        "analysis_type": "Behavioral Correlation",
        "finding_count": len(findings),
        "findings": findings
    }

    with open(
        CORRELATION_OUTPUT,
        "w",
        encoding="utf-8"
    ) as output_file:
        json.dump(report, output_file, indent=4)


def main():
    events = load_events(EVENT_FILE)
    rules = load_sigma_rules(DETECTION_DIR)

    print("=== WINDOWS SIGMA DETECTION LAB ===\n")
    print(f"Loaded events: {len(events)}")
    print(f"Loaded Sigma rules: {len(rules)}\n")

    matched_event_indexes = set()
    detection_matches = []

    for rule in rules:
        matches = test_rule(rule, events)

        print("=" * 70)
        print(f"Rule: {rule['title']}")
        print(f"File: {rule['_file']}")
        print(f"Severity: {rule.get('level', 'unknown').upper()}")
        print(f"Matches: {len(matches)}")
        print("-" * 70)

        if not matches:
            print("No matching events.")

        for match in matches:
            event_index = events.index(match)
            matched_event_indexes.add(event_index)

            detection_matches.append(
                {
                    "rule_title": rule["title"],
                    "rule_file": rule["_file"],
                    "severity": rule.get("level", "unknown").upper(),
                    "event": {
                        "timestamp": match["timestamp"],
                        "event_id": match["event_id"],
                        "computer": match["computer"],
                        "user": match.get("user"),
                        "source_ip": match.get("source_ip"),
                        "description": match["description"]
                    }
                }
            )

            print(
                f"[MATCH] "
                f"{match['timestamp']} | "
                f"Event ID {match['event_id']} | "
                f"{match['computer']} | "
                f"{match['description']}"
            )

        print()

    print("=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)

    correct = 0
    false_positive = 0
    false_negative = 0

    for index, event in enumerate(events):
        detected = index in matched_event_indexes
        expected = event["expected_detection"]

        if detected == expected:
            result = "PASS"
            correct += 1

        elif detected and not expected:
            result = "FALSE POSITIVE"
            false_positive += 1

        else:
            result = "FALSE NEGATIVE"
            false_negative += 1

        print(
            f"[{result}] "
            f"Event ID {event['event_id']} | "
            f"{event['description']}"
        )

    print("\n=== TEST SUMMARY ===")
    print(f"Total events:     {len(events)}")
    print(f"Correct results:  {correct}")
    print(f"False positives:  {false_positive}")
    print(f"False negatives:  {false_negative}")
    print()

    correlation_findings = correlate_failed_logons(events)
    print_correlation_findings(correlation_findings)

    export_detection_results(
        detection_matches,
        len(events),
        len(rules),
        correct,
        false_positive,
        false_negative
    )

    export_correlation_findings(correlation_findings)

    print("=== REPORT EXPORT COMPLETE ===")
    print(f"Detection report:   {DETECTION_OUTPUT}")
    print(f"Correlation report: {CORRELATION_OUTPUT}")


if __name__ == "__main__":
    main()
