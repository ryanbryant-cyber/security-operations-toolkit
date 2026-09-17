import json
from pathlib import Path

import yaml


EVENT_FILE = Path("sample_events.json")
DETECTION_DIR = Path("detections")


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
    """
    Map training-dataset fields to Sigma-style field names.

    This simulates the normalization that a SIEM or log pipeline
    may perform before detection rules are evaluated.
    """
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
    """Compare an event value to a Sigma-style rule value."""
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
    """
    Evaluate the simple Sigma conditions used in this lab.

    Supported:
    - selection
    - selection_a and selection_b
    """
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


def main():
    events = load_events(EVENT_FILE)
    rules = load_sigma_rules(DETECTION_DIR)

    print("=== WINDOWS SIGMA DETECTION LAB ===\n")
    print(f"Loaded events: {len(events)}")
    print(f"Loaded Sigma rules: {len(rules)}\n")

    matched_event_indexes = set()

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


if __name__ == "__main__":
    main()
