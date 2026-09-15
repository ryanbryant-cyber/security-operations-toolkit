import csv
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


INPUT_FILE = Path("sample_iocs.csv")
OUTPUT_DIR = Path("output")
CSV_OUTPUT = OUTPUT_DIR / "ioc_triage_results.csv"
JSON_OUTPUT = OUTPUT_DIR / "ioc_triage_results.json"


def load_iocs(file_path):
    """Load IOC records from a CSV file."""
    records = []

    with open(file_path, "r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            records.append(row)

    return records


def detect_ioc_type(indicator):
    """Detect the IOC type based on the indicator's format."""
    value = indicator.strip()

    try:
        ip = ipaddress.ip_address(value)

        if ip.version == 4:
            return "ipv4"
    except ValueError:
        pass

    if re.fullmatch(r"[A-Fa-f0-9]{32}", value):
        return "md5"

    if re.fullmatch(r"[A-Fa-f0-9]{40}", value):
        return "sha1"

    if re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        return "sha256"

    validation_url = (
        value.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )

    parsed_url = urlsplit(validation_url)

    if (
        parsed_url.scheme in ("http", "https")
        and parsed_url.netloc
    ):
        return "url"

    domain_pattern = (
        r"^(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,}$"
    )

    if re.fullmatch(domain_pattern, value):
        return "domain"

    return "unknown"


def normalize_indicator(indicator, ioc_type):
    """Normalize an IOC so duplicate values can be correlated."""
    value = indicator.strip()

    if ioc_type == "ipv4":
        return str(ipaddress.ip_address(value))

    if ioc_type in ("md5", "sha1", "sha256"):
        return value.lower()

    if ioc_type == "domain":
        return value.lower().rstrip(".")

    if ioc_type == "url":
        live_url = (
            value.replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
        )

        parsed = urlsplit(live_url)

        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""

        netloc = hostname

        if parsed.port:
            netloc = f"{hostname}:{parsed.port}"

        normalized = urlunsplit(
            (
                scheme,
                netloc,
                parsed.path,
                parsed.query,
                ""
            )
        )

        return (
            normalized.replace("https://", "hxxps://")
            .replace("http://", "hxxp://")
        )

    return value


def validate_and_normalize(records):
    """Validate IOC types and create normalized indicator values."""
    processed_records = []

    for record in records:
        indicator = record["indicator"]
        declared_type = record["type"].lower()
        detected_type = detect_ioc_type(indicator)

        record["detected_type"] = detected_type
        record["type_match"] = declared_type == detected_type
        record["normalized_indicator"] = normalize_indicator(
            indicator,
            detected_type
        )

        record["observed_events"] = int(record["observed_events"])
        record["failed_logins"] = int(record["failed_logins"])

        processed_records.append(record)

    return processed_records


def correlate_iocs(records):
    """Combine duplicate IOC observations from multiple data sources."""
    correlated = {}

    for record in records:
        key = record["normalized_indicator"]

        if key not in correlated:
            correlated[key] = {
                "indicator": key,
                "type": record["detected_type"],
                "occurrences": 0,
                "observed_events": 0,
                "failed_logins": 0,
                "sources": set(),
                "notes": []
            }

        correlated[key]["occurrences"] += 1
        correlated[key]["observed_events"] += record["observed_events"]
        correlated[key]["failed_logins"] += record["failed_logins"]
        correlated[key]["sources"].add(record["source"])
        correlated[key]["notes"].append(record["notes"])

    return correlated


def calculate_risk_score(data):
    """
    Calculate a simple evidence-based triage score.

    The score represents investigation priority,
    not confirmed maliciousness.
    """
    score = 0

    if data["observed_events"] >= 1:
        score += 1

    if data["observed_events"] >= 3:
        score += 1

    if data["observed_events"] >= 5:
        score += 1

    if data["failed_logins"] >= 1:
        score += 2

    if data["failed_logins"] >= 3:
        score += 1

    if data["occurrences"] >= 2:
        score += 1

    if len(data["sources"]) >= 2:
        score += 1

    return score


def assign_priority(score):
    """Convert a numeric score into an analyst triage priority."""
    if score >= 6:
        return "CRITICAL"

    if score >= 3:
        return "HIGH"

    if score >= 1:
        return "MODERATE"

    return "LOW"


def generate_recommendation(priority):
    """Generate an analyst recommendation based on triage priority."""
    recommendations = {
        "CRITICAL": (
            "Escalate immediately. Correlate additional telemetry and "
            "evaluate containment actions after validating the indicator."
        ),
        "HIGH": (
            "Prioritize analyst investigation. Review related logs and "
            "consider containment or blocking after validation."
        ),
        "MODERATE": (
            "Perform additional enrichment and correlation. Monitor for "
            "new activity before taking restrictive action."
        ),
        "LOW": (
            "Retain for context and monitoring. No immediate containment "
            "action is recommended without additional evidence."
        )
    }

    return recommendations[priority]


def score_iocs(correlated_iocs):
    """Assign risk scores, priorities, and recommendations."""
    for data in correlated_iocs.values():
        score = calculate_risk_score(data)
        priority = assign_priority(score)

        data["risk_score"] = score
        data["priority"] = priority
        data["recommendation"] = generate_recommendation(priority)

    return correlated_iocs


def export_csv(results):
    """Export IOC triage results to CSV."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    fieldnames = [
        "indicator",
        "type",
        "occurrences",
        "observed_events",
        "failed_logins",
        "sources",
        "risk_score",
        "priority",
        "recommendation",
        "notes"
    ]

    with open(
        CSV_OUTPUT,
        "w",
        encoding="utf-8",
        newline=""
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for data in results:
            writer.writerow(
                {
                    "indicator": data["indicator"],
                    "type": data["type"],
                    "occurrences": data["occurrences"],
                    "observed_events": data["observed_events"],
                    "failed_logins": data["failed_logins"],
                    "sources": "; ".join(sorted(data["sources"])),
                    "risk_score": data["risk_score"],
                    "priority": data["priority"],
                    "recommendation": data["recommendation"],
                    "notes": " | ".join(data["notes"])
                }
            )


def export_json(results):
    """Export IOC triage results to JSON."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    json_results = []

    for data in results:
        record = {
            "indicator": data["indicator"],
            "type": data["type"],
            "occurrences": data["occurrences"],
            "observed_events": data["observed_events"],
            "failed_logins": data["failed_logins"],
            "sources": sorted(data["sources"]),
            "risk_score": data["risk_score"],
            "priority": data["priority"],
            "recommendation": data["recommendation"],
            "notes": data["notes"]
        }

        json_results.append(record)

    with open(
        JSON_OUTPUT,
        "w",
        encoding="utf-8"
    ) as json_file:

        json.dump(
            json_results,
            json_file,
            indent=4
        )


def main():
    iocs = load_iocs(INPUT_FILE)
    processed_iocs = validate_and_normalize(iocs)
    correlated_iocs = correlate_iocs(processed_iocs)
    scored_iocs = score_iocs(correlated_iocs)

    sorted_iocs = sorted(
        scored_iocs.values(),
        key=lambda item: item["risk_score"],
        reverse=True
    )

    print(f"Loaded IOC records: {len(processed_iocs)}")
    print(f"Unique indicators: {len(sorted_iocs)}\n")

    print("=== IOC TRIAGE RESULTS ===")

    for data in sorted_iocs:
        sources = ", ".join(sorted(data["sources"]))

        print(
            f"\nIndicator: {data['indicator']}\n"
            f"Type: {data['type']}\n"
            f"Occurrences: {data['occurrences']}\n"
            f"Observed Events: {data['observed_events']}\n"
            f"Failed Logins: {data['failed_logins']}\n"
            f"Sources: {sources}\n"
            f"Risk Score: {data['risk_score']}\n"
            f"Priority: {data['priority']}\n"
            f"Recommendation: {data['recommendation']}"
        )

    export_csv(sorted_iocs)
    export_json(sorted_iocs)

    print("\n=== REPORT EXPORT COMPLETE ===")
    print(f"CSV report:  {CSV_OUTPUT}")
    print(f"JSON report: {JSON_OUTPUT}")


if __name__ == "__main__":
    main()
