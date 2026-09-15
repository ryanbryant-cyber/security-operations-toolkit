import csv
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


INPUT_FILE = Path("sample_iocs.csv")


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

    # Check for IPv4.
    try:
        ip = ipaddress.ip_address(value)

        if ip.version == 4:
            return "ipv4"
    except ValueError:
        pass

    # Check common file hash formats.
    if re.fullmatch(r"[A-Fa-f0-9]{32}", value):
        return "md5"

    if re.fullmatch(r"[A-Fa-f0-9]{40}", value):
        return "sha1"

    if re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        return "sha256"

    # Refang only internally so URLs can be validated.
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

    # Check for domain names.
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

        # Defang again before storing/displaying the normalized result.
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

        # Convert numeric CSV fields from text into integers.
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


def main():
    iocs = load_iocs(INPUT_FILE)
    processed_iocs = validate_and_normalize(iocs)
    correlated_iocs = correlate_iocs(processed_iocs)

    print(f"Loaded IOC records: {len(processed_iocs)}")
    print(f"Unique indicators: {len(correlated_iocs)}\n")

    print("=== VALIDATION RESULTS ===")

    for record in processed_iocs:
        status = "VALID" if record["type_match"] else "REVIEW"

        print(
            f"[{status}] "
            f"{record['indicator']} | "
            f"Detected: {record['detected_type']} | "
            f"Normalized: {record['normalized_indicator']}"
        )

    print("\n=== CORRELATED IOC RESULTS ===")

    for indicator, data in correlated_iocs.items():
        sources = ", ".join(sorted(data["sources"]))

        print(
            f"\nIndicator: {indicator}\n"
            f"Type: {data['type']}\n"
            f"Occurrences: {data['occurrences']}\n"
            f"Observed Events: {data['observed_events']}\n"
            f"Failed Logins: {data['failed_logins']}\n"
            f"Sources: {sources}"
        )


if __name__ == "__main__":
    main()
