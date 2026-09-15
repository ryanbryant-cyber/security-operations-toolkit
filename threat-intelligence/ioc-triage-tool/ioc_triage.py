import csv
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse


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

    # Check for an IPv4 address.
    try:
        ip = ipaddress.ip_address(value)

        if ip.version == 4:
            return "ipv4"
    except ValueError:
        pass

    # Check for common file hash formats.
    if re.fullmatch(r"[A-Fa-f0-9]{32}", value):
        return "md5"

    if re.fullmatch(r"[A-Fa-f0-9]{40}", value):
        return "sha1"

    if re.fullmatch(r"[A-Fa-f0-9]{64}", value):
        return "sha256"

    # Refang training URLs only for validation.
    normalized_url = (
        value.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )

    parsed_url = urlparse(normalized_url)

    if (
        parsed_url.scheme in ("http", "https")
        and parsed_url.netloc
    ):
        return "url"

    # Check for a domain name.
    domain_pattern = (
        r"^(?:[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,}$"
    )

    if re.fullmatch(domain_pattern, value):
        return "domain"

    return "unknown"


def validate_iocs(records):
    """Compare the declared IOC type with the detected IOC type."""
    validated_records = []

    for record in records:
        indicator = record["indicator"]
        declared_type = record["type"].lower()
        detected_type = detect_ioc_type(indicator)

        record["detected_type"] = detected_type
        record["type_match"] = declared_type == detected_type

        validated_records.append(record)

    return validated_records


def main():
    iocs = load_iocs(INPUT_FILE)
    validated_iocs = validate_iocs(iocs)

    print(f"Loaded {len(validated_iocs)} IOC records.\n")

    for record in validated_iocs:
        status = "VALID" if record["type_match"] else "REVIEW"

        print(
            f"[{status}] "
            f"Indicator: {record['indicator']} | "
            f"Declared: {record['type']} | "
            f"Detected: {record['detected_type']} | "
            f"Source: {record['source']}"
        )


if __name__ == "__main__":
    main()
