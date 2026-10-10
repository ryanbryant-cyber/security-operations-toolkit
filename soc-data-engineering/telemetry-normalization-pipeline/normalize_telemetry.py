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


if __name__ == "__main__":
    main()
