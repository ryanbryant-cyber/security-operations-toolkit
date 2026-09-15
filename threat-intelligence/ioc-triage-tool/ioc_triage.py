import csv
from pathlib import Path


INPUT_FILE = Path("sample_iocs.csv")


def load_iocs(file_path):
    """Load IOC records from a CSV file."""
    records = []

    with open(file_path, "r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)

        for row in reader:
            records.append(row)

    return records


def main():
    iocs = load_iocs(INPUT_FILE)

    print(f"Loaded {len(iocs)} IOC records.\n")

    for record in iocs:
        print(
            f"Indicator: {record['indicator']} | "
            f"Type: {record['type']} | "
            f"Source: {record['source']}"
        )


if __name__ == "__main__":
    main()
