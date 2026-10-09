import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

CASE_FILE = (
    BASE_DIR
    / "case-data"
    / "case_metadata.json"
)

EVIDENCE_DIR = (
    BASE_DIR
    / "sample-evidence"
)

OUTPUT_DIR = BASE_DIR / "output"

MANIFEST_FILE = (
    OUTPUT_DIR
    / "evidence_manifest.json"
)

INVENTORY_FILE = (
    OUTPUT_DIR
    / "evidence_inventory.csv"
)

CUSTODY_FILE = (
    OUTPUT_DIR
    / "chain_of_custody.csv"
)


EVIDENCE_METADATA = {
    "authentication_events.csv": {
        "evidence_type": "Authentication Log",
        "source_system": "Identity Monitoring",
        "description": (
            "Synthetic authentication telemetry "
            "associated with the Finance incident."
        )
    },

    "network_connections.csv": {
        "evidence_type": "Network Evidence",
        "source_system": "Network Monitoring",
        "description": (
            "Synthetic network connection evidence "
            "associated with the investigated host."
        )
    },

    "incident_timeline.csv": {
        "evidence_type": "Incident Timeline",
        "source_system": "Analyst Timeline",
        "description": (
            "Chronological synthetic incident timeline "
            "built from correlated evidence."
        )
    },

    "analyst_notes.txt": {
        "evidence_type": "Analyst Notes",
        "source_system": "Analyst Work Product",
        "description": (
            "Synthetic analyst notes documenting "
            "confirmed evidence and unresolved hypotheses."
        )
    },

    "powershell_transcript.txt": {
        "evidence_type": "Command Transcript",
        "source_system": "Windows PowerShell",
        "description": (
            "Synthetic PowerShell transcript associated "
            "with endpoint investigation activity."
        )
    },

    "investigation_results.json": {
        "evidence_type": "Investigation Results",
        "source_system": "Incident Analysis",
        "description": (
            "Structured synthetic investigation findings "
            "and analyst assessment."
        )
    }
}


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def load_json(path):
    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def sha256_file(path):
    digest = hashlib.sha256()

    with open(
        path,
        "rb"
    ) as file:

        for chunk in iter(
            lambda: file.read(65536),
            b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def discover_evidence():
    return sorted(
        [
            path
            for path in EVIDENCE_DIR.iterdir()
            if path.is_file()
        ],
        key=lambda path: path.name.lower()
    )


def register_evidence(
    case_data,
    evidence_files
):
    evidence_records = []
    custody_records = []

    registration_time = utc_now()

    for index, path in enumerate(
        evidence_files,
        start=1
    ):
        evidence_id = f"EV-{index:03d}"

        metadata = EVIDENCE_METADATA.get(
            path.name,
            {
                "evidence_type": "Unclassified Evidence",
                "source_system": "Unknown",
                "description": (
                    "Evidence file discovered during "
                    "case registration."
                )
            }
        )

        stat = path.stat()

        sha256 = sha256_file(path)

        record = {
            "case_id": case_data["case_id"],
            "evidence_id": evidence_id,
            "file_name": path.name,
            "relative_path": str(
                path.relative_to(
                    BASE_DIR
                )
            ),
            "evidence_type": metadata[
                "evidence_type"
            ],
            "source_system": metadata[
                "source_system"
            ],
            "description": metadata[
                "description"
            ],
            "file_size_bytes": stat.st_size,
            "sha256": sha256,
            "registered_timestamp": (
                registration_time
            ),
            "registered_by": case_data[
                "lead_analyst"
            ],
            "integrity_status": "REGISTERED"
        }

        evidence_records.append(
            record
        )

        custody_records.append({
            "case_id": case_data[
                "case_id"
            ],
            "evidence_id": evidence_id,
            "timestamp": (
                registration_time
            ),
            "action": "Collected",
            "custodian": case_data[
                "lead_analyst"
            ],
            "location": case_data[
                "evidence_storage_location"
            ],
            "reason": (
                "Initial evidence collection "
                "for synthetic incident case."
            ),
            "notes": (
                f"{path.name} entered into "
                "the evidence package."
            )
        })

        custody_records.append({
            "case_id": case_data[
                "case_id"
            ],
            "evidence_id": evidence_id,
            "timestamp": (
                registration_time
            ),
            "action": "Registered",
            "custodian": case_data[
                "lead_analyst"
            ],
            "location": case_data[
                "evidence_storage_location"
            ],
            "reason": (
                "Evidence metadata and SHA-256 "
                "hash recorded."
            ),
            "notes": (
                f"Initial SHA-256: {sha256}"
            )
        })

    return (
        evidence_records,
        custody_records
    )


def export_manifest(
    case_data,
    evidence_records
):
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    manifest = {
        "case": case_data,
        "manifest_created": utc_now(),
        "hash_algorithm": "SHA-256",
        "evidence_count": len(
            evidence_records
        ),
        "evidence": evidence_records
    }

    with open(
        MANIFEST_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            manifest,
            file,
            indent=2
        )


def export_inventory(
    evidence_records
):
    fieldnames = [
        "case_id",
        "evidence_id",
        "file_name",
        "relative_path",
        "evidence_type",
        "source_system",
        "file_size_bytes",
        "sha256",
        "registered_timestamp",
        "registered_by",
        "integrity_status"
    ]

    with open(
        INVENTORY_FILE,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for record in evidence_records:
            writer.writerow({
                field: record[field]
                for field in fieldnames
            })


def export_custody(
    custody_records
):
    fieldnames = [
        "case_id",
        "evidence_id",
        "timestamp",
        "action",
        "custodian",
        "location",
        "reason",
        "notes"
    ]

    with open(
        CUSTODY_FILE,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for record in custody_records:
            writer.writerow(record)


def print_results(
    case_data,
    evidence_records,
    custody_records
):
    print()
    print("=" * 88)
    print(
        "DIGITAL EVIDENCE REGISTRATION"
    )
    print("=" * 88)

    print(
        f"Case:       "
        f"{case_data['case_id']}"
    )

    print(
        f"Case Name:  "
        f"{case_data['case_name']}"
    )

    print(
        f"Analyst:    "
        f"{case_data['lead_analyst']}"
    )

    print("-" * 88)

    for record in evidence_records:
        print(
            f"{record['evidence_id']} | "
            f"{record['evidence_type']:<22} | "
            f"{record['file_name']}"
        )

        print(
            f"         SHA-256: "
            f"{record['sha256']}"
        )

    print("=" * 88)

    print(
        f"Evidence registered: "
        f"{len(evidence_records)}"
    )

    print(
        f"Custody records:     "
        f"{len(custody_records)}"
    )

    print("=" * 88)

    print(
        f"Manifest: "
        f"{MANIFEST_FILE}"
    )

    print(
        f"Inventory: "
        f"{INVENTORY_FILE}"
    )

    print(
        f"Custody:   "
        f"{CUSTODY_FILE}"
    )

    print("=" * 88)


def main():
    case_data = load_json(
        CASE_FILE
    )

    evidence_files = discover_evidence()

    if not evidence_files:
        raise RuntimeError(
            "No evidence files were found "
            "in sample-evidence."
        )

    (
        evidence_records,
        custody_records
    ) = register_evidence(
        case_data,
        evidence_files
    )

    export_manifest(
        case_data,
        evidence_records
    )

    export_inventory(
        evidence_records
    )

    export_custody(
        custody_records
    )

    print_results(
        case_data,
        evidence_records,
        custody_records
    )


if __name__ == "__main__":
    main()
