import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

MANIFEST_FILE = (
    BASE_DIR
    / "output"
    / "evidence_manifest.json"
)

VERIFICATION_DIR = (
    BASE_DIR
    / "verification-evidence"
)

OUTPUT_DIR = BASE_DIR / "output"

JSON_OUTPUT = (
    OUTPUT_DIR
    / "integrity_verification.json"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "integrity_verification_summary.csv"
)

CUSTODY_FILE = (
    OUTPUT_DIR
    / "chain_of_custody.csv"
)


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


def verify_evidence(manifest):
    verification_time = utc_now()

    results = []

    for evidence in manifest["evidence"]:
        path = (
            VERIFICATION_DIR
            / evidence["file_name"]
        )

        expected_hash = evidence["sha256"]

        if not path.exists():
            results.append({
                "case_id": evidence["case_id"],
                "evidence_id": evidence[
                    "evidence_id"
                ],
                "file_name": evidence[
                    "file_name"
                ],
                "expected_sha256": expected_hash,
                "current_sha256": None,
                "status": "MISSING",
                "verified_timestamp": (
                    verification_time
                ),
                "notes": (
                    "Evidence file was recorded "
                    "in the manifest but was not "
                    "present during verification."
                )
            })

            continue

        current_hash = sha256_file(
            path
        )

        if current_hash == expected_hash:
            status = "VERIFIED"

            notes = (
                "Current SHA-256 matches the "
                "registered evidence manifest."
            )

        else:
            status = "HASH MISMATCH"

            notes = (
                "Current SHA-256 differs from "
                "the originally registered hash."
            )

        results.append({
            "case_id": evidence["case_id"],
            "evidence_id": evidence[
                "evidence_id"
            ],
            "file_name": evidence[
                "file_name"
            ],
            "expected_sha256": expected_hash,
            "current_sha256": current_hash,
            "status": status,
            "verified_timestamp": (
                verification_time
            ),
            "notes": notes
        })

    return results


def summarize(results):
    return {
        "evidence_checked": len(
            results
        ),
        "verified": sum(
            1
            for item in results
            if item["status"]
            == "VERIFIED"
        ),
        "hash_mismatch": sum(
            1
            for item in results
            if item["status"]
            == "HASH MISMATCH"
        ),
        "missing": sum(
            1
            for item in results
            if item["status"]
            == "MISSING"
        )
    }


def export_json(
    manifest,
    results,
    summary
):
    report = {
        "case_id": manifest[
            "case"
        ][
            "case_id"
        ],
        "verification_directory": str(
            VERIFICATION_DIR.relative_to(
                BASE_DIR
            )
        ),
        "hash_algorithm": "SHA-256",
        "summary": summary,
        "results": results
    }

    with open(
        JSON_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )


def export_csv(results):
    fieldnames = [
        "case_id",
        "evidence_id",
        "file_name",
        "expected_sha256",
        "current_sha256",
        "status",
        "verified_timestamp",
        "notes"
    ]

    with open(
        CSV_OUTPUT,
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
            writer.writerow(result)


def append_custody_events(
    manifest,
    results
):
    if not CUSTODY_FILE.exists():
        raise RuntimeError(
            "Chain-of-custody file is missing."
        )

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

    analyst = manifest[
        "case"
    ][
        "lead_analyst"
    ]

    with open(
        CUSTODY_FILE,
        "a",
        encoding="utf-8",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        for result in results:

            writer.writerow({
                "case_id": result[
                    "case_id"
                ],
                "evidence_id": result[
                    "evidence_id"
                ],
                "timestamp": result[
                    "verified_timestamp"
                ],
                "action": (
                    "Verified"
                ),
                "custodian": analyst,
                "location": (
                    "verification-evidence"
                ),
                "reason": (
                    "Evidence integrity "
                    "verification."
                ),
                "notes": (
                    f"Integrity status: "
                    f"{result['status']}"
                )
            })


def print_results(
    manifest,
    results,
    summary
):
    print()
    print("=" * 88)
    print(
        "DIGITAL EVIDENCE INTEGRITY "
        "VERIFICATION"
    )
    print("=" * 88)

    print(
        f"Case: "
        f"{manifest['case']['case_id']}"
    )

    print("-" * 88)

    for result in results:
        print(
            f"{result['evidence_id']} | "
            f"{result['status']:<13} | "
            f"{result['file_name']}"
        )

    print("=" * 88)

    print(
        f"Evidence checked: "
        f"{summary['evidence_checked']}"
    )

    print(
        f"VERIFIED:         "
        f"{summary['verified']}"
    )

    print(
        f"HASH MISMATCH:    "
        f"{summary['hash_mismatch']}"
    )

    print(
        f"MISSING:          "
        f"{summary['missing']}"
    )

    print("=" * 88)

    print(
        f"JSON report: "
        f"{JSON_OUTPUT}"
    )

    print(
        f"CSV summary: "
        f"{CSV_OUTPUT}"
    )

    print("=" * 88)


def main():
    manifest = load_json(
        MANIFEST_FILE
    )

    results = verify_evidence(
        manifest
    )

    summary = summarize(
        results
    )

    export_json(
        manifest,
        results,
        summary
    )

    export_csv(
        results
    )

    append_custody_events(
        manifest,
        results
    )

    print_results(
        manifest,
        results,
        summary
    )


if __name__ == "__main__":
    main()
