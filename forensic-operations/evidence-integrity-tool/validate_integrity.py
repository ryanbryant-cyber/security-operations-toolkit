import csv
import hashlib
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

MANIFEST_FILE = (
    BASE_DIR
    / "output"
    / "evidence_manifest.json"
)

VERIFICATION_FILE = (
    BASE_DIR
    / "output"
    / "integrity_verification.json"
)

CUSTODY_FILE = (
    BASE_DIR
    / "output"
    / "chain_of_custody.csv"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "integrity_expectations.json"
)

SAMPLE_EVIDENCE_DIR = (
    BASE_DIR
    / "sample-evidence"
)

VALIDATION_OUTPUT = (
    BASE_DIR
    / "output"
    / "integrity_validation_results.json"
)


def load_json(path):
    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def load_csv(path):
    with open(
        path,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        return list(csv.DictReader(file))


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


def manifest_lookup(manifest):
    return {
        item["evidence_id"]: item
        for item in manifest["evidence"]
    }


def verification_lookup(report):
    return {
        item["evidence_id"]: item
        for item in report["results"]
    }


def validate_summary(
    verification,
    expectations
):
    actual = verification["summary"]
    expected = expectations[
        "expected_summary"
    ]

    passed = all(
        actual[key] == value
        for key, value in expected.items()
    )

    return {
        "check": "Integrity verification summary",
        "passed": passed
    }


def validate_statuses(
    verification,
    expectations
):
    results = verification_lookup(
        verification
    )

    passed = True

    for evidence_id, expected_status in (
        expectations[
            "expected_statuses"
        ].items()
    ):
        item = results.get(
            evidence_id
        )

        if (
            item is None
            or item["status"]
            != expected_status
        ):
            passed = False
            break

    return {
        "check": (
            "Evidence integrity states match "
            "expected ground truth"
        ),
        "passed": passed
    }


def validate_file_mapping(
    manifest,
    expectations
):
    lookup = manifest_lookup(
        manifest
    )

    passed = True

    for evidence_id, expected_file in (
        expectations[
            "expected_files"
        ].items()
    ):
        item = lookup.get(
            evidence_id
        )

        if (
            item is None
            or item["file_name"]
            != expected_file
        ):
            passed = False
            break

    return {
        "check": (
            "Evidence IDs remain mapped to "
            "the correct files"
        ),
        "passed": passed
    }


def validate_manifest_count(
    manifest,
    expectations
):
    expected = expectations[
        "expected_evidence_count"
    ]

    passed = (
        manifest["evidence_count"]
        == expected
        and len(
            manifest["evidence"]
        )
        == expected
    )

    return {
        "check": "Evidence manifest count",
        "passed": passed
    }


def validate_original_evidence(
    manifest
):
    mismatches = []

    for evidence in manifest[
        "evidence"
    ]:
        path = (
            SAMPLE_EVIDENCE_DIR
            / evidence["file_name"]
        )

        if not path.exists():
            mismatches.append(
                evidence[
                    "evidence_id"
                ]
            )
            continue

        current_hash = sha256_file(
            path
        )

        if (
            current_hash
            != evidence["sha256"]
        ):
            mismatches.append(
                evidence[
                    "evidence_id"
                ]
            )

    return {
        "check": (
            "Original sample-evidence package "
            "remains unchanged"
        ),
        "mismatches": mismatches,
        "passed": len(mismatches) == 0
    }


def validate_hash_mismatch(
    verification
):
    results = verification_lookup(
        verification
    )

    item = results.get(
        "EV-002"
    )

    passed = (
        item is not None
        and item["status"]
        == "HASH MISMATCH"
        and item[
            "current_sha256"
        ] is not None
        and item[
            "current_sha256"
        ]
        != item[
            "expected_sha256"
        ]
    )

    return {
        "check": (
            "Altered authentication evidence "
            "produces SHA-256 mismatch"
        ),
        "passed": passed
    }


def validate_missing_evidence(
    verification
):
    results = verification_lookup(
        verification
    )

    item = results.get(
        "EV-005"
    )

    passed = (
        item is not None
        and item["status"]
        == "MISSING"
        and item[
            "current_sha256"
        ] is None
    )

    return {
        "check": (
            "Removed network evidence "
            "is classified as MISSING"
        ),
        "passed": passed
    }


def validate_verified_hashes(
    verification
):
    verified = [
        item
        for item in verification[
            "results"
        ]
        if item["status"]
        == "VERIFIED"
    ]

    passed = (
        len(verified) == 4
        and all(
            item[
                "current_sha256"
            ]
            == item[
                "expected_sha256"
            ]
            for item in verified
        )
    )

    return {
        "check": (
            "All VERIFIED evidence matches "
            "the registered SHA-256 hash"
        ),
        "passed": passed
    }


def validate_custody_count(
    custody,
    expectations
):
    minimum = expectations[
        "minimum_custody_records"
    ]

    return {
        "check": (
            "Chain-of-custody contains "
            "registration and verification history"
        ),
        "passed": len(custody) >= minimum
    }


def validate_custody_actions(
    custody,
    expectations
):
    required = set(
        expectations[
            "required_custody_actions"
        ]
    )

    actions_by_evidence = {}

    for record in custody:
        evidence_id = record[
            "evidence_id"
        ]

        actions_by_evidence.setdefault(
            evidence_id,
            set()
        ).add(
            record["action"]
        )

    expected_ids = set(
        expectations[
            "expected_statuses"
        ].keys()
    )

    passed = all(
        evidence_id
        in actions_by_evidence
        and required.issubset(
            actions_by_evidence[
                evidence_id
            ]
        )
        for evidence_id
        in expected_ids
    )

    return {
        "check": (
            "Each evidence item contains "
            "Collected, Registered, and Verified "
            "custody actions"
        ),
        "passed": passed
    }


def validate_case_identity(
    manifest,
    verification
):
    case_id = manifest[
        "case"
    ][
        "case_id"
    ]

    passed = (
        case_id
        == "CASE-2026-001"
        and verification[
            "case_id"
        ]
        == case_id
    )

    return {
        "check": (
            "Case identity remains consistent "
            "across evidence records"
        ),
        "passed": passed
    }


def main():
    manifest = load_json(
        MANIFEST_FILE
    )

    verification = load_json(
        VERIFICATION_FILE
    )

    custody = load_csv(
        CUSTODY_FILE
    )

    expectations = load_json(
        EXPECTATIONS_FILE
    )

    checks = [
        validate_summary(
            verification,
            expectations
        ),

        validate_statuses(
            verification,
            expectations
        ),

        validate_file_mapping(
            manifest,
            expectations
        ),

        validate_manifest_count(
            manifest,
            expectations
        ),

        validate_original_evidence(
            manifest
        ),

        validate_hash_mismatch(
            verification
        ),

        validate_missing_evidence(
            verification
        ),

        validate_verified_hashes(
            verification
        ),

        validate_custody_count(
            custody,
            expectations
        ),

        validate_custody_actions(
            custody,
            expectations
        ),

        validate_case_identity(
            manifest,
            verification
        )
    ]

    passed = sum(
        1
        for check in checks
        if check["passed"]
    )

    failed = len(checks) - passed

    report = {
        "validation_status": (
            "PASS"
            if failed == 0
            else "REVIEW"
        ),
        "checks_run": len(
            checks
        ),
        "checks_passed": passed,
        "checks_failed": failed,
        "checks": checks
    }

    with open(
        VALIDATION_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=2
        )

    print()
    print("=" * 88)
    print(
        "DIGITAL EVIDENCE INTEGRITY "
        "VALIDATION"
    )
    print("=" * 88)

    for check in checks:
        status = (
            "PASS"
            if check["passed"]
            else "REVIEW"
        )

        print(
            f"{status:<7} "
            f"{check['check']}"
        )

    print("=" * 88)

    print(
        f"Checks run:     "
        f"{len(checks)}"
    )

    print(
        f"Checks passed:  "
        f"{passed}"
    )

    print(
        f"Checks failed:  "
        f"{failed}"
    )

    print(
        f"Overall:        "
        f"{report['validation_status']}"
    )

    print("=" * 88)

    print(
        f"Validation report: "
        f"{VALIDATION_OUTPUT}"
    )


if __name__ == "__main__":
    main()
