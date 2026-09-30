import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

ANALYSIS_FILE = (
    BASE_DIR
    / "output"
    / "memory_forensics_results.json"
)

EXPECTATIONS_FILE = (
    BASE_DIR
    / "expected-results"
    / "memory_forensics_expectations.json"
)

VALIDATION_OUTPUT = (
    BASE_DIR
    / "output"
    / "memory_forensics_validation_results.json"
)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def get_indicator_names(finding):
    return {
        indicator["indicator"]
        for indicator in finding["indicators"]
    }


def validate_summary(report, expectations):
    actual = report["summary"]
    expected = expectations["expected_summary"]

    passed = (
        actual["findings"]
        == expected["findings"]
        and actual["high_priority_findings"]
        == expected["high_priority_findings"]
    )

    return {
        "check": "Finding summary",
        "expected": expected,
        "actual": actual,
        "passed": passed
    }


def validate_finding(finding, expectations):
    expected = expectations["expected_finding"]

    passed = (
        finding["finding_id"]
        == expected["finding_id"]
        and finding["host"]
        == expected["host"]
        and finding["user"]
        == expected["user"]
        and finding["risk_score"]
        == expected["risk_score"]
        and finding["investigation_priority"]
        == expected["investigation_priority"]
        and finding["indicator_count"]
        == expected["indicator_count"]
    )

    return {
        "check": "Primary memory-forensics finding",
        "finding_id": finding["finding_id"],
        "host": finding["host"],
        "user": finding["user"],
        "risk_score": finding["risk_score"],
        "priority": finding[
            "investigation_priority"
        ],
        "indicator_count": finding[
            "indicator_count"
        ],
        "passed": passed
    }


def validate_indicators(finding, expectations):
    actual_indicators = get_indicator_names(
        finding
    )

    required = set(
        expectations["required_indicators"]
    )

    missing = sorted(
        required - actual_indicators
    )

    unexpected_missing = len(missing) > 0

    return {
        "check": (
            "All required forensic indicators "
            "are present"
        ),
        "required_count": len(required),
        "actual_count": len(actual_indicators),
        "missing_indicators": missing,
        "passed": not unexpected_missing
    }


def validate_process_chain(finding):
    chain = finding["process_chain"]

    process_names = [
        item["process_name"].lower()
        for item in chain
    ]

    expected_order = [
        "winword.exe",
        "powershell.exe",
        "rundll32.exe",
        "cmd.exe"
    ]

    passed = (
        process_names == expected_order
    )

    return {
        "check": (
            "Suspicious process chain is "
            "reconstructed correctly"
        ),
        "expected": expected_order,
        "actual": process_names,
        "passed": passed
    }


def validate_timeline(finding):
    timeline_text = " | ".join(
        item["event"]
        for item in finding["timeline"]
    ).lower()

    required_evidence = [
        "financehelper.dll loaded by rundll32.exe",
        "rundll32.exe → 203.0.113.88:8443",
        "powershell.exe → 203.0.113.77:443",
        "cmd.exe → 10.10.20.40:445",
        "rwx private executable memory",
        "rx private executable memory"
    ]

    missing = [
        evidence
        for evidence in required_evidence
        if evidence.lower()
        not in timeline_text
    ]

    return {
        "check": (
            "Timeline contains required correlated "
            "forensic evidence"
        ),
        "required_count": len(
            required_evidence
        ),
        "missing_evidence": missing,
        "passed": len(missing) == 0
    }


def validate_unsigned_temp_dll(finding):
    indicators = finding["indicators"]

    unsigned_temp = next(
        (
            indicator
            for indicator in indicators
            if indicator["indicator"]
            == "Unsigned DLL loaded from Temp"
        ),
        None
    )

    passed = (
        unsigned_temp is not None
        and "financehelper.dll"
        in unsigned_temp["evidence"].lower()
        and (
            "\\appdata\\local\\temp\\"
            in unsigned_temp[
                "evidence"
            ].lower()
        )
    )

    return {
        "check": (
            "Unsigned Temp DLL evidence is preserved"
        ),
        "passed": passed
    }


def validate_memory_evidence(finding):
    names = get_indicator_names(
        finding
    )

    passed = (
        "Private RWX memory" in names
        and (
            "Private executable memory "
            "without backing file"
        ) in names
    )

    return {
        "check": (
            "Private executable memory evidence "
            "is detected"
        ),
        "passed": passed
    }


def validate_network_precision(finding):
    indicators = finding["indicators"]

    smb = next(
        (
            indicator
            for indicator in indicators
            if indicator["indicator"]
            == "Attempted internal SMB communication"
        ),
        None
    )

    passed = (
        smb is not None
        and "syn_sent"
        in smb["evidence"].lower()
    )

    return {
        "check": (
            "SMB activity remains classified "
            "as attempted communication"
        ),
        "passed": passed
    }


def validate_guardrails(finding):
    guardrails = finding["guardrails"]

    required_phrases = [
        "Do not classify an unsigned DLL as malware",
        (
            "Do not classify private executable memory "
            "as confirmed process injection"
        ),
        (
            "Do not classify an outbound connection "
            "as command-and-control"
        ),
        (
            "Do not classify a SYN_SENT SMB event "
            "as successful lateral movement"
        )
    ]

    missing = [
        phrase
        for phrase in required_phrases
        if not any(
            phrase.lower()
            in guardrail.lower()
            for guardrail in guardrails
        )
    ]

    return {
        "check": (
            "Forensic analyst guardrails are present"
        ),
        "required_count": len(
            required_phrases
        ),
        "missing_guardrails": missing,
        "passed": len(missing) == 0
    }


def validate_assessment_language(finding):
    assessment = finding[
        "analyst_assessment"
    ].lower()

    required_uncertainty = [
        "does not independently prove malware",
        "command-and-control",
        "process injection",
        "successful lateral movement"
    ]

    passed = all(
        phrase in assessment
        for phrase in required_uncertainty
    )

    return {
        "check": (
            "Analyst assessment preserves "
            "evidentiary uncertainty"
        ),
        "passed": passed
    }


def main():
    report = load_json(
        ANALYSIS_FILE
    )

    expectations = load_json(
        EXPECTATIONS_FILE
    )

    finding = report["finding"]

    checks = [
        validate_summary(
            report,
            expectations
        ),
        validate_finding(
            finding,
            expectations
        ),
        validate_indicators(
            finding,
            expectations
        ),
        validate_process_chain(
            finding
        ),
        validate_timeline(
            finding
        ),
        validate_unsigned_temp_dll(
            finding
        ),
        validate_memory_evidence(
            finding
        ),
        validate_network_precision(
            finding
        ),
        validate_guardrails(
            finding
        ),
        validate_assessment_language(
            finding
        )
    ]

    passed = sum(
        1
        for check in checks
        if check["passed"]
    )

    failed = len(checks) - passed

    validation_report = {
        "validation_status": (
            "PASS"
            if failed == 0
            else "REVIEW"
        ),
        "checks_run": len(checks),
        "checks_passed": passed,
        "checks_failed": failed,
        "checks": checks
    }

    VALIDATION_OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        VALIDATION_OUTPUT,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            validation_report,
            file,
            indent=2
        )

    print()
    print("=" * 92)
    print(
        "WINDOWS MEMORY FORENSICS "
        "VALIDATION"
    )
    print("=" * 92)

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

    print("=" * 92)

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
        f"{validation_report['validation_status']}"
    )

    print("=" * 92)

    print(
        f"Validation report: "
        f"{VALIDATION_OUTPUT}"
    )


if __name__ == "__main__":
    main()
