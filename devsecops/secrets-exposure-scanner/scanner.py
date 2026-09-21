import csv
import json
import re
from collections import Counter
from pathlib import Path


RULE_FILE = Path("rules/secret_patterns.json")
TARGET_DIR = Path("test-repository")

OUTPUT_DIR = Path("output")
JSON_OUTPUT = OUTPUT_DIR / "secrets_scan_results.json"
CSV_OUTPUT = OUTPUT_DIR / "secrets_scan_findings.csv"


SCANNABLE_EXTENSIONS = {
    ".py",
    ".json",
    ".ini",
    ".txt"
}


PLACEHOLDER_VALUES = {
    "your_api_key_here",
    "your_token_here",
    "placeholder",
    "changeme",
    "replace_me",
    "example"
}


def load_rules(rule_file):
    """Load secret-detection patterns from JSON."""
    with open(rule_file, "r", encoding="utf-8") as file:
        return json.load(file)


def is_scannable(file_path):
    """Determine whether a file should be scanned."""
    if file_path.name == ".env":
        return True

    return file_path.suffix.lower() in SCANNABLE_EXTENSIONS


def is_placeholder(match_text):
    """Identify obvious documentation placeholders."""
    lowered = match_text.lower()

    return any(
        placeholder in lowered
        for placeholder in PLACEHOLDER_VALUES
    )


def redact_match(match_text):
    """Redact likely secret values before reporting them."""
    if "=" in match_text:
        key, _ = match_text.split("=", 1)
        return f"{key}=<REDACTED>"

    if ":" in match_text:
        key, _ = match_text.split(":", 1)
        return f"{key}: <REDACTED>"

    return "<REDACTED>"


def scan_file(file_path, rules):
    """Scan one file against every configured detection rule."""
    findings = []
    suppressed = []

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        for line_number, line in enumerate(file, start=1):

            for rule_name, rule in rules.items():
                pattern = rule["pattern"]

                for match in re.finditer(pattern, line):
                    matched_text = match.group(0)

                    result = {
                        "rule": rule_name,
                        "file": str(file_path),
                        "line": line_number,
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "matched_text": redact_match(matched_text),
                        "remediation": rule["remediation"]
                    }

                    if is_placeholder(matched_text):
                        suppressed.append(result)
                    else:
                        findings.append(result)

    return findings, suppressed


def scan_repository(target_dir, rules):
    """Recursively scan supported files in the repository."""
    findings = []
    suppressed = []
    files_scanned = 0

    for file_path in sorted(target_dir.rglob("*")):
        if not file_path.is_file():
            continue

        if not is_scannable(file_path):
            continue

        files_scanned += 1

        file_findings, file_suppressed = scan_file(
            file_path,
            rules
        )

        findings.extend(file_findings)
        suppressed.extend(file_suppressed)

    return findings, suppressed, files_scanned


def print_findings(findings):
    """Display security findings."""
    print("=" * 70)
    print("SECURITY FINDINGS")
    print("=" * 70)

    if not findings:
        print("No secret or configuration exposures detected.")
        return

    for finding in findings:
        print(
            f"[{finding['severity']}] "
            f"{finding['rule']} | "
            f"{finding['file']}:{finding['line']}"
        )
        print(f"Matched: {finding['matched_text']}")
        print(f"Description: {finding['description']}")
        print(f"Remediation: {finding['remediation']}")
        print()


def print_suppressed(suppressed):
    """Display placeholder matches excluded from findings."""
    print("=" * 70)
    print("SUPPRESSED PLACEHOLDER MATCHES")
    print("=" * 70)

    if not suppressed:
        print("No placeholder matches were suppressed.")
        return

    for finding in suppressed:
        print(
            f"[SUPPRESSED] "
            f"{finding['rule']} | "
            f"{finding['file']}:{finding['line']}"
        )


def export_json(
    rules,
    files_scanned,
    findings,
    suppressed
):
    """Export complete scan results to JSON."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )

    report = {
        "project": "Secrets & Configuration Exposure Scanner",
        "summary": {
            "rules_loaded": len(rules),
            "files_scanned": files_scanned,
            "security_findings": len(findings),
            "suppressed_placeholders": len(suppressed),
            "severity_counts": dict(severity_counts)
        },
        "findings": findings,
        "suppressed_matches": suppressed
    }

    with open(
        JSON_OUTPUT,
        "w",
        encoding="utf-8"
    ) as output_file:
        json.dump(report, output_file, indent=4)


def export_csv(findings, suppressed):
    """Export findings and suppressed matches to CSV."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    fieldnames = [
        "status",
        "rule",
        "severity",
        "file",
        "line",
        "matched_text",
        "description",
        "remediation"
    ]

    with open(
        CSV_OUTPUT,
        "w",
        encoding="utf-8",
        newline=""
    ) as output_file:

        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for finding in findings:
            writer.writerow({
                "status": "FINDING",
                **finding
            })

        for finding in suppressed:
            writer.writerow({
                "status": "SUPPRESSED",
                **finding
            })


def main():
    rules = load_rules(RULE_FILE)

    findings, suppressed, files_scanned = scan_repository(
        TARGET_DIR,
        rules
    )

    print("=== SECRETS & CONFIGURATION EXPOSURE SCANNER ===\n")
    print(f"Detection rules loaded: {len(rules)}")
    print(f"Files scanned: {files_scanned}")
    print(f"Security findings: {len(findings)}")
    print(f"Suppressed placeholders: {len(suppressed)}")
    print()

    print_findings(findings)
    print()
    print_suppressed(suppressed)

    export_json(
        rules,
        files_scanned,
        findings,
        suppressed
    )

    export_csv(
        findings,
        suppressed
    )

    print("\n=== REPORT EXPORT COMPLETE ===")
    print(f"JSON report: {JSON_OUTPUT}")
    print(f"CSV report:  {CSV_OUTPUT}")


if __name__ == "__main__":
    main()
